// =====================================================================
// Bulk Sensitive File Access - shape-based scoring
// Platform: Defender XDR Advanced Hunting (Timestamp)
// Design: all signals computed within the lookback window. No historical
//         join, no baselining. Scoring model, not a single threshold.
// =====================================================================
let LookbackWindow  = 2h;
let MinFilesToScore = 15;   // Cheap pre-gate. Below this, nothing is interesting.
let ScoreThreshold  = 5;    // TUNE - see scoring table in notes
//
// --- Process classification -------------------------------------------
let IncidentalReaders = dynamic([          // Rendering/preview/sync/scan. Rank 0.
    "msedgewebview2.exe", "msedge.exe", "chrome.exe", "PreviewHost.exe",
    "dllhost.exe", "OneDrive.exe", "FileCoAuth.exe",
    "SearchIndexer.exe", "SearchProtocolHost.exe",
    "MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseCE.exe",
    "DOCSTORBKP.exe", "DOCSTOR.exe" ]);
let DocumentApps = dynamic([               // Human document work. Rank 1.
    "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "ONENOTE.EXE",
    "Acrobat.exe", "AcroRd32.exe", "notepad.exe", "ppdfcreate.exe" ]);
let CollectionTools = dynamic([            // Scripting/copy/archive. Rank 3.
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "python.exe", "robocopy.exe", "xcopy.exe",
    "esentutl.exe", "certutil.exe", "7z.exe", "7zG.exe", "WinRAR.exe",
    "rar.exe", "tar.exe", "curl.exe", "rclone.exe" ]);
let TrustedLocations = dynamic([
    @"c:\program files", @"c:\program files (x86)",
    @"c:\windows\system32", @"c:\windows\syswow64" ]);
let TransientPaths = dynamic([             // Attachment/preview caches - not real access
    @"\appdata\local\microsoft\windows\inetcache\content.outlook\",
    @"\appdata\local\microsoft\windows\temporary internet files\",
    @"\appdata\local\microsoft\windows\inetcache\ie\" ]);
//
DeviceEvents
| where Timestamp >= ago(LookbackWindow)
| where ActionType == "SensitiveFileRead"
| where isnotempty(FolderPath) and isnotempty(InitiatingProcessFileName)
//
// --- Normalisation ----------------------------------------------------
| extend FullPath = iff(FolderPath endswith FileName,
                        FolderPath, strcat(FolderPath, @"\", FileName))
| extend DirectoryPath = tostring(parse_path(FullPath).DirectoryPath)
| where not (tolower(DirectoryPath) has_any (TransientPaths))
| extend FolderRoot = strcat_array(array_slice(split(DirectoryPath, @"\"), 0, 3), @"\")
| extend FileExt      = tolower(tostring(parse_path(FullPath).Extension))
| extend IsNetworkPath = FullPath startswith @"\\"
//
// --- Process rank. Masquerade check: trusted names only get the benign
//     rank when running from a trusted location.
| extend InTrustedLocation = tolower(InitiatingProcessFolderPath) has_any (TrustedLocations)
| extend ProcRank = case(
      InitiatingProcessFileName in~ (CollectionTools),                      3,
      InitiatingProcessFileName in~ (IncidentalReaders) and InTrustedLocation, 0,
      InitiatingProcessFileName in~ (DocumentApps)      and InTrustedLocation, 1,
      2)   // Unknown, or known-name-from-untrusted-path
//
// --- Rhythm: inter-arrival gaps per actor -----------------------------
| extend ActorKey = strcat(DeviceId, "|", InitiatingProcessAccountSid)
| sort by ActorKey asc, Timestamp asc
| extend GapSeconds = iff(prev(ActorKey) == ActorKey,
             todouble(datetime_diff('millisecond', Timestamp, prev(Timestamp))) / 1000.0,
             real(null))
//
// --- Aggregate: one row per device + identity -------------------------
| summarize
      StartTime        = min(Timestamp),
      EndTime          = max(Timestamp),
      DistinctFiles    = count_distinct(FullPath),
      DistinctFolders  = count_distinct(DirectoryPath),
      DistinctRoots    = count_distinct(FolderRoot),
      DistinctExts     = count_distinct(FileExt),
      NetworkPathReads = countif(IsNetworkPath),
      TotalReadEvents  = count(),
      MaxProcRank      = max(ProcRank),
      MedianGap        = percentile(GapSeconds, 50),
      MeanGap          = avg(GapSeconds),
      GapStdDev        = stdev(GapSeconds),
      SubSecondReads   = countif(GapSeconds < 1.0),
      SampleFiles      = make_set(FileName, 20),
      SampleRoots      = make_set(FolderRoot, 10),
      Processes        = make_set(InitiatingProcessFileName, 10)
  by DeviceId, DeviceName,
     AccountUpn      = InitiatingProcessAccountUpn,
     AccountName     = InitiatingProcessAccountName,
     AccountDomain   = InitiatingProcessAccountDomain,
     AccountSid      = InitiatingProcessAccountSid
//
| where DistinctFiles >= MinFilesToScore
//
// --- Derived shape metrics --------------------------------------------
| extend FilesPerFolder = round(todouble(DistinctFiles) / max_of(DistinctFolders, 1), 2)
| extend GapCoefVar     = round(GapStdDev / max_of(MeanGap, 0.001), 2)
| extend RhythmClass    = case(
      isnull(MedianGap),                       "Insufficient data",
      MedianGap < 1.0,                         "Machine - sub-second",
      GapCoefVar < 0.35 and MedianGap < 30,    "Machine - regular interval",
      GapCoefVar > 1.5,                        "Human - irregular",
      "Ambiguous")
//
// --- Scoring. No single signal is mandatory. -------------------------
| extend S_Volume     = toint(DistinctFiles >= 40)                              * 1
| extend S_Dispersion = toint(DistinctRoots >= 3)                               * 2
| extend S_Harvest    = toint(FilesPerFolder <= 1.5 and DistinctFolders >= 5)   * 2
| extend S_Rhythm     = toint(RhythmClass startswith "Machine")                 * 3
| extend S_Diversity  = toint(DistinctExts >= 5)                                * 1
| extend S_Network    = toint(NetworkPathReads > 0)                             * 1
| extend S_Process    = case(MaxProcRank == 3, 2, MaxProcRank == 2, 1, 0)
| extend Score = S_Volume + S_Dispersion + S_Harvest + S_Rhythm
               + S_Diversity + S_Network + S_Process
| where Score >= ScoreThreshold
//
// --- Entity + detail columns ------------------------------------------
| extend HostName      = tostring(split(DeviceName, ".")[0])
| extend HostDnsDomain = iff(DeviceName contains ".",
                             strcat_array(array_slice(split(DeviceName, "."), 1, -1), "."), "")
| extend UpnSuffix     = tostring(split(AccountUpn, "@")[1])
| extend DurationMinutes = round((EndTime - StartTime) / 1m, 2)
| extend ScoreBreakdown  = strcat("Vol:", S_Volume, " Disp:", S_Dispersion,
                                  " Harv:", S_Harvest, " Rhythm:", S_Rhythm,
                                  " Div:", S_Diversity, " Net:", S_Network,
                                  " Proc:", S_Process)
| extend AlertSeverity = case(Score >= 8, "High", Score >= 6, "Medium", "Low")
| extend SampleFilesStr = tostring(SampleFiles),
         SampleRootsStr = tostring(SampleRoots),
         ProcessesStr   = tostring(Processes)
| project
      StartTime, EndTime, DurationMinutes,
      HostName, HostDnsDomain, DeviceName, DeviceId,
      AccountName, AccountDomain, AccountUpn, UpnSuffix, AccountSid,
      Score, AlertSeverity, ScoreBreakdown, RhythmClass,
      DistinctFiles, DistinctFolders, DistinctRoots, DistinctExts,
      FilesPerFolder, MedianGap, GapCoefVar, SubSecondReads,
      NetworkPathReads, TotalReadEvents,
      ProcessesStr, SampleRootsStr, SampleFilesStr
| order by Score desc, DistinctFiles desc
