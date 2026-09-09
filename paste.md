// =====================================================================
// Bulk Sensitive File Access - condition-based
// Platform: Defender XDR Advanced Hunting (uses Timestamp)
//
// Each condition is a factual statement about observed behaviour.
// A row alerts if any one condition matches. No scoring, no ranking.
// All signals are computed within the lookback window - no historical
// join, no baselining.
//
// For Sentinel: swap Timestamp -> TimeGenerated and remove the ago()
// filter (the rule's lookup period defines the window).
// =====================================================================
let LookbackWindow = 2h;
//
let CollectionTools = dynamic([
    "powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe",
    "rundll32.exe","python.exe","robocopy.exe","xcopy.exe","esentutl.exe",
    "certutil.exe","7z.exe","7zG.exe","WinRAR.exe","rar.exe","tar.exe",
    "curl.exe","rclone.exe" ]);
// Read file content to draw a preview. Excluded: the file was rendered,
// not opened with intent. Accepted gap: browsing a share with the preview
// pane enabled is invisible to this rule.
let RenderingProcesses = dynamic([
    "prevhost.exe","PreviewHost.exe","msedgewebview2.exe","dllhost.exe" ]);
// Scan / index / sync / backup. Read everything by design.
let PlatformProcesses = dynamic([
    "MsMpEng.exe","MsSense.exe","SenseIR.exe","SenseCE.exe",
    "SearchIndexer.exe","SearchProtocolHost.exe","OneDrive.exe","FileCoAuth.exe",
    "DOCSTORBKP.exe","DOCSTOR.exe" ]);
let TrustedLocations = dynamic([
    @"c:\program files", @"c:\program files (x86)",
    @"c:\windows\system32", @"c:\windows\syswow64" ]);
// Attachment / preview caches - copies, not the originals.
let TransientPaths = dynamic([
    @"\appdata\local\microsoft\windows\inetcache\content.outlook\",
    @"\appdata\local\microsoft\windows\temporary internet files\",
    @"\appdata\local\microsoft\windows\inetcache\ie\" ]);
//
// --- Condition thresholds (all environment-specific) -----------------
let MinFilesForTiming   = 20;    // Floor: below this, gap stats are unreliable
let MaxMedianGapSec     = 2.0;   // A person does not open a doc every 2s sustained
let MaxGapVariation     = 0.5;   // stdev/mean. Low = regular = loop. Scale-invariant.
let MinToolFiles        = 10;    // Below this, plausibly a single archive operation
let MinToolRoots        = 2;     // One root = zipping a project. Two unrelated = not.
let MinHarvestFolders   = 10;    // Fewer is normal project navigation
let MaxHarvestPerFolder = 1.5;   // ~1 file per location = picking files out
let MinShareRoots       = 3;     // Separate shares, not subfolders of one
let MinFilesForShares   = 20;
//
DeviceEvents
| where Timestamp >= ago(LookbackWindow)
| where ActionType == "SensitiveFileRead"
| where isnotempty(FolderPath) and isnotempty(InitiatingProcessFileName)
//
// --- Process exclusions -----------------------------------------------
// Excluded only when running from a trusted location, so a copy of a
// trusted binary name elsewhere on disk stays in scope.
| extend InTrustedLocation = tolower(InitiatingProcessFolderPath) has_any (TrustedLocations)
| where not(InitiatingProcessFileName in~ (RenderingProcesses) and InTrustedLocation)
| where not(InitiatingProcessFileName in~ (PlatformProcesses)  and InTrustedLocation)
//
// --- Path normalisation -----------------------------------------------
| extend FullPath = iff(FolderPath endswith FileName,
                        FolderPath, strcat(FolderPath, @"\", FileName))
| extend DirectoryPath = tostring(parse_path(FullPath).DirectoryPath)
| where not (tolower(DirectoryPath) has_any (TransientPaths))
| extend FolderRoot = strcat_array(array_slice(split(DirectoryPath, @"\"), 0, 3), @"\")
| extend FileExt          = tolower(tostring(parse_path(FullPath).Extension))
| extend IsNetworkPath    = FullPath startswith @"\\"
| extend IsCollectionTool = InitiatingProcessFileName in~ (CollectionTools)
//
// --- Inter-arrival gaps per actor -------------------------------------
// sort forces single-node processing. Kept after all filters so it only
// ever sees SensitiveFileRead rows.
| extend ActorKey = strcat(DeviceId, "|", InitiatingProcessAccountSid)
| sort by ActorKey asc, Timestamp asc
| extend GapSeconds = iff(prev(ActorKey) == ActorKey,
             todouble(datetime_diff('millisecond', Timestamp, prev(Timestamp))) / 1000.0,
             real(null))
//
// --- Aggregate: one row per device + identity -------------------------
| summarize
      StartTime             = min(Timestamp),
      EndTime               = max(Timestamp),
      TotalReadEvents       = count(),
      DistinctFiles         = count_distinct(FullPath),
      DistinctFolders       = count_distinct(DirectoryPath),
      DistinctRoots         = count_distinct(FolderRoot),
      DistinctExtensions    = count_distinct(FileExt),
      NetworkPathReads      = countif(IsNetworkPath),
      NetworkRoots          = count_distinctif(FolderRoot, IsNetworkPath),
      FilesByCollectionTool = count_distinctif(FullPath, IsCollectionTool),
      MedianGap             = percentile(GapSeconds, 50),
      MeanGap               = avg(GapSeconds),
      GapStdDev             = stdev(GapSeconds),
      MinGap                = min(GapSeconds),
      MaxGap                = max(GapSeconds),
      SubSecondReads        = countif(GapSeconds < 1.0),
      Processes             = make_set(InitiatingProcessFileName, 10),
      SampleRoots           = make_set(FolderRoot, 10),
      SampleFiles           = make_set(FileName, 20)
  by DeviceId, DeviceName,
     AccountUpn    = InitiatingProcessAccountUpn,
     AccountName   = InitiatingProcessAccountName,
     AccountDomain = InitiatingProcessAccountDomain,
     AccountSid    = InitiatingProcessAccountSid
//
// --- Derived metrics --------------------------------------------------
| extend DurationMinutes = round((EndTime - StartTime) / 1m, 2)
| extend FilesPerFolder  = round(todouble(DistinctFiles) / max_of(DistinctFolders, 1), 2)
| extend GapVariation    = round(GapStdDev / max_of(MeanGap, 0.001), 2)
| extend FilesPerMinute  = round(todouble(DistinctFiles) / max_of(DurationMinutes, 0.1), 2)
| extend PctSubSecond    = round(100.0 * SubSecondReads / max_of(TotalReadEvents - 1, 1), 1)
| extend ReadsPerFile    = round(todouble(TotalReadEvents) / max_of(DistinctFiles, 1), 2)
//
// --- Conditions -------------------------------------------------------
// A: A scripting or archiving tool read sensitive files from more than one
//    unrelated location. Zipping a single project reads from one root.
| extend Cond_Tool = FilesByCollectionTool >= MinToolFiles
                 and DistinctRoots >= MinToolRoots
//
// B: Reads arrived at near-constant intervals. People read irregularly;
//    loops do not.
| extend Cond_Timing = DistinctFiles >= MinFilesForTiming
                   and MedianGap < MaxMedianGapSec
                   and GapVariation < MaxGapVariation
//
// C: Roughly one file taken from each of many separate folders - consistent
//    with picking files out, not working through a directory.
| extend Cond_Harvest = DistinctFolders >= MinHarvestFolders
                    and FilesPerFolder <= MaxHarvestPerFolder
//
// D: Sensitive files read from several different network shares.
| extend Cond_Shares = NetworkRoots >= MinShareRoots
                   and DistinctFiles >= MinFilesForShares
//
| extend MatchedConditions = array_strcat(array_concat(
      iff(Cond_Tool,    dynamic(["Collection tool across multiple locations"]), dynamic([])),
      iff(Cond_Timing,  dynamic(["Machine-regular read intervals"]),            dynamic([])),
      iff(Cond_Harvest, dynamic(["One file taken from many folders"]),          dynamic([])),
      iff(Cond_Shares,  dynamic(["Multiple network shares accessed"]),          dynamic([]))
  ), "; ")
| where isnotempty(MatchedConditions)
//
// --- Entity columns ---------------------------------------------------
// DeviceName is an FQDN; split so the Host entity correlates with
// SecurityEvent / SigninLogs, which use short names.
| extend HostName      = tostring(split(DeviceName, ".")[0])
| extend HostDnsDomain = iff(DeviceName contains ".",
                             strcat_array(array_slice(split(DeviceName, "."), 1, -1), "."), "")
| extend UpnSuffix     = tostring(split(AccountUpn, "@")[1])
//
| project
      // What matched
      MatchedConditions, Cond_Tool, Cond_Timing, Cond_Harvest, Cond_Shares,
      // When
      StartTime, EndTime, DurationMinutes,
      // Who / where
      HostName, HostDnsDomain, DeviceName, DeviceId,
      AccountName, AccountDomain, AccountUpn, UpnSuffix, AccountSid,
      // Scope
      DistinctFiles, TotalReadEvents, ReadsPerFile,
      DistinctFolders, DistinctRoots, FilesPerFolder, DistinctExtensions,
      NetworkPathReads, NetworkRoots,
      // Timing
      MedianGap, MeanGap, GapStdDev, GapVariation, MinGap, MaxGap,
      SubSecondReads, PctSubSecond, FilesPerMinute,
      // Process
      FilesByCollectionTool,
      ProcessesStr   = tostring(Processes),
      SampleRootsStr = tostring(SampleRoots),
      SampleFilesStr = tostring(SampleFiles)
| order by DistinctFiles desc
