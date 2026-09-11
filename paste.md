//=====================================================================
// Mass Document Staging Followed by Archive Creation
// MITRE: TA0009 Collection — T1074.001, T1560.001
//
// Rule config: queryFrequency 30m | queryPeriod 3h
// Requires: Defender XDR connector with DeviceFileEvents streaming.
//
// SCOPE LIMITATION — this rule does NOT cover staging in:
//   - Documents / Downloads / Desktop / OneDrive sync root
//   - Any non-C: volume (network drives, removable media)
// These are excluded for volume reasons. Coverage gap is deliberate.
//=====================================================================

// ---------- Tunables (all environment-specific) ----------
let AnchorSlice          = 30m;        // MUST match queryFrequency
let StagingWindow        = 30m;        // staging lookback per archive
let StagingFileThreshold = 100;        // TUNE
let ArchiveMinSizeBytes  = 10485760;   // 10 MB — TUNE

let DocExtensions = dynamic([
    "doc","docx","docm","dot","dotx","xls","xlsx","xlsm","xlsb",
    "ppt","pptx","pptm","pdf","csv","txt","rtf","odt","ods","odp",
    "msg","eml","one","vsd","vsdx"
]);
let ArchiveExtensions = dynamic([
    "zip","zipx","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","arj","lzh"
]);
let ArchiverProcesses = dynamic([
    "7z.exe","7zg.exe","7zfm.exe","7za.exe","winrar.exe","rar.exe",
    "peazip.exe","bandizip.exe","wzzip.exe","winzip32.exe","winzip64.exe",
    "tar.exe","zip.exe","makecab.exe","explorer.exe",
    "powershell.exe","pwsh.exe","cmd.exe","python.exe","wscript.exe","cscript.exe"
]);
let DecompressionProcesses = dynamic([
    "7z.exe","7zg.exe","7zfm.exe","7za.exe","winrar.exe","rar.exe","unrar.exe",
    "tar.exe","peazip.exe","bandizip.exe","wzzip.exe","winzip32.exe","winzip64.exe",
    "zip.exe","unzip.exe"
]);

//---------------------------------------------------------------------
// BLOCK 1 — Archive anchors (the rare event; drives the whole rule)
// Sliced by ingestion_time() so late-arriving MDE data is still
// processed exactly once, in the run where it lands.
//---------------------------------------------------------------------
let ArchiveAnchors =
    DeviceFileEvents
    | where ingestion_time() > ago(AnchorSlice)
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (ArchiveExtensions)
    | where InitiatingProcessFileName in~ (ArchiverProcesses)
    | where ArchiveMinSizeBytes == 0 or tolong(FileSize) >= ArchiveMinSizeBytes
    // OneDrive "download as zip" — multipart volume unpacked into temp.
    // Narrow: requires process AND temp path AND volume-suffix directory.
    | where not(InitiatingProcessFileName in~ ("explorer.exe","onedrive.exe")
            and FolderPath has @"\appdata\local\temp\"
            and FolderPath matches regex @"\.zip\.[0-9a-f]{3}\\")
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | extend ArchiveFolderNorm = tolower(iff(
          tolower(FolderPath) endswith tolower(FileName),
          substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
          FolderPath))
    | extend ArchiveFolderNorm = trim_end(@"\\+", ArchiveFolderNorm)
    | project ArchiveTime      = TimeGenerated,
              DeviceId, DeviceName, AccountSid,
              AccountUpn       = InitiatingProcessAccountUpn,
              ArchiveName      = FileName,
              ArchiveFolderNorm,
              ArchiveSizeBytes = tolong(FileSize),
              ArchiveSha256    = SHA256,
              ArchiveProcess   = InitiatingProcessFileName,
              ArchiveCmdLine   = InitiatingProcessCommandLine;

//---------------------------------------------------------------------
// BLOCK 2 — Bucket keys. Bounds the join to 2 bins per anchor,
// preventing a cross product against all file activity in the period.
//---------------------------------------------------------------------
let ArchiveKeyed =
    ArchiveAnchors
    | mv-expand JoinBucket = pack_array(
          bin(ArchiveTime, StagingWindow),
          bin(ArchiveTime, StagingWindow) - StagingWindow
      ) to typeof(datetime);

//---------------------------------------------------------------------
// BLOCK 3 — Staging candidates
// Filter order: cheapest + most selective first.
//---------------------------------------------------------------------
let StagingEvents =
    DeviceFileEvents
    | where ActionType == "FileCreated"
    // Optional prefilter — cuts extract() cost substantially.
    // Superset match (can over-match, never under-match); the exact
    // Ext check below is authoritative. Compare counts before enabling.
    // | where FileName has_any (DocExtensions)
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (DocExtensions)
    | extend InitProc = tolower(InitiatingProcessFileName)
    | where InitProc !in (DecompressionProcesses)
    | where FolderPath startswith "C:\\"
    // --- Baseline user-activity exclusions (SEE SCOPE LIMITATION) ---
    | where not(FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\(Documents|Downloads|Desktop|OneDrive - ORG NAME HERE|OneDrive - ORG NAME|ORG NAME)(\\|$)")
    | where not(FolderPath startswith "C:\\$Recycle.Bin")
    // --- Application-specific exclusions ---
    | where not(FolderPath has @"\appdata\local\microsoft\windows\inetcache"
            and InitiatingProcessFileName in~ ("outlook.exe","winword.exe","msedge.exe"))
    | where not(FolderPath has @"\appdata\local\temp\scrub"
            and InitiatingProcessFileName =~ "outlook.exe")
    | where not(FolderPath has @"\appdata\local\microsoft\capture\logs"
            and InitiatingProcessFileName =~ "capture.exe")
    | where not(FolderPath startswith "C:\\programdata\\APPNAME3\\APP NAME FOLDER.NAME"
            and InitiatingProcessFileName =~ "APP.NAME3.SERVICE.app.exe")
    | where not(FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\FOLDER NAME1(\\|$)"
            and InitiatingProcessFileName =~ "APPNAME2.exe")
    // FIXED: brackets — was not(A or (B and C)), now not((A or B) and C)
    | where not((FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\APPNAME1(\\|$)"
                 or FolderPath startswith "C:\\Temp\\")
            and InitiatingProcessFileName =~ "APPNAME1.exe")
    | where not(FolderPath startswith "C:\\programdata\\templateupdates"
            and InitiatingProcessFileName =~ "powershell.exe")
    | where not(InitiatingProcessFileName in~ ("explorer.exe","onedrive.exe")
            and FolderPath has @"\appdata\local\temp\"
            and FolderPath matches regex @"\.zip\.[0-9a-f]{3}\\")
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | extend StageFolderNorm = tolower(iff(
          tolower(FolderPath) endswith tolower(FileName),
          substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
          FolderPath))
    | extend StageFolderNorm = trim_end(@"\\+", StageFolderNorm)
    | project StageTime    = TimeGenerated,
              DeviceId, AccountSid,
              StagePath    = FolderPath,
              StageFolderNorm,
              StageProcess = InitiatingProcessFileName,
              StageExt     = Ext,
              JoinBucket   = bin(TimeGenerated, StagingWindow);

//---------------------------------------------------------------------
// BLOCK 4 — Correlate. Ordering constraint is what separates staging
// from decompression; do not remove it.
//---------------------------------------------------------------------
let Correlated =
    ArchiveKeyed
    | join kind=inner hint.shufflekey=DeviceId (StagingEvents)
        on DeviceId, AccountSid, JoinBucket
    | where StageTime < ArchiveTime
    | where StageTime >= ArchiveTime - StagingWindow
    // Split: archive inside staging tree = suspicious.
    //        staged files under archive path = extraction artefact.
    | extend ArchiveUnderStaging = iff(ArchiveFolderNorm startswith StageFolderNorm, 1, 0),
             StagingUnderArchive = iff(StageFolderNorm startswith ArchiveFolderNorm, 1, 0)
    | summarize StagedFileCount      = count_distinct(StagePath),
                StagingFolderCount   = count_distinct(StageFolderNorm),
                StagingFolders       = make_set(StageFolderNorm, 5),
                StagingProcesses     = make_set(StageProcess, 5),
                StagingExtensions    = make_set(StageExt, 6),
                FirstStagedFile      = min(StageTime),
                LastStagedFile       = max(StageTime),
                ArchiveUnderStaging  = max(ArchiveUnderStaging),
                StagingUnderArchive  = max(StagingUnderArchive)
        by ArchiveTime, DeviceId, DeviceName, AccountSid, AccountUpn,
           ArchiveName, ArchiveFolderNorm, ArchiveSizeBytes, ArchiveSha256,
           ArchiveProcess, ArchiveCmdLine;

//---------------------------------------------------------------------
// BLOCK 5 — One row per device + account. arg_max picks the largest
// archive for File / FileHash entity mapping.
//---------------------------------------------------------------------
Correlated
| where StagedFileCount >= StagingFileThreshold
| summarize StagedFileCount     = max(StagedFileCount),
            StagingFolderCount  = max(StagingFolderCount),
            StagingFolders      = take_any(StagingFolders),
            StagingProcesses    = take_any(StagingProcesses),
            StagingExtensions   = take_any(StagingExtensions),
            ArchiveCount        = dcount(ArchiveName),
            ArchiveNames        = make_set(ArchiveName, 5),
            ArchiveFolders      = make_set(ArchiveFolderNorm, 3),
            ArchiveProcesses    = make_set(ArchiveProcess, 3),
            ArchiveCmdLines     = make_set(ArchiveCmdLine, 3),
            TotalArchiveBytes   = sum(ArchiveSizeBytes),
            FirstArchive        = min(ArchiveTime),
            LastArchive         = max(ArchiveTime),
            FirstStagedFile     = min(FirstStagedFile),
            LastStagedFile      = max(LastStagedFile),
            ArchiveUnderStaging = max(ArchiveUnderStaging),
            StagingUnderArchive = max(StagingUnderArchive),
            (LargestArchiveBytes, LargestArchiveName, LargestArchiveFolder,
             LargestArchiveSha256, LargestArchiveProcess, LargestArchiveCmdLine)
                = arg_max(ArchiveSizeBytes, ArchiveName, ArchiveFolderNorm,
                          ArchiveSha256, ArchiveProcess, ArchiveCmdLine)
    by DeviceId, DeviceName, AccountSid, AccountUpn
| extend FilesPerFolder      = round(StagedFileCount * 1.0 / StagingFolderCount, 1),
         StagingDurationMin  = round(datetime_diff('second', LastStagedFile, FirstStagedFile) / 60.0, 1),
         GapToArchiveSeconds = datetime_diff('second', FirstArchive, LastStagedFile),
         LargestArchiveMB    = round(LargestArchiveBytes / 1048576.0, 1),
         TotalArchiveMB      = round(TotalArchiveBytes / 1048576.0, 1)
// Entity-mapping helpers
| extend AccountName   = tostring(split(AccountUpn, "@")[0]),
         UpnSuffix     = tostring(split(AccountUpn, "@")[1]),
         HashAlgorithm = "SHA256",
         TimeGenerated = FirstArchive,
         DedupeKey     = strcat(DeviceId, "|", AccountSid, "|", bin(FirstArchive, 30m))
| project TimeGenerated, DeviceId, DeviceName, AccountSid, AccountUpn,
          AccountName, UpnSuffix,
          StagedFileCount, StagingFolderCount, FilesPerFolder,
          StagingProcesses  = tostring(StagingProcesses),
          StagingExtensions = tostring(StagingExtensions),
          StagingFolders    = tostring(StagingFolders),
          StagingDurationMin, GapToArchiveSeconds,
          ArchiveCount, LargestArchiveMB, TotalArchiveMB,
          ArchiveProcesses  = tostring(ArchiveProcesses),
          ArchiveNames      = tostring(ArchiveNames),
          ArchiveFolders    = tostring(ArchiveFolders),
          ArchiveCmdLines   = tostring(ArchiveCmdLines),
          LargestArchiveName, LargestArchiveFolder, LargestArchiveSha256,
          LargestArchiveCmdLine, HashAlgorithm,
          ArchiveUnderStaging, StagingUnderArchive,
          FirstStagedFile, LastStagedFile, FirstArchive, DedupeKey
| order by TimeGenerated desc
