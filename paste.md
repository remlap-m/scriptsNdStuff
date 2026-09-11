//=====================================================================
// HUNT — Document staging and archiving in unusual locations
// 7-day retrospective. Ordering tolerance replaces strict ordering
// to accommodate observed MDE timestamp skew on bulk file operations.
//=====================================================================

let Lookback             = 7d;
let StagingWindow        = 30m;
let OrderTolerance       = 15m;        // staging may report AFTER archive
let StagingFileThreshold = 100;        // NOTE: unreliable at volume — see caveats
let ArchiveMinSizeBytes  = 10485760;   // 10 MB

let UserDocRegex = @"(?i)C:\\Users\\[^\\]+\\(Documents|Downloads|Desktop|OneDrive - ORG NAME HERE|OneDrive - ORG NAME|ORG NAME)(\\|$)";

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
// BLOCK 1 — Archive anchors
//---------------------------------------------------------------------
let ArchiveAnchors =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (ArchiveExtensions)
    | where InitiatingProcessFileName in~ (ArchiverProcesses)
    | where ArchiveMinSizeBytes == 0 or tolong(FileSize) >= ArchiveMinSizeBytes
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
    | extend ArchiveUnusual = iff(FolderPath matches regex UserDocRegex, 0, 1)
    | project ArchiveTime      = TimeGenerated,
              DeviceId, DeviceName, AccountSid,
              AccountUpn       = InitiatingProcessAccountUpn,
              ArchiveName      = FileName,
              ArchiveFolderNorm, ArchiveUnusual,
              ArchiveSizeBytes = tolong(FileSize),
              ArchiveProcess   = InitiatingProcessFileName,
              ArchiveParent    = InitiatingProcessParentFileName,
              ArchiveCmdLine   = InitiatingProcessCommandLine;

//---------------------------------------------------------------------
// BLOCK 2 — Bucket keys. Widened to 3 bins to cover the tolerance
// window, since staging can now fall in the bin AFTER the archive.
//---------------------------------------------------------------------
let ArchiveKeyed =
    ArchiveAnchors
    | mv-expand JoinBucket = pack_array(
          bin(ArchiveTime, StagingWindow) + StagingWindow,
          bin(ArchiveTime, StagingWindow),
          bin(ArchiveTime, StagingWindow) - StagingWindow
      ) to typeof(datetime);

//---------------------------------------------------------------------
// BLOCK 3 — Staging candidates
//---------------------------------------------------------------------
let StagingEvents =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (DocExtensions)
    | extend InitProc = tolower(InitiatingProcessFileName)
    | where InitProc !in (DecompressionProcesses)
    | where FolderPath startswith "C:\\"
    | where not(FolderPath startswith "C:\\$Recycle.Bin")
    // --- Application noise exclusions ---
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
    | extend StageUnusual = iff(FolderPath matches regex UserDocRegex, 0, 1)
    | project StageTime    = TimeGenerated,
              DeviceId, AccountSid,
              StagePath    = FolderPath,
              StageFolderNorm, StageUnusual,
              StageProcess = InitiatingProcessFileName,
              StageExt     = Ext,
              JoinBucket   = bin(TimeGenerated, StagingWindow);

//---------------------------------------------------------------------
// BLOCK 4 — Correlate with ordering TOLERANCE
//---------------------------------------------------------------------
let Correlated =
    ArchiveKeyed
    | join kind=inner hint.shufflekey=DeviceId (StagingEvents)
        on DeviceId, AccountSid, JoinBucket
    | where StageTime <  ArchiveTime + OrderTolerance
    | where StageTime >= ArchiveTime - StagingWindow
    | extend ArchiveUnderStaging = iff(ArchiveFolderNorm startswith StageFolderNorm, 1, 0),
             StagingUnderArchive = iff(StageFolderNorm startswith ArchiveFolderNorm, 1, 0)
    | summarize StagedFileCount       = count_distinct(StagePath),
                StagedUnusualCount    = count_distinctif(StagePath, StageUnusual == 1),
                StagedAfterArchive    = count_distinctif(StagePath, StageTime > ArchiveTime),
                StagingFolderCount    = count_distinct(StageFolderNorm),
                StagingFolders        = make_set(StageFolderNorm, 5),
                StagingUnusualFolders = make_setif(StageFolderNorm, StageUnusual == 1, 5),
                StagingProcesses      = make_set(StageProcess, 5),
                StagingExtensions     = make_set(StageExt, 6),
                FirstStagedFile       = min(StageTime),
                LastStagedFile        = max(StageTime),
                ArchiveUnderStaging   = max(ArchiveUnderStaging),
                StagingUnderArchive   = max(StagingUnderArchive)
        by ArchiveTime, DeviceId, DeviceName, AccountSid, AccountUpn,
           ArchiveName, ArchiveFolderNorm, ArchiveUnusual, ArchiveSizeBytes,
           ArchiveProcess, ArchiveParent, ArchiveCmdLine;

//---------------------------------------------------------------------
// BLOCK 5 — Two branches, plus structural extraction filter
//---------------------------------------------------------------------
let Hits =
    Correlated
    // Structural: staged files UNDER the archive path = extraction.
    // Doing more work now that ordering is loose.
    | where StagingUnderArchive == 0
    | where StagedUnusualCount >= StagingFileThreshold
         or (ArchiveUnusual == 1 and StagedFileCount >= StagingFileThreshold)
    | extend MatchReason = case(
          StagedUnusualCount >= StagingFileThreshold and ArchiveUnusual == 1, "Both",
          StagedUnusualCount >= StagingFileThreshold,                         "StagingUnusual",
                                                                              "ArchiveUnusual");

//---------------------------------------------------------------------
// BLOCK 6 — One row per device + account + window
//---------------------------------------------------------------------
Hits
| summarize MatchReason           = tostring(make_set(MatchReason)),
            StagedFileCount       = max(StagedFileCount),
            StagedUnusualCount    = max(StagedUnusualCount),
            StagedAfterArchive    = max(StagedAfterArchive),
            StagingFolderCount    = max(StagingFolderCount),
            StagingFolders        = tostring(take_any(StagingFolders)),
            StagingUnusualFolders = tostring(take_any(StagingUnusualFolders)),
            StagingProcesses      = tostring(take_any(StagingProcesses)),
            StagingExtensions     = tostring(take_any(StagingExtensions)),
            ArchiveCount          = dcount(ArchiveName),
            ArchiveNames          = tostring(make_set(ArchiveName, 5)),
            ArchiveFolders        = tostring(make_set(ArchiveFolderNorm, 3)),
            ArchiveProcesses      = tostring(make_set(ArchiveProcess, 3)),
            ArchiveParents        = tostring(make_set(ArchiveParent, 3)),
            ArchiveCmdLines       = tostring(make_set(ArchiveCmdLine, 3)),
            LargestArchiveMB      = round(max(ArchiveSizeBytes) / 1048576.0, 1),
            TotalArchiveMB        = round(sum(ArchiveSizeBytes) / 1048576.0, 1),
            AnyArchiveUnusual     = max(ArchiveUnusual),
            ArchiveUnderStaging   = max(ArchiveUnderStaging),
            FirstArchive          = min(ArchiveTime),
            LastArchive           = max(ArchiveTime),
            FirstStagedFile       = min(FirstStagedFile),
            LastStagedFile        = max(LastStagedFile)
    by DeviceId, DeviceName, AccountSid, AccountUpn,
       RunWindow = bin(ArchiveTime, 30m)
| extend FilesPerFolder      = round(StagedFileCount * 1.0 / StagingFolderCount, 1),
         StagingDurationMin  = round(datetime_diff('second', LastStagedFile, FirstStagedFile) / 60.0, 1),
         GapToArchiveSeconds = datetime_diff('second', FirstArchive, LastStagedFile)
| project RunWindow, DeviceName, AccountUpn, MatchReason,
          StagedFileCount, StagedUnusualCount, StagedAfterArchive,
          StagingFolderCount, FilesPerFolder,
          StagingProcesses, StagingExtensions, StagingFolders, StagingUnusualFolders,
          StagingDurationMin, GapToArchiveSeconds,
          ArchiveCount, LargestArchiveMB, TotalArchiveMB, AnyArchiveUnusual,
          ArchiveProcesses, ArchiveParents, ArchiveNames, ArchiveFolders,
          ArchiveCmdLines, ArchiveUnderStaging,
          FirstStagedFile, LastStagedFile, FirstArchive
| order by RunWindow desc
