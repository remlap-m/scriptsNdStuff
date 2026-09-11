//=====================================================================
// ALERT PREVIEW — staging followed by archiving
// One row = one incident. 7-day backtest, 30-min windows.
// NOT an analytics rule. No exclusions applied.
//=====================================================================
let Lookback             = 7d;
let StagingWindow        = 30m;
let StagingFileThreshold = 100;
let ArchiveMinSizeBytes  = 10485760; //10mb
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
// ---- Exclusions: populate from this output ----
let ExcludedInitiatingProcesses = dynamic([]);
let ExcludedFolderPathFragments = dynamic([]);
let ExcludedAccountSids         = dynamic([]);
let ExcludedDeviceNames         = dynamic([]);
let ArchiveAnchors =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (ArchiveExtensions)
    | where tolower(InitiatingProcessFileName) in (ArchiverProcesses)
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | where AccountSid !in (ExcludedAccountSids)
    | where DeviceName !in~ (ExcludedDeviceNames)
    | where ArchiveMinSizeBytes == 0 or tolong(FileSize) >= ArchiveMinSizeBytes
    | where not(InitiatingProcessFileName in~ ("explorer.exe","onedrive.exe") and FolderPath has @"\appdata\local\temp\" and FolderPath matches regex @"\.zip\.[0-9a-f]{3}\\")
    | extend ArchiveFolderNorm = tolower(iff(
          tolower(FolderPath) endswith tolower(FileName),
          substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
          FolderPath))
    | extend ArchiveFolderNorm = trim_end(@"\\+", ArchiveFolderNorm)
    | project ArchiveTime = TimeGenerated, DeviceId, DeviceName, AccountSid,
              AccountUpn      = InitiatingProcessAccountUpn,
              ArchiveName     = FileName,
              ArchiveFolderNorm,
              ArchiveSizeBytes= tolong(FileSize),
              ArchiveProcess  = InitiatingProcessFileName,
              ArchiveCmdLine  = InitiatingProcessCommandLine;
let ArchiveKeyed =
    ArchiveAnchors
    | mv-expand JoinBucket = pack_array(
          bin(ArchiveTime, StagingWindow),
          bin(ArchiveTime, StagingWindow) - StagingWindow
      ) to typeof(datetime);
let StagingEvents =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where FolderPath startswith "C:\\"
    | where not(FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\(Documents|Downloads|Desktop|OneDrive - ORG NAME HERE|OneDrive - ORG NAME|ORG NAME)(\\|$)" or FolderPath startswith "C:\\$Recycle.Bin")
    | where not(FolderPath has_any (@"\appdata\local\microsoft\windows\inetcache") and InitiatingProcessFileName has_any ("outlook.exe","winword.exe", "msedge.exe"))
    | where not(FolderPath has @"\appdata\local\temp\scrub" and InitiatingProcessFileName has_any ("outlook.exe"))
    | where not(FolderPath has @"\appdata\local\microsoft\capture\logs" and InitiatingProcessFileName has_any ("capture.exe"))
    | where not(FolderPath startswith "c:\\programdata\\APPNAME3\\APP NAME FOLDER.NAME" and InitiatingProcessFileName == "APP.NAME3.SERVICE.app.exe")
    | where not(FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\(FOLDER NAME1)(\\|$)" and InitiatingProcessFileName =~ "APPNAME2.exe")
    | where not(FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\(APPNAME1)(\\|$)" or FolderPath startswith "C:\\Temp\\" and InitiatingProcessFileName =~ "APPNAME1.exe")
    | where not(FolderPath startswith "C:\\programdata\\templateupdates" and InitiatingProcessFileName =~ "powershell.exe")
    | where not(InitiatingProcessFileName in~ ("explorer.exe","onedrive.exe") and FolderPath has @"\appdata\local\temp\" and FolderPath matches regex @"\.zip\.[0-9a-f]{3}\\")
    | where Ext in (DocExtensions)
    | extend AccountSid = tostring(InitiatingProcessAccountSid),
             InitProc   = tolower(InitiatingProcessFileName)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | where InitProc !in (DecompressionProcesses)
    | where InitProc !in (ExcludedInitiatingProcesses)
    | where array_length(ExcludedFolderPathFragments) == 0
         or not(tolower(FolderPath) has_any (ExcludedFolderPathFragments))
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
let Correlated =
    ArchiveKeyed
    | join kind=inner hint.shufflekey=DeviceId (StagingEvents)
        on DeviceId, AccountSid, JoinBucket
    | where StageTime < ArchiveTime
    | where StageTime >= ArchiveTime - StagingWindow
    | extend SameTree = iff(
          ArchiveFolderNorm startswith StageFolderNorm
       or StageFolderNorm  startswith ArchiveFolderNorm, 1, 0)
    | summarize StagedFileCount      = count_distinct(StagePath),
                StagingFolderCount   = count_distinct(StageFolderNorm),
                StagingFolders       = make_set(StageFolderNorm, 5),
                StagingProcesses     = make_set(StageProcess, 5),
                StagingExtensions    = make_set(StageExt, 6),
                FirstStagedFile      = min(StageTime),
                LastStagedFile       = max(StageTime),
                ArchiveInStagingTree = max(SameTree)
        by ArchiveTime, DeviceId, DeviceName, AccountSid, AccountUpn,
           ArchiveName, ArchiveFolderNorm, ArchiveSizeBytes,
           ArchiveProcess, ArchiveCmdLine;
// one row 
Correlated
| where StagedFileCount >= StagingFileThreshold
| summarize StagedFileCount      = max(StagedFileCount),
            StagingFolderCount   = max(StagingFolderCount),
            StagingFolders       = take_any(StagingFolders),
            StagingProcesses     = take_any(StagingProcesses),
            StagingExtensions    = take_any(StagingExtensions),
            ArchiveCount         = dcount(ArchiveName),
            ArchiveNames         = make_set(ArchiveName, 5),
            ArchiveFolders       = make_set(ArchiveFolderNorm, 3),
            ArchiveProcesses     = make_set(ArchiveProcess, 3),
            ArchiveCmdLines      = make_set(ArchiveCmdLine, 5),
            LargestArchiveMB     = round(max(ArchiveSizeBytes) / 1048576.0, 1),
            TotalArchiveMB       = round(sum(ArchiveSizeBytes) / 1048576.0, 1),
            FirstArchive         = min(ArchiveTime),
            LastArchive          = max(ArchiveTime),
            FirstStagedFile      = min(FirstStagedFile),
            LastStagedFile       = max(LastStagedFile),
            ArchiveInStagingTree = max(ArchiveInStagingTree)
    by DeviceId, DeviceName, AccountSid, AccountUpn,
       RunWindow = bin(ArchiveTime, 30m)
| extend FilesPerFolder      = round(StagedFileCount * 1.0 / StagingFolderCount, 1),
         StagingDurationMin  = round(datetime_diff('second', LastStagedFile, FirstStagedFile) / 60.0, 1),
         GapToArchiveSeconds = datetime_diff('second', FirstArchive, LastStagedFile)
| project RunWindow, DeviceName, AccountUpn,
          StagedFileCount, StagingFolderCount, FilesPerFolder,
          StagingProcesses  = tostring(StagingProcesses),
          StagingExtensions = tostring(StagingExtensions),
          StagingFolders    = tostring(StagingFolders),
          StagingDurationMin, GapToArchiveSeconds,
          ArchiveCount, LargestArchiveMB, TotalArchiveMB,
          ArchiveProcesses  = tostring(ArchiveProcesses),
          ArchiveNames      = tostring(ArchiveNames),
          ArchiveFolders    = tostring(ArchiveFolders),
          ArchiveInStagingTree,
          FirstStagedFile, LastStagedFile, FirstArchive,
          ArchiveCmdLines   = tostring(ArchiveCmdLines)
| order by RunWindow desc
