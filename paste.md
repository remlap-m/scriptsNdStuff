//==========================================================================
// HUNT: Bulk document creation by anomalous process, with staging escalator
// Window: 7 days, bucketed to match scheduled-rule burst windows
//==========================================================================
let Lookback            = 7d;
let BurstWindow         = 10m;    // TUNE - burst bucket size
let MinFileCount        = 40;     // TUNE - deliberately low (emission ceiling)
let ArchivePriorWindow  = 30m;    // how far back an archive suppresses
let ArchiveFollowWindow = 2h;     // how far forward an archive escalates
let OrderTrustCeiling   = 500;    // TUNE - above this, distrust temporal order
//
let DocExtensions = dynamic(["docx","doc","docm","xlsx","xls","xlsm","xlsb","pptx","ppt","pptm",
                             "pdf","csv","rtf","odt","ods","odp","msg","eml","pst","ost","one",
                             "vsdx","vsd","accdb","mdb"]);
let ArchiveExtensions = dynamic(["zip","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","wim",
                                 "arj","lzh","ace","001","z01","r00","r01"]);
let SuspectProcesses = dynamic(["robocopy.exe","xcopy.exe","powershell.exe","pwsh.exe","cmd.exe",
                                "wscript.exe","cscript.exe","mshta.exe","rundll32.exe","certutil.exe",
                                "bitsadmin.exe","esentutl.exe","forfiles.exe","curl.exe","wget.exe",
                                "wmic.exe","ftp.exe","python.exe"]);
let ExcludedAccounts = dynamic(["system","local service","network service","localsystem","-"]);
// PLACEHOLDER - replace with your service-account naming convention
let ServiceAcctRegex = @"^(svc|sa|adm|_)[-_.]";
// PLACEHOLDER - replace with a device-group join if you have one
let ExcludedDeviceRegex = @"^(srv|bld|vdi|sccm|mgmt)-";
// TUNE - extraction verbs
let ExtractionVerbs = @"(?i)(expand-archive|7z[a]?\s+[xe]\b|\brar\s+[xe]\b|\bunzip\b|tar\s+[^|]*-?x|extractto|\bexpand\s+-)";
//
let ScopedCreates =
    DeviceFileEvents
    | where Timestamp > ago(Lookback)
    | where ActionType == "FileCreated"
    | where isnotempty(InitiatingProcessFileName)
    | extend FileExt = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, FileName))
    | where FileExt in (DocExtensions)
    | extend InitProc = tolower(InitiatingProcessFileName)
    | where InitProc in (SuspectProcesses)
    | extend Acct = tolower(InitiatingProcessAccountName)
    | where Acct !in (ExcludedAccounts)
    | where Acct !endswith "$"
    | where not(Acct matches regex ServiceAcctRegex)
    | where not(tolower(DeviceName) matches regex ExcludedDeviceRegex)
    | extend IsExtractionCmd = tostring(InitiatingProcessCommandLine) matches regex ExtractionVerbs;
//
let Bursts =
    ScopedCreates
    | summarize
        FileCount          = count(),
        DistinctFolders    = dcount(FolderPath),
        DistinctExts       = dcount(FileExt),
        ExtractionCmdCount = countif(IsExtractionCmd),
        NetworkWrites      = countif(FolderPath startswith "\\\\"),
        TempWrites         = countif(FolderPath has @"\AppData\Local\Temp" or FolderPath has @"\Windows\Temp"),
        AppDataWrites      = countif(FolderPath has @"\AppData\"),
        PublicWrites       = countif(FolderPath has @"\Users\Public\" or FolderPath has @"\ProgramData\"),
        FirstCreate        = min(Timestamp),
        LastCreate         = max(Timestamp),
        SampleFolders      = make_set(FolderPath, 8),
        SampleFiles        = make_set(FileName, 8),
        CmdSample          = make_set(substring(tostring(InitiatingProcessCommandLine), 0, 250), 3),
        ProcPaths          = make_set(InitiatingProcessFolderPath, 3)
      by DeviceId, DeviceName, Acct, InitProc, BurstStart = bin(Timestamp, BurstWindow)
    | where FileCount >= MinFileCount
    | extend BurstSpanSec = datetime_diff('second', LastCreate, FirstCreate)
    | extend FilesPerMin  = iff(BurstSpanSec <= 0, todouble(FileCount),
                                round(FileCount / (BurstSpanSec / 60.0), 1))
    | extend BurstQ1Time  = FirstCreate + (LastCreate - FirstCreate) * 0.25
    | extend BurstKey     = strcat(DeviceId, "|", Acct, "|", InitProc, "|", format_datetime(BurstStart, "yyyyMMddHHmm"));
//
let ArchiveEvents =
    DeviceFileEvents
    | where Timestamp > ago(Lookback)
    | where ActionType == "FileCreated"
    | extend ArchExt = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, FileName))
    | where ArchExt in (ArchiveExtensions)
    | project ArchiveTime = Timestamp, DeviceId,
              ArchAcct    = tolower(InitiatingProcessAccountName),
              ArchiveFull = strcat(FolderPath, "\\", FileName),
              ArchiveProc = tolower(InitiatingProcessFileName);
//
let BurstArchive =
    Bursts
    | project BurstKey, DeviceId, Acct, FirstCreate, LastCreate, BurstQ1Time
    | join kind=leftouter ArchiveEvents on DeviceId, $left.Acct == $right.ArchAcct
    | extend RelPos = case(
          isnull(ArchiveTime), "none",
          ArchiveTime between ((FirstCreate - ArchivePriorWindow) .. FirstCreate), "prior",
          ArchiveTime between (BurstQ1Time .. (LastCreate + ArchiveFollowWindow)), "following",
          "outofwindow")
    | summarize
        ArchivePriorCount  = countif(RelPos == "prior"),
        ArchiveFollowCount = countif(RelPos == "following"),
        PriorArchives      = make_set_if(ArchiveFull, RelPos == "prior", 5),
        FollowingArchives  = make_set_if(ArchiveFull, RelPos == "following", 5),
        FollowingArchProcs = make_set_if(ArchiveProc, RelPos == "following", 5)
      by BurstKey;
//
Bursts
| join kind=leftouter BurstArchive on BurstKey
| extend ArchivePriorCount  = coalesce(ArchivePriorCount, 0),
         ArchiveFollowCount = coalesce(ArchiveFollowCount, 0)
| extend Verdict = case(
      ExtractionCmdCount > 0,
          "SUPPRESS - extraction command line",
      ArchivePriorCount > 0 and FileCount <  OrderTrustCeiling,
          "SUPPRESS - archive precedes burst",
      ArchivePriorCount > 0 and FileCount >= OrderTrustCeiling,
          "ALERT - archive precedes, but volume exceeds order-trust ceiling",
          "ALERT")
| extend Severity = case(
      Verdict startswith "SUPPRESS",                      "n/a",
      ArchiveFollowCount > 0 and NetworkWrites > 0,       "High",
      ArchiveFollowCount > 0,                             "High",
      NetworkWrites > 0,                                  "Medium-High",
      TempWrites + AppDataWrites + PublicWrites > 0,      "Medium",
                                                          "Medium")
| where Verdict startswith "ALERT"
| project BurstStart, DeviceName, Acct, InitProc, FileCount, FilesPerMin, BurstSpanSec,
          DistinctFolders, DistinctExts, NetworkWrites, TempWrites, AppDataWrites, PublicWrites,
          ArchiveFollowCount, FollowingArchives, FollowingArchProcs,
          ArchivePriorCount, PriorArchives,
          Verdict, Severity, FirstCreate, LastCreate,
          SampleFolders, SampleFiles, CmdSample, ProcPaths, DeviceId, BurstKey
| sort by BurstStart desc














// Raw burst count (what the rule would fire on with no grouping)
| summarize AlertBursts = count()

// After device+account grouping over 4h (closer to real incident count)
| summarize by DeviceId, Acct, GroupWindow = bin(BurstStart, 4h)
| summarize GroupedIncidents = count()

// Noise profile - what's driving volume
| summarize Bursts = count(), TotalFiles = sum(FileCount) by InitProc, DeviceName
| sort by Bursts desc
