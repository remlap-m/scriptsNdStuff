//==========================================================================
// HQ-MassDocCreationAnomalousProcess
// Sentinel scheduled analytics rule
//
// REQUIRED RULE CONFIG - the in-query logic depends on it:
//   Run query every : 1 hour        <-- if you change this, update Liveness below
//   Lookup period   : 8 hours       -- must exceed BurstWindow + ArchiveFollowWindow + skew
//   Event grouping  : trigger an alert for each event (1 row = 1 burst)
//   Alert grouping  : ON, Host + Account, 8 hours   <-- backstop, not primary dedupe
//==========================================================================
let BurstWindow         = 1h;      // UNMEASURED - set from observed Timestamp spread
let MinFileCount        = 40;      // UNMEASURED - set from baseline distribution run
let ArchivePriorWindow  = 30m;     // UNVALIDATED PLACEHOLDER
let ArchiveFollowWindow = 2h;      // UNVALIDATED PLACEHOLDER
let OrderTrustCeiling   = 500;     // DERIVED - local testing: 600 clean, 3000 reordered
// Dedupe gate. Constraints, all three of which fail silently if broken:
//   1. MUST be < the lookup period, or the filter is inert.
//   2. MUST be >= frequency + jitter, or a burst landing just after a run is
//      never reported. A miss is worse than a duplicate.
//   3. MUST be updated by hand if the wizard frequency changes.
// 2h15m tolerates one missed/delayed execution at the cost of at most two
// alerts per burst. Tight setting for 1h frequency would be 1h15m.
let Liveness            = 2h15m;
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
let ServiceAcctRegex    = @"^(svc|sa|adm|_)[-_.]";        // PLACEHOLDER
let ExcludedDeviceRegex = @"^(srv|bld|vdi|sccm|mgmt)-";   // PLACEHOLDER - prefer device-group join
let ExtractionVerbs = @"(?i)(expand-archive|7z[a]?\s+[xe]\b|\brar\s+[xe]\b|\bunzip\b|tar\s+[^|]*-?x|extractto|\bexpand\s+-)";
//
let ScopedCreates =
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where isnotempty(InitiatingProcessFileName)
    | extend FileExt = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, FileName))
    | where FileExt in (DocExtensions)
    | extend InitProc = tolower(InitiatingProcessFileName)
    // [VERSIONINFO] delete next 2 lines if the field is absent in this tenant
    | extend InitProcOriginal = tolower(tostring(InitiatingProcessVersionInfoOriginalFileName))
    | extend NameMismatch = isnotempty(InitProcOriginal) and InitProcOriginal != InitProc
    | where InitProc in (SuspectProcesses) or InitProcOriginal in (SuspectProcesses)
    | extend Acct       = tolower(InitiatingProcessAccountName),
             AcctDomain = tostring(InitiatingProcessAccountDomain),
             AcctUpn    = tostring(InitiatingProcessAccountUpn)
    | where Acct !in (ExcludedAccounts)
    | where Acct !endswith "$"
    | where not(Acct matches regex ServiceAcctRegex)
    | where not(tolower(DeviceName) matches regex ExcludedDeviceRegex)
    | extend IsExtractionCmd = tostring(InitiatingProcessCommandLine) matches regex ExtractionVerbs
    | extend IngestAt = ingestion_time();
//
// NOTE: aggregation runs over the FULL lookup period. The dedupe gate is applied
// after this, never before it - filtering raw rows by ingestion time would count
// a batched burst in fragments and fail the threshold on every run.
let Bursts =
    ScopedCreates
    | summarize
        FileCount          = count(),
        DistinctFolders    = dcount(FolderPath),
        DistinctExts       = dcount(FileExt),
        ExtractionCmdCount = countif(IsExtractionCmd),
        MismatchCount      = countif(NameMismatch),          // [VERSIONINFO]
        OriginalNames      = make_set(InitProcOriginal, 3),  // [VERSIONINFO]
        NetworkWrites      = countif(FolderPath startswith "\\\\"),
        TempWrites         = countif(FolderPath has @"\AppData\Local\Temp" or FolderPath has @"\Windows\Temp"),
        AppDataWrites      = countif(FolderPath has @"\AppData\"),
        PublicWrites       = countif(FolderPath has @"\Users\Public\" or FolderPath has @"\ProgramData\"),
        FirstCreate        = min(Timestamp),
        LastCreate         = max(Timestamp),
        FirstIngest        = min(IngestAt),
        LastIngest         = max(IngestAt),
        LastRowTG          = max(TimeGenerated),
        AcctDomain         = any(AcctDomain),
        AcctUpn            = any(AcctUpn),
        SampleFolders      = make_set(FolderPath, 8),
        SampleFiles        = make_set(FileName, 8),
        CmdSample          = make_set(substring(tostring(InitiatingProcessCommandLine), 0, 250), 3),
        ProcPaths          = make_set(InitiatingProcessFolderPath, 3)
      by DeviceId, DeviceName, Acct, InitProc, BurstStart = bin(Timestamp, BurstWindow)
    | where FileCount >= MinFileCount
    | extend BurstSpanSec    = datetime_diff('second', LastCreate, FirstCreate)
    | extend IngestSpreadSec = datetime_diff('second', LastIngest, FirstIngest)
    | extend MaxLagMin       = datetime_diff('minute', LastIngest, FirstCreate)
    | extend FilesPerMin     = iff(BurstSpanSec <= 0, todouble(FileCount),
                                   round(FileCount / (BurstSpanSec / 60.0), 1))
    | extend BurstQ1Time     = FirstCreate + (LastCreate - FirstCreate) * 0.25
    | extend BurstKey        = strcat(DeviceId, "|", Acct, "|", InitProc, "|", format_datetime(BurstStart, "yyyyMMddHHmm"));
//
let ArchiveEvents =
    DeviceFileEvents
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
// --- Suppression: likely archive extraction ---
// Command-line verb is timestamp-independent, so suppress unconditionally.
| where ExtractionCmdCount == 0
// Preceding archive is order-based, so only trusted below the volume at which
// local testing showed event ordering becomes unreliable (600 clean / 3000 reordered).
| where ArchivePriorCount == 0 or FileCount >= OrderTrustCeiling
// --- Dedupe gate ---
// Report a burst only on the run during which new rows arrived for it. The burst
// stays in scope on later runs, but with nothing new landed it stays silent.
| where LastIngest > ago(Liveness)
// --- Flatten dynamics for custom details / entity fields ---
| extend FollowingArchivesStr = tostring(strcat_array(FollowingArchives, "; ")),
         PriorArchivesStr     = tostring(strcat_array(PriorArchives, "; ")),
         SampleFoldersStr     = tostring(strcat_array(SampleFolders, "; ")),
         SampleFilesStr       = tostring(strcat_array(SampleFiles, "; ")),
         CmdSampleStr         = tostring(strcat_array(CmdSample, " || ")),
         ProcPathsStr         = tostring(strcat_array(ProcPaths, "; ")),
         OriginalNamesStr     = tostring(strcat_array(OriginalNames, "; "))
// Sentinel needs TimeGenerated on a summarised result for alert timestamping.
// Uses max(TimeGenerated) of contributing rows, NOT Timestamp - Timestamp is skewed
// and could fall outside the lookup period.
| extend TimeGenerated = LastRowTG
| project TimeGenerated, BurstStart, DeviceName, DeviceId, Acct, AcctDomain, AcctUpn, InitProc,
          FileCount, FilesPerMin, BurstSpanSec, DistinctFolders, DistinctExts,
          MismatchCount, OriginalNamesStr,
          NetworkWrites, TempWrites, AppDataWrites, PublicWrites,
          ArchiveFollowCount, FollowingArchivesStr, ArchivePriorCount, PriorArchivesStr,
          FirstCreate, LastCreate, FirstIngest, LastIngest, IngestSpreadSec, MaxLagMin,
          SampleFoldersStr, SampleFilesStr, CmdSampleStr, ProcPathsStr, BurstKey
