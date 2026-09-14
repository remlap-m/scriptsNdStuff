let Lookback = 7d;
let ReadThreshold = 100;
let CreateThreshold = 100;
let WindowMinutes = 30;
let ArchiveExtensions = dynamic(["zip","7z","rar","tar","gz","bz2","cab","iso"]);
let ExcludedProcesses = dynamic(["MsMpEng.exe", "backupagent.exe"]);  // TODO: your current exclusion list
let ExcludedAccounts = dynamic(["SYSTEM", "NETWORK SERVICE"]);        // TODO: your current exclusion list
//
let Reads =
    DeviceEvents
    | where TimeGenerated > ago(Lookback)
    | where ActionType == "SensitiveFileRead"
    | where InitiatingProcessAccountName !in (ExcludedAccounts)
    | where InitiatingProcessFileName !in (ExcludedProcesses)
    | extend Bin = bin(TimeGenerated, 30m)
    | summarize ReadCount = count(),
                FirstRead = min(TimeGenerated),
                LastRead = max(TimeGenerated),
                SampleReadFiles = make_set(FileName, 10),
                ReadProcesses = make_set(InitiatingProcessFileName, 5),
                DistinctReadProcesses = dcount(InitiatingProcessFileName)
          by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, Bin
    | where ReadCount >= ReadThreshold
    | extend JoinBin = pack_array(Bin - 30m, Bin, Bin + 30m)
    | mv-expand JoinBin to typeof(datetime);
//
let Creates =
    DeviceFileEvents
    | where TimeGenerated > ago(Lookback)
    | where ActionType == "FileCreated"
    | where InitiatingProcessAccountName !in (ExcludedAccounts)
    | where InitiatingProcessFileName !in (ExcludedProcesses)
    | extend Bin = bin(TimeGenerated, 30m)
    | extend FileExt = tolower(extract(@"\.([0-9a-z]+)$", 1, FileName))
    | summarize CreateCount = count(),
                FirstCreate = min(TimeGenerated),
                LastCreate = max(TimeGenerated),
                SampleCreateFiles = make_set(FileName, 10),
                CreateProcesses = make_set(InitiatingProcessFileName, 5),
                DistinctCreateProcesses = dcount(InitiatingProcessFileName),
                ArchiveCount = countif(FileExt in (ArchiveExtensions)),
                ArchiveFiles = make_set_if(FileName, FileExt in (ArchiveExtensions)),
                ArchiveFolders = make_set_if(FolderPath, FileExt in (ArchiveExtensions)),
                NonArchiveFolders = make_set_if(FolderPath, FileExt !in (ArchiveExtensions))
          by DeviceId, InitiatingProcessAccountName, Bin
    | where CreateCount >= CreateThreshold;
//
Reads
| join kind=inner (Creates) on DeviceId, InitiatingProcessAccountName, $left.JoinBin == $right.Bin
| extend GapMinutes = datetime_diff('minute', FirstCreate, LastRead)
| extend AbsGapMinutes = abs(GapMinutes)
| where GapMinutes between (-5 .. WindowMinutes)
| summarize arg_min(AbsGapMinutes, ReadCount, LastRead, SampleReadFiles, ReadProcesses, DistinctReadProcesses,
                     CreateCount, FirstCreate, LastCreate, SampleCreateFiles, CreateProcesses, DistinctCreateProcesses,
                     ArchiveCount, ArchiveFiles, ArchiveFolders, NonArchiveFolders,
                     DeviceName, InitiatingProcessAccountDomain)
      by DeviceId, InitiatingProcessAccountName, Bin
| project TimeGenerated = Bin, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName,
          ReadCount, LastRead, SampleReadFiles, ReadProcesses, DistinctReadProcesses,
          CreateCount, FirstCreate, LastCreate, SampleCreateFiles, CreateProcesses, DistinctCreateProcesses,
          GapMinutes = AbsGapMinutes, ArchiveCount, ArchiveFiles, ArchiveFolders, NonArchiveFolders
| order by TimeGenerated desc
