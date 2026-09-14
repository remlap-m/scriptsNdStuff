let CandidateSet = materialize(
    let Lookback = 7d;
    let ReadThreshold = 100;
    let CreateThreshold = 100;
    let WindowMinutes = 30;
    let DocumentExtensions = dynamic(["doc","docx","xls","xlsx","ppt","pptx","pdf","csv","txt","rtf","odt","ods","odp"]);
    let ArchiveExtensions = dynamic(["zip","7z","rar","tar","gz","bz2","cab","iso"]);
    let CountedExtensions = array_concat(DocumentExtensions, ArchiveExtensions);
    let ExcludedProcesses = dynamic(["MsMpEng.exe", "backupagent.exe"]);  // TODO: your current exclusion list
    let ExcludedAccounts = dynamic(["SYSTEM", "NETWORK SERVICE"]);        // TODO: your current exclusion list
    let Reads =
        DeviceEvents
        | where TimeGenerated > ago(Lookback)
        | where ActionType == "SensitiveFileRead"
        | where InitiatingProcessAccountName !in (ExcludedAccounts)
        | where InitiatingProcessFileName !in (ExcludedProcesses)
        | extend FileExt = tolower(extract(@"\.([0-9a-z]+)$", 1, FileName))
        | where FileExt in (CountedExtensions)
        | extend Bin = bin(TimeGenerated, 30m)
        | summarize ReadCount = count(),
                    FirstRead = min(TimeGenerated),
                    LastRead = max(TimeGenerated),
                    SampleReadFiles = make_set(FileName, 10),
                    ReadFolders = make_set(FolderPath, 10),
                    DistinctReadFolders = dcount(FolderPath),
                    ReadProcesses = make_set(InitiatingProcessFileName, 5),
                    DistinctReadProcesses = dcount(InitiatingProcessFileName)
              by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, Bin
        | where ReadCount >= ReadThreshold
        | extend JoinBin = pack_array(Bin - 30m, Bin, Bin + 30m)
        | mv-expand JoinBin to typeof(datetime);
    let Creates =
        DeviceFileEvents
        | where TimeGenerated > ago(Lookback)
        | where ActionType == "FileCreated"
        | where InitiatingProcessAccountName !in (ExcludedAccounts)
        | where InitiatingProcessFileName !in (ExcludedProcesses)
        | extend FileExt = tolower(extract(@"\.([0-9a-z]+)$", 1, FileName))
        | where FileExt in (CountedExtensions)
        | extend Bin = bin(TimeGenerated, 30m)
        | summarize CreateCount = count(),
                    FirstCreate = min(TimeGenerated),
                    LastCreate = max(TimeGenerated),
                    SampleCreateFiles = make_set(FileName, 10),
                    SampleCreateFolders = make_set(FolderPath, 10),
                    DistinctCreateFolders = dcount(FolderPath),
                    CreateProcesses = make_set(InitiatingProcessFileName, 5),
                    DistinctCreateProcesses = dcount(InitiatingProcessFileName),
                    ArchiveCount = countif(FileExt in (ArchiveExtensions)),
                    ArchiveFiles = make_set_if(FileName, FileExt in (ArchiveExtensions)),
                    ArchiveFolders = make_set_if(FolderPath, FileExt in (ArchiveExtensions))
              by DeviceId, InitiatingProcessAccountName, Bin
        | where CreateCount >= CreateThreshold;
    Reads
    | join kind=inner (Creates) on DeviceId, InitiatingProcessAccountName, $left.JoinBin == $right.Bin
    | extend GapMinutes = datetime_diff('minute', FirstCreate, LastRead)
    | extend AbsGapMinutes = abs(GapMinutes)
    | where GapMinutes between (-5 .. WindowMinutes)
    | summarize arg_min(AbsGapMinutes, ReadCount, LastRead, SampleReadFiles, ReadFolders, DistinctReadFolders,
                         ReadProcesses, DistinctReadProcesses,
                         CreateCount, FirstCreate, LastCreate, SampleCreateFiles, SampleCreateFolders, DistinctCreateFolders,
                         CreateProcesses, DistinctCreateProcesses,
                         ArchiveCount, ArchiveFiles, ArchiveFolders,
                         DeviceName, InitiatingProcessAccountDomain)
          by DeviceId, InitiatingProcessAccountName, Bin
    | project TimeGenerated = Bin, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName,
              ReadCount, LastRead, SampleReadFiles, ReadFolders, DistinctReadFolders, ReadProcesses, DistinctReadProcesses,
              CreateCount, FirstCreate, LastCreate, SampleCreateFiles, SampleCreateFolders, DistinctCreateFolders,
              CreateProcesses, DistinctCreateProcesses,
              GapMinutes = AbsGapMinutes, ArchiveCount, ArchiveFiles, ArchiveFolders
);
//
let CandidateWindows =
    CandidateSet
    | project DeviceId, InitiatingProcessAccountName, WindowStart = LastRead - 35m, WindowEnd = LastCreate + 5m;
//
let RawReads =
    DeviceEvents
    | where TimeGenerated > ago(7d)
    | where ActionType == "SensitiveFileRead"
    | join kind=inner (CandidateWindows) on DeviceId, InitiatingProcessAccountName
    | where TimeGenerated between (WindowStart .. WindowEnd)
    | project DeviceId, InitiatingProcessAccountName, ReadFileName = FileName;
//
let RawCreates =
    DeviceFileEvents
    | where TimeGenerated > ago(7d)
    | where ActionType == "FileCreated"
    | join kind=inner (CandidateWindows) on DeviceId, InitiatingProcessAccountName
    | where TimeGenerated between (WindowStart .. WindowEnd)
    | project DeviceId, InitiatingProcessAccountName, CreateFileName = FileName;
//
let FilenameOverlap =
    RawReads
    | join kind=inner (RawCreates) on DeviceId, InitiatingProcessAccountName
    | where ReadFileName == CreateFileName
    | summarize OverlapFiles = make_set(ReadFileName, 20), OverlapCount = dcount(ReadFileName)
          by DeviceId, InitiatingProcessAccountName;
//
CandidateSet
| join kind=leftouter (FilenameOverlap) on DeviceId, InitiatingProcessAccountName
| extend OverlapCount = coalesce(OverlapCount, 0)
| order by OverlapCount desc, TimeGenerated desc
