let Lookback = 7d;
let ReadThreshold = 50;
let CreateThreshold = 20;
let WindowMinutes = 30;
let ArchiveExtensions = dynamic(["zip","7z","rar","tar","gz","bz2","cab","iso"]);
//
let Reads =
    DeviceEvents
    | where TimeGenerated > ago(Lookback)
    | where ActionType == "SensitiveFileRead"
    | extend Bin = bin(TimeGenerated, 30m)
    | summarize ReadCount = count(),
                FirstRead = min(TimeGenerated),
                LastRead = max(TimeGenerated),
                SampleReadFiles = make_set(FileName, 10),
                ReadProcesses = make_set(InitiatingProcessFileName, 5),          // ADDED
                DistinctReadProcesses = dcount(InitiatingProcessFileName)         // ADDED
          by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, Bin
    | where ReadCount >= ReadThreshold
    | extend JoinBin = pack_array(Bin - 30m, Bin, Bin + 30m)
    | mv-expand JoinBin to typeof(datetime);
//
let Creates =
    DeviceFileEvents
    | where TimeGenerated > ago(Lookback)
    | where ActionType == "FileCreated"
    | extend Bin = bin(TimeGenerated, 30m)
    | extend FileExt = tolower(extract(@"\.([0-9a-z]+)$", 1, FileName))
    | summarize CreateCount = count(),
                FirstCreate = min(TimeGenerated),
                LastCreate = max(TimeGenerated),
                SampleCreateFiles = make_set(FileName, 10),
                CreateProcesses = make_set(InitiatingProcessFileName, 5),         // ADDED
                DistinctCreateProcesses = dcount(InitiatingProcessFileName),      // ADDED
                SampleFolders = make_set(FolderPath, 5),                         // ADDED
                ArchiveCount = countif(FileExt in (ArchiveExtensions)),
                ArchiveFiles = make_set_if(FileName, FileExt in (ArchiveExtensions))
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
                     SampleFolders, ArchiveCount, ArchiveFiles, DeviceName, InitiatingProcessAccountDomain)
      by DeviceId, InitiatingProcessAccountName, Bin
| project TimeGenerated = Bin, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName,
          ReadCount, LastRead, SampleReadFiles, ReadProcesses, DistinctReadProcesses,
          CreateCount, FirstCreate, LastCreate, SampleCreateFiles, CreateProcesses, DistinctCreateProcesses,
          SampleFolders, GapMinutes = AbsGapMinutes, ArchiveCount, ArchiveFiles
| order by TimeGenerated desc







let HuntResults = (
    // paste the entire Step 1 query here, everything from "let Lookback" down to the final "order by"
);
HuntResults
| summarize Occurrences = count(),
            Devices = dcount(DeviceId),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
      by InitiatingProcessAccountName
| order by Occurrences desc








let HuntResults = (
    // paste the entire Step 1 query here again
);
HuntResults
| where InitiatingProcessAccountName !in ("SYSTEM", "NETWORK SERVICE")  // add your noisy exclusions here
| mv-expand CreateProcesses to typeof(string)
| summarize Occurrences = count(),
            Accounts = dcount(InitiatingProcessAccountName),
            SampleFolders = make_set(SampleFolders, 5)
      by CreateProcesses
| order by Occurrences desc

