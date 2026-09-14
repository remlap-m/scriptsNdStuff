// Run against your existing hunt result set (materialize it first, or re-run as one pipeline)
YourHuntResults
| summarize Occurrences = count(),
            Devices = dcount(DeviceId),
            Accounts = dcount(InitiatingProcessAccountName),
            SampleFolders = make_set(FolderPath, 5)  // if you added FolderPath — see below
      by InitiatingProcessFileName
| order by Occurrences desc

let Reads =
    DeviceEvents
    | where TimeGenerated > ago(Lookback)
    | where ActionType == "SensitiveFileRead"
    | extend Bin = bin(TimeGenerated, 30m)
    | summarize ReadCount = count(),
                FirstRead = min(TimeGenerated),
                LastRead = max(TimeGenerated),
                SampleReadFiles = make_set(FileName, 10),
                ReadProcesses = make_set(InitiatingProcessFileName, 5)
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
                CreateProcesses = make_set(InitiatingProcessFileName, 5),
                SampleFolders = make_set(FolderPath, 5),
                ArchiveCount = countif(FileExt in (ArchiveExtensions)),
                ArchiveFiles = make_set_if(FileName, FileExt in (ArchiveExtensions))
          by DeviceId, InitiatingProcessAccountName, Bin
    | where CreateCount >= CreateThreshold;
