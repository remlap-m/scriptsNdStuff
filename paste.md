DeviceFileEvents
| where TimeGenerated > ago(7d) and ActionType == "FileCreated"
| summarize Total = count(),
            EmptyAccount = countif(isempty(AccountName)),
            EmptyFileName = countif(isempty(FileName)),
            EmptyFolderPath = countif(isempty(FolderPath))




            let Lookback = 7d;
let ReadThreshold = 50;      // tune: reads per 30-min window to be "large"
let CreateThreshold = 20;    // tune: creates per 30-min window to be "large"
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
                SampleReadFiles = make_set(FileName, 10)
          by DeviceId, DeviceName, AccountName, AccountDomain, Bin
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
                ArchiveCount = countif(FileExt in (ArchiveExtensions)),
                ArchiveFiles = make_set_if(FileName, FileExt in (ArchiveExtensions))
          by DeviceId, AccountName, Bin
    | where CreateCount >= CreateThreshold;
//
Reads
| join kind=inner (Creates) on DeviceId, AccountName, $left.JoinBin == $right.Bin
| extend GapMinutes = datetime_diff('minute', FirstCreate, LastRead)
| where GapMinutes between (-5 .. WindowMinutes)   // small negative allowance for near-simultaneous activity
| summarize arg_min(abs(GapMinutes), ReadCount, LastRead, SampleReadFiles, CreateCount, FirstCreate, LastCreate, SampleCreateFiles, ArchiveCount, ArchiveFiles, DeviceName, AccountDomain)
      by DeviceId, AccountName, Bin
| project TimeGenerated = Bin, DeviceId, DeviceName, AccountDomain, AccountName,
          ReadCount, LastRead, SampleReadFiles,
          CreateCount, FirstCreate, LastCreate, SampleCreateFiles,
          GapMinutes = abs_GapMinutes, ArchiveCount, ArchiveFiles
| order by TimeGenerated desc
