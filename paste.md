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
| summarize arg_min(AbsGapMinutes, ReadCount, LastRead, SampleReadFiles, CreateCount, FirstCreate, LastCreate, SampleCreateFiles, ArchiveCount, ArchiveFiles, DeviceName, InitiatingProcessAccountDomain)
      by DeviceId, InitiatingProcessAccountName, Bin
| project TimeGenerated = Bin, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName,
          ReadCount, LastRead, SampleReadFiles,
          CreateCount, FirstCreate, LastCreate, SampleCreateFiles,
          GapMinutes = AbsGapMinutes, ArchiveCount, ArchiveFiles
| order by TimeGenerated desc
