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
                SampleCreateFolders = make_set(FolderPath, 10),                          // NEW — full picture
                DistinctCreateFolders = dcount(FolderPath),
                CreateProcesses = make_set(InitiatingProcessFileName, 5),
                DistinctCreateProcesses = dcount(InitiatingProcessFileName),
                ArchiveCount = countif(FileExt in (ArchiveExtensions)),
                ArchiveFiles = make_set_if(FileName, FileExt in (ArchiveExtensions)),
                ArchiveFolders = make_set_if(FolderPath, FileExt in (ArchiveExtensions)),
                NonArchiveFolders = make_set_if(FolderPath, FileExt !in (ArchiveExtensions))
          by DeviceId, InitiatingProcessAccountName, Bin
    | where CreateCount >= CreateThreshold;
