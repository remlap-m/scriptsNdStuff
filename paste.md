let lookback           = 21d;
let renameWindowMax    = 30m;
let renameBurstWindow  = 15m;
let maxRenamesInBurst  = 5;
let benignExtensions   = dynamic(["pdf","docx","xlsx","pptx","csv","txt","rtf","odt",
                                   "docm","xlsm","pptm","msg","eml","one","vsdx","doc","xls","ppt"]);
let stagingExtensions  = dynamic(["zip","rar","7z","gz","tar","iso","dat","bin","tmp",
                                   "enc","locked","z","cab","img"]);
let excludedProcesses  = dynamic(["backup.exe"]);

let SensitiveReads =
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "SensitiveFileRead"
    | project ReadTime = Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
              ReadFileName = FileName, ReadFolderPath = FolderPath, ReadSHA256 = SHA256;

let AllRenames =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "FileRenamed"
    | extend AccountName = InitiatingProcessAccountName, AccountSid = InitiatingProcessAccountSid
    | project RenameTime = Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
              PreviousFileName, PreviousFolderPath, FileName, FolderPath, SHA256,
              InitiatingProcessFileName;

let Stage0  = SensitiveReads | summarize Stage = "0_TotalSensitiveReads", Count = count();
let Stage0b = AllRenames     | summarize Stage = "0b_TotalFileRenamed", Count = count();

let TimeWindowJoin =
    SensitiveReads
    | join kind=inner AllRenames on DeviceId, AccountName
    | extend ReadDeadline = ReadTime + renameWindowMax
    | where RenameTime >= ReadTime and RenameTime <= ReadDeadline;
let Stage1 = TimeWindowJoin | summarize Stage = "1_SameDeviceAccountWithinWindow", Count = count();

let IdentityConfirmed =
    TimeWindowJoin
    | extend SHA256Match = isnotempty(ReadSHA256) and isnotempty(SHA256) and ReadSHA256 == SHA256
    | extend PathMatch   = ReadFolderPath == PreviousFolderPath and ReadFileName == PreviousFileName
    | where SHA256Match or PathMatch;
let Stage2 = IdentityConfirmed | summarize Stage = "2_SameFileIdentityConfirmed", Count = count();

let RenameCounts =
    AllRenames
    | extend BurstBin = bin(RenameTime, renameBurstWindow)
    | summarize RenamesInWindow = count() by DeviceId, BurstBin;
let BurstOk =
    IdentityConfirmed
    | extend BurstBin = bin(RenameTime, renameBurstWindow)
    | join kind=inner RenameCounts on DeviceId, BurstBin
    | where RenamesInWindow <= maxRenamesInBurst;
let Stage3 = BurstOk | summarize Stage = "3_PassesBurstCap", Count = count();

let ProcessOk = BurstOk | where InitiatingProcessFileName !in~ (excludedProcesses);
let Stage4 = ProcessOk | summarize Stage = "4_ProcessNotExcluded", Count = count();

let SuspiciousShape =
    ProcessOk
    | extend FullPathOld = iff(PreviousFolderPath endswith PreviousFileName, PreviousFolderPath, strcat(PreviousFolderPath, @"\", PreviousFileName))
    | extend FullPathNew = iff(FolderPath endswith FileName, FolderPath, strcat(FolderPath, @"\", FileName))
    | extend OldParts = parse_path(FullPathOld)
    | extend NewParts = parse_path(FullPathNew)
    | extend OldExt  = tolower(tostring(OldParts.Extension))
    | extend NewExt  = tolower(tostring(NewParts.Extension))
    | extend OldDir  = tostring(OldParts.DirectoryPath)
    | extend NewDir  = tostring(NewParts.DirectoryPath)
    | extend NewBase = tostring(NewParts.Filename)
    | extend DirChanged   = OldDir != NewDir
    | extend LeftProfile  = not(NewDir startswith @"C:\Users\")
    | extend ExtStripped  = isnotempty(OldExt) and isempty(NewExt)
    | extend ExtToStaging = NewExt in (stagingExtensions)
    | extend ExtToNonDoc  = isnotempty(NewExt) and NewExt !in (benignExtensions) and NewExt != OldExt
    | extend HexLikeName  = NewBase matches regex @"^[a-fA-F0-9]{12,}$"
    | extend LowVowelName = strlen(NewBase) >= 10 and not(NewBase matches regex @"(?i)[aeiou]")
    | where ExtStripped or ExtToStaging or ExtToNonDoc or HexLikeName or LowVowelName or DirChanged;
let Stage5 = SuspiciousShape | summarize Stage = "5_SuspiciousShape_FINAL", Count = count();

union Stage0, Stage0b, Stage1, Stage2, Stage3, Stage4, Stage5
| order by Stage asc
