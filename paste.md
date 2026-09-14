// ============================================================================
// HUNT: Sensitive file read followed by a suspicious rename
// (masking-for-exfiltration hypothesis — T1036.008 / T1074.001)
// ============================================================================

let lookback           = 7d;     // hunting window; shortened for the scheduled rule — see §5
let renameWindowMax    = 30m;    // max gap between read and rename to be considered related — TUNE
let renameBurstWindow  = 15m;    // window used to count renames/device — TUNE
let maxRenamesInBurst  = 5;      // above this: treat as mass-rename (ransomware-shaped), exclude — TUNE
let benignExtensions   = dynamic(["pdf","docx","xlsx","pptx","csv","txt","rtf","odt",
                                   "docm","xlsm","pptm","msg","eml","one","vsdx","doc","xls","ppt"]);
let stagingExtensions  = dynamic(["zip","rar","7z","gz","tar","iso","dat","bin","tmp",
                                   "enc","locked","z","cab","img"]);
let excludedProcesses  = dynamic(["backup.exe"]);   // PLACEHOLDER — populate before enabling. MUST TUNE.

// ---- sensitive reads (Purview / Endpoint DLP classification signal) ----
let SensitiveReads =
    DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "SensitiveFileRead"
    | project
        ReadTime             = Timestamp,
        DeviceId,
        DeviceName,
        AccountName,
        AccountSid,
        ReadFileName         = FileName,
        ReadFolderPath       = FolderPath,
        ReadSHA256           = SHA256,
        ReadAdditionalFields = AdditionalFields;

// ---- rename burst counts per device, to exclude ransomware-scale activity ----
let RenameCounts =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "FileRenamed"
    | extend BurstBin = bin(Timestamp, renameBurstWindow)
    | summarize RenamesInWindow = count() by DeviceId, BurstBin;

// ---- renames, enriched, filtered to low-volume + suspicious shape ----
let SuspiciousRenames =
    DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "FileRenamed"
    | where InitiatingProcessFileName !in~ (excludedProcesses)
    | extend BurstBin = bin(Timestamp, renameBurstWindow)
    | join kind=inner RenameCounts on DeviceId, BurstBin
    | where RenamesInWindow <= maxRenamesInBurst
    | extend FullPathOld = iff(PreviousFolderPath endswith PreviousFileName,
                                PreviousFolderPath, strcat(PreviousFolderPath, @"\", PreviousFileName))
    | extend FullPathNew = iff(FolderPath endswith FileName,
                                FolderPath, strcat(FolderPath, @"\", FileName))
    | extend OldParts = parse_path(FullPathOld)
    | extend NewParts = parse_path(FullPathNew)
    | extend OldExt  = tolower(tostring(OldParts.Extension))
    | extend NewExt  = tolower(tostring(NewParts.Extension))
    | extend OldDir  = tostring(OldParts.DirectoryPath)
    | extend NewDir  = tostring(NewParts.DirectoryPath)
    | extend NewBase = tostring(NewParts.Filename)
    | extend DirChanged   = OldDir != NewDir
    | extend LeftProfile  = NewDir !startswith strcat(@"C:\Users\", AccountName) and not(NewDir startswith @"C:\Users\")
    | extend ExtStripped  = isnotempty(OldExt) and isempty(NewExt)
    | extend ExtToStaging = NewExt in (stagingExtensions)
    | extend ExtToNonDoc  = isnotempty(NewExt) and NewExt !in (benignExtensions) and NewExt != OldExt
    | extend HexLikeName  = NewBase matches regex @"^[a-fA-F0-9]{12,}$"
    | extend LowVowelName = strlen(NewBase) >= 10 and NewBase !matches regex @"(?i)[aeiou]"
    | extend SuspicionScore = iff(ExtStripped,1,0) + iff(ExtToStaging,1,0) + iff(ExtToNonDoc,1,0)
                             + iff(HexLikeName,1,0) + iff(LowVowelName,1,0) + iff(DirChanged,1,0) + iff(LeftProfile,1,0)
    | where ExtStripped or ExtToStaging or ExtToNonDoc or HexLikeName or LowVowelName or DirChanged
    | project
        RenameTime = Timestamp, DeviceId, DeviceName, AccountName, AccountSid,
        PreviousFileName, PreviousFolderPath, FileName, FolderPath, SHA256,
        OldExt, NewExt, ExtStripped, ExtToStaging, ExtToNonDoc, HexLikeName, LowVowelName,
        DirChanged, LeftProfile, SuspicionScore, RenamesInWindow,
        InitiatingProcessFileName, InitiatingProcessCommandLine;

// ---- correlate: same device + account, rename shortly after read, same file identity ----
SensitiveReads
| join kind=inner (SuspiciousRenames) on DeviceId, AccountName
| where RenameTime between (ReadTime .. ReadTime + renameWindowMax)
| extend SHA256Match = isnotempty(ReadSHA256) and isnotempty(SHA256) and ReadSHA256 == SHA256
| extend PathMatch   = ReadFolderPath == PreviousFolderPath and ReadFileName == PreviousFileName
| where SHA256Match or PathMatch
| extend TimeToRename = RenameTime - ReadTime
| project
    ReadTime, RenameTime, TimeToRename,
    DeviceId, DeviceName, AccountName, AccountSid,
    ReadFolderPath, ReadFileName, ReadSHA256,
    PreviousFolderPath, PreviousFileName, FolderPath, FileName, SHA256,
    OldExt, NewExt, ExtStripped, ExtToStaging, ExtToNonDoc, HexLikeName, LowVowelName,
    DirChanged, LeftProfile, SuspicionScore, RenamesInWindow,
    SHA256Match, PathMatch,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by ReadTime desc
