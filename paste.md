SensitiveReads
| join kind=inner (SuspiciousRenames) on DeviceId, AccountName
| extend ReadDeadline = ReadTime + renameWindowMax
| where RenameTime >= ReadTime and RenameTime <= ReadDeadline
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
