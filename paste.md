let ArchiveTools = dynamic(["7z.exe","7za.exe","7zr.exe","7zg.exe","rar.exe","winrar.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (ArchiveTools) or ProcessVersionInfoOriginalFileName in~ (ArchiveTools)
| where ProcessCommandLine matches regex @"(?i)(?:^|\s)-p\S*"
    and not(ProcessCommandLine matches regex @"(?i)(?:^|\s)(-hp\S*|-mhe(=on)?)\b")
| summarize Invocations = count(),
            Devices     = dcount(DeviceId),
            SampleCmd   = any(ProcessCommandLine),
            Parents     = make_set(InitiatingProcessParentFileName, 5)
    by AccountName = InitiatingProcessAccountName, InitiatingProcessFileName
| order by Invocations desc
