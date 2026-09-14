DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("7z.exe","7za.exe","7zr.exe","7zg.exe","rar.exe","winrar.exe")
| extend HasPasswordSwitch = ProcessCommandLine matches regex @"(?i)(?:^|\s)-p\S*"
       , HasHeaderEnc      = ProcessCommandLine matches regex @"(?i)(?:^|\s)(-hp\S*|-mhe(=on)?)"
| summarize Invocations = count(), Devices = dcount(DeviceId), Users = dcount(AccountName)
    by Signal = case(HasHeaderEnc, "HeaderEncrypted", HasPasswordSwitch, "PasswordOnly", "None")
