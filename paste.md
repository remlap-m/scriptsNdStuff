let ArchiveTools = dynamic(["7z.exe","7za.exe","7zr.exe","7zg.exe","rar.exe","winrar.exe"]);
DeviceProcessEvents
| where FileName in~ (ArchiveTools)
    or ProcessVersionInfoOriginalFileName in~ (ArchiveTools)
| extend CmdLine = ProcessCommandLine
| extend HasPasswordSwitch  = CmdLine matches regex @"(?i)(?:^|\s)-p\S*"
       , HasHeaderEncSwitch = CmdLine matches regex @"(?i)(?:^|\s)-hp\S*"
       , Has7zHeaderEnc     = CmdLine matches regex @"(?i)(?:^|\s)-mhe(=on)?\b"
       , SplitVolume        = CmdLine matches regex @"(?i)(?:^|\s)-v\d"
       , NonStandardBinary  = FileName != tostring(ProcessVersionInfoOriginalFileName)
           and isnotempty(ProcessVersionInfoOriginalFileName)
| where HasPasswordSwitch or HasHeaderEncSwitch or Has7zHeaderEnc
| where not (InitiatingProcessAccountName =~ "<YOUR_EXCLUDED_ACCOUNT>"
             and InitiatingProcessFileName =~ "<YOUR_EXCLUDED_TOOL>"
             and InitiatingProcessParentFileName =~ "<YOUR_EXCLUDED_PARENT>")
| extend PasswordMethod  = case(HasHeaderEncSwitch or Has7zHeaderEnc, "HeaderEncrypted", "PasswordOnly")
| extend AlertSeverity   = case(PasswordMethod == "HeaderEncrypted", "High", "Medium")     // ← here
| project Timestamp, ReportId, DeviceId, DeviceName,
          AccountName   = InitiatingProcessAccountName,
          AccountDomain = InitiatingProcessAccountDomain,
          AccountUpn    = InitiatingProcessAccountUpn,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName,
          IsInitiatingProcessRemoteSession,
          PasswordMethod, SplitVolume, NonStandardBinary,
          ProcessVersionInfoOriginalFileName, AlertSeverity   // ← and here, in the output
