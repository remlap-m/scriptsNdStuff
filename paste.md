let ArchiveTools = dynamic(["7z.exe","7za.exe","7zr.exe","7zg.exe","rar.exe","winrar.exe"]);
DeviceProcessEvents
| where ingestion_time() > ago(15m)
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
| where not (InitiatingProcessAccountName =~ "svc-backupagent"
             and InitiatingProcessFileName =~ "7z.exe"
             and InitiatingProcessParentFileName =~ "backupscheduler.exe")
| extend PasswordMethod = case(
      HasHeaderEncSwitch or Has7zHeaderEnc, "HeaderEncrypted",
      "PasswordOnly")
| project Timestamp, ReportId, DeviceId, DeviceName,
          AccountName   = InitiatingProcessAccountName,
          AccountDomain = InitiatingProcessAccountDomain,
          AccountUpn    = InitiatingProcessAccountUpn,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName,
          IsInitiatingProcessRemoteSession,
          PasswordMethod, SplitVolume, NonStandardBinary,
          ProcessVersionInfoOriginalFileName
