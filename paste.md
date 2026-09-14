union isfuzzy=true
  (DeviceEvents | where ActionType == "SensitiveFileRead" | take 5 | extend TableName = "DeviceEvents"),
  (DeviceFileEvents | where ActionType == "FileCreated" | take 5 | extend TableName = "DeviceFileEvents")
| project TableName,
    AccountName = column_ifexists("AccountName", ""),
    AccountSid = column_ifexists("AccountSid", ""),
    InitiatingProcessAccountName = column_ifexists("InitiatingProcessAccountName", ""),
    InitiatingProcessAccountSid = column_ifexists("InitiatingProcessAccountSid", "")
