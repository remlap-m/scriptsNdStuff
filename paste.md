DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Sensitive"
| summarize count() by ActionType

DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileRenamed"
| summarize HasHash = countif(isnotempty(SHA256)), Total = count()
