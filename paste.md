DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where isempty(SHA256)
| extend FileExt = tolower(tostring(split(FileName, ".")[-1]))
| summarize Count = count() by FileExt, InitiatingProcessFileName
| top 25 by Count desc
