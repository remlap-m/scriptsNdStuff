DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType == "FileCreated"
| where not(FolderPath startswith @"\\")
| where isnotempty(InitiatingProcessAccountUpn)
| extend NameParts = split(FileName, ".")
| extend Ext = tolower(tostring(NameParts[array_length(NameParts) - 1]))
| where array_length(NameParts) > 1
| where Ext in (dynamic(["doc","docx","docm","dot","dotx","xls","xlsx",
    "xlsm","ppt","pptx","pdf","msg","eml","rtf","txt","csv","zip","7z","rar","pst","ost"]))
| summarize FilesCreated = count()
  by Actor = tolower(InitiatingProcessAccountUpn), DeviceId, bin(Timestamp, 20m)
| order by FilesCreated desc
| take 20
