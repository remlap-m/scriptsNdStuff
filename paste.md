DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where LogonType == "RemoteInteractive"
| summarize Count = count(), Devices = dcount(DeviceId) by AccountName
| order by Count desc


DeviceLogonEvents
| where TimeGenerated > ago(1d)
| where LogonType == "RemoteInteractive"
| take 20
| project TimeGenerated, DeviceName, AccountName, RemoteIP, ActionType, AdditionalFields


