// paste this against your hunt result set, or re-run as a summarize on top of it
YourHuntResults
| summarize Occurrences = count(), 
            Devices = dcount(DeviceId), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated)
      by InitiatingProcessAccountName
| order by Occurrences desc
