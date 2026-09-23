# HQ-MassDocCreationAnomalousProcess

**Status:** Deployed — tuning in progress
**Platform:** Microsoft Sentinel (scheduled analytics rule)
**Data source:** `DeviceFileEvents` (MDE, via Defender XDR data connector)
**Owner:** _[fill in]_
**Created:** _[fill in]_
**Last reviewed:** _[fill in]_
**Version:** 1.1 — see change log

---

## 1. What this detects

Bulk creation of document-type files by copy, scripting or admin utilities running under an interactive user account, on devices outside the IT/server estate.

Creation of an archive shortly after the burst is surfaced as a staging escalator. Bursts *preceded* by an archive, or initiated by a command line containing an extraction verb, are suppressed as likely unpacking.

**Hypothesis:** an adversary collecting data prior to exfiltration will copy documents into a staging location using an available copy or scripting utility, and will frequently compress the result before transfer. The copy-then-archive sequence is a structural requirement of that workflow and is rare in normal user activity.

**MITRE ATT&CK**
| | |
|---|---|
| Tactic | Collection (TA0009) |
| Technique | T1074.001 — Local Data Staging |
| Technique | T1560.001 — Archive via Utility *(where a following archive is present)* |

Exfiltration (TA0010) is deliberately **not** mapped. Nothing in this rule observes egress, and the mapping should reflect what the query evidences.

---

## 2. Design rationale

Recorded because the reasoning is not obvious from the query, and because several intuitive alternatives were considered and rejected.

### Why the chain, not just volume

Bulk file creation alone is far too noisy — routine archive extraction alone generates dozens of events per day in a normal estate. Neither bulk creation nor archive creation is convincing in isolation. The ordered pair, on one device under one account within a short window, is what carries the signal.

### Why order is used to suppress rather than to fire

An archive *before* a burst indicates extraction. An archive *after* indicates staging. The same two components appear in both the benign and malicious case; only the direction differs.

This means the archive is not a mandatory firing condition. Requiring it would produce good precision and poor recall — collection is not always followed by local compression (direct cloud upload, staging to a mapped share, exfil in place all skip it). Instead:

- Archive **before** → suppress
- Archive **after** → escalator, raises confidence
- No archive → alert stands on process, volume and destination class

### Why the process list is a noise filter, not a detection boundary

The process list is trivially evaded by renaming, recompiling or substituting a tool. It is retained because it is an effective *noise* filter, not because it is evasion-resistant. Original-filename checking (`InitiatingProcessVersionInfoOriginalFileName`) raises the bar against simple renaming of in-box binaries, but nothing here detects an unlisted or custom copy utility.

This distinction must be preserved in any future review. The list is not the detection.

### Approaches considered and rejected

| Approach | Rejected because |
|---|---|
| Per-user process baseline (first-seen) | Cold-start on new starters, breaks on reimage/role change/VDI, poisonable over a two-week dwell, cannot exceed the 14-day query lookup cap without a precomputed table. Does not suppress the actual FP sources, which are device- and account-class driven. |
| Confidence tiering (multiple rules at different thresholds) | Tier boundaries were invented rather than derived. Replaced by a single rule with corroborated suppression. |
| Numeric severity scoring in-query | Severity is a claim about false positive rate, which cannot be known before the rule runs. Deferred to post-baseline. |
| Pre-aggregation `ingestion_time()` dedupe | Filters raw rows before counting them, so a batched burst is counted in fragments and fails the threshold on every run. Silent miss. See §6. |
| Alert grouping as the *sole* dedupe mechanism | Tried in v1.0 and failed in production — 8 identical alerts per burst. See §6. |
| Distinct-folder count as a filter | Direction is ambiguous — staging into one directory produces a low count; `robocopy /E` preserving tree structure produces a high one. Retained as a triage column only. |

---

## 3. Telemetry findings — read before modifying this rule

These were measured locally in this tenant and directly shape the design. None of this behaviour is documented by Microsoft, and it may change with sensor version.

### Sampling / emission ceiling

| Test | Files written | Events initially returned |
|---|---|---|
| 1 | 300 | complete |
| 2 | 600 | complete |
| 3 | 3,000 | fewer than 100 |

The reliability boundary sits somewhere between 600 and 3,000. The pattern is more consistent with a **ceiling** than with proportional sampling.

**Consequence:** any file-count threshold above that ceiling will never fire, regardless of how much data is actually moved. This is a silent failure mode. `MinFileCount` is therefore set deliberately low, and count is treated as evidence that a burst occurred rather than as a measure of its size.

**This affects other rules.** Any detection with a file-count threshold — mass encryption, wiper, destruction, DLP-adjacent — is exposed to the same ceiling. Existing thresholds should be reviewed against this finding.

### Timestamp misassignment

In test 3, the bulk of events arrived **over an hour late**, and `Timestamp`, `TimeGenerated` and `ingestion_time()` were all shifted together — none of the three accounted for the delay.

Three consequences:

1. **Detection latency is structural**, roughly two hours. Not fixable by increasing rule frequency.
2. **Event ordering cannot be fully trusted at high volume.** If file creates are batch-timestamped and shifted forward while a single archive event is not, a genuine staging sequence can be recorded as an extraction pattern and suppressed. This is why the order-based suppression has a volume ceiling above which it does not apply.
3. **Analyst timelines will be misleading.** Surfaced via the `MaxLagMin` custom detail.

### Production observation (v1.0, first fires)

Eight alerts generated for a single burst, grouped into one incident, with **identical `FileCount` across all eight**.

Identical counts mean no new rows arrived after the first alert — the burst settled quickly and was then re-emitted on each subsequent execution for no informational gain. This contradicts the long-tail ingestion pattern that had been assumed when the dedupe gate was originally rejected, and prompted the v1.1 change.

### Open with Microsoft

_[Record ticket reference and status here.]_

The sampling behaviour will likely be confirmed as by design. The **timestamp misassignment is the defect worth pursuing** — if `Timestamp` reflects batch processing rather than event occurrence, that affects every timeline and every correlation in the tenant, not just this rule. Lead with that; keep sampling as context.

Re-validate all of the above after any MDE sensor version change.

---

## 4. Query

```kql
//==========================================================================
// HQ-MassDocCreationAnomalousProcess
// Sentinel scheduled analytics rule
//
// REQUIRED RULE CONFIG - the in-query logic depends on it:
//   Run query every : 1 hour        <-- if you change this, update Liveness below
//   Lookup period   : 8 hours       -- must exceed BurstWindow + ArchiveFollowWindow + skew
//   Event grouping  : trigger an alert for each event (1 row = 1 burst)
//   Alert grouping  : ON, Host + Account, 8 hours   <-- backstop, not primary dedupe
//==========================================================================
let BurstWindow         = 1h;      // UNMEASURED - set from observed Timestamp spread
let MinFileCount        = 40;      // UNMEASURED - set from baseline distribution run
let ArchivePriorWindow  = 30m;     // UNVALIDATED PLACEHOLDER
let ArchiveFollowWindow = 2h;      // UNVALIDATED PLACEHOLDER
let OrderTrustCeiling   = 500;     // DERIVED - local testing: 600 clean, 3000 reordered
// Dedupe gate. Constraints, all three of which fail silently if broken:
//   1. MUST be < the lookup period, or the filter is inert.
//   2. MUST be >= frequency + jitter, or a burst landing just after a run is
//      never reported. A miss is worse than a duplicate.
//   3. MUST be updated by hand if the wizard frequency changes.
// 2h15m tolerates one missed/delayed execution at the cost of at most two
// alerts per burst. Tight setting for 1h frequency would be 1h15m.
let Liveness            = 2h15m;
//
let DocExtensions = dynamic(["docx","doc","docm","xlsx","xls","xlsm","xlsb","pptx","ppt","pptm",
                             "pdf","csv","rtf","odt","ods","odp","msg","eml","pst","ost","one",
                             "vsdx","vsd","accdb","mdb"]);
let ArchiveExtensions = dynamic(["zip","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","wim",
                                 "arj","lzh","ace","001","z01","r00","r01"]);
let SuspectProcesses = dynamic(["robocopy.exe","xcopy.exe","powershell.exe","pwsh.exe","cmd.exe",
                                "wscript.exe","cscript.exe","mshta.exe","rundll32.exe","certutil.exe",
                                "bitsadmin.exe","esentutl.exe","forfiles.exe","curl.exe","wget.exe",
                                "wmic.exe","ftp.exe","python.exe"]);
let ExcludedAccounts = dynamic(["system","local service","network service","localsystem","-"]);
let ServiceAcctRegex    = @"^(svc|sa|adm|_)[-_.]";        // PLACEHOLDER
let ExcludedDeviceRegex = @"^(srv|bld|vdi|sccm|mgmt)-";   // PLACEHOLDER - prefer device-group join
let ExtractionVerbs = @"(?i)(expand-archive|7z[a]?\s+[xe]\b|\brar\s+[xe]\b|\bunzip\b|tar\s+[^|]*-?x|extractto|\bexpand\s+-)";
//
let ScopedCreates =
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where isnotempty(InitiatingProcessFileName)
    | extend FileExt = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, FileName))
    | where FileExt in (DocExtensions)
    | extend InitProc = tolower(InitiatingProcessFileName)
    // [VERSIONINFO] delete next 2 lines if the field is absent in this tenant
    | extend InitProcOriginal = tolower(tostring(InitiatingProcessVersionInfoOriginalFileName))
    | extend NameMismatch = isnotempty(InitProcOriginal) and InitProcOriginal != InitProc
    | where InitProc in (SuspectProcesses) or InitProcOriginal in (SuspectProcesses)
    | extend Acct       = tolower(InitiatingProcessAccountName),
             AcctDomain = tostring(InitiatingProcessAccountDomain),
             AcctUpn    = tostring(InitiatingProcessAccountUpn)
    | where Acct !in (ExcludedAccounts)
    | where Acct !endswith "$"
    | where not(Acct matches regex ServiceAcctRegex)
    | where not(tolower(DeviceName) matches regex ExcludedDeviceRegex)
    | extend IsExtractionCmd = tostring(InitiatingProcessCommandLine) matches regex ExtractionVerbs
    | extend IngestAt = ingestion_time();
//
// NOTE: aggregation runs over the FULL lookup period. The dedupe gate is applied
// after this, never before it - filtering raw rows by ingestion time would count
// a batched burst in fragments and fail the threshold on every run.
let Bursts =
    ScopedCreates
    | summarize
        FileCount          = count(),
        DistinctFolders    = dcount(FolderPath),
        DistinctExts       = dcount(FileExt),
        ExtractionCmdCount = countif(IsExtractionCmd),
        MismatchCount      = countif(NameMismatch),          // [VERSIONINFO]
        OriginalNames      = make_set(InitProcOriginal, 3),  // [VERSIONINFO]
        NetworkWrites      = countif(FolderPath startswith "\\\\"),
        TempWrites         = countif(FolderPath has @"\AppData\Local\Temp" or FolderPath has @"\Windows\Temp"),
        AppDataWrites      = countif(FolderPath has @"\AppData\"),
        PublicWrites       = countif(FolderPath has @"\Users\Public\" or FolderPath has @"\ProgramData\"),
        FirstCreate        = min(Timestamp),
        LastCreate         = max(Timestamp),
        FirstIngest        = min(IngestAt),
        LastIngest         = max(IngestAt),
        LastRowTG          = max(TimeGenerated),
        AcctDomain         = any(AcctDomain),
        AcctUpn            = any(AcctUpn),
        SampleFolders      = make_set(FolderPath, 8),
        SampleFiles        = make_set(FileName, 8),
        CmdSample          = make_set(substring(tostring(InitiatingProcessCommandLine), 0, 250), 3),
        ProcPaths          = make_set(InitiatingProcessFolderPath, 3)
      by DeviceId, DeviceName, Acct, InitProc, BurstStart = bin(Timestamp, BurstWindow)
    | where FileCount >= MinFileCount
    | extend BurstSpanSec    = datetime_diff('second', LastCreate, FirstCreate)
    | extend IngestSpreadSec = datetime_diff('second', LastIngest, FirstIngest)
    | extend MaxLagMin       = datetime_diff('minute', LastIngest, FirstCreate)
    | extend FilesPerMin     = iff(BurstSpanSec <= 0, todouble(FileCount),
                                   round(FileCount / (BurstSpanSec / 60.0), 1))
    | extend BurstQ1Time     = FirstCreate + (LastCreate - FirstCreate) * 0.25
    | extend BurstKey        = strcat(DeviceId, "|", Acct, "|", InitProc, "|", format_datetime(BurstStart, "yyyyMMddHHmm"));
//
let ArchiveEvents =
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | extend ArchExt = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, FileName))
    | where ArchExt in (ArchiveExtensions)
    | project ArchiveTime = Timestamp, DeviceId,
              ArchAcct    = tolower(InitiatingProcessAccountName),
              ArchiveFull = strcat(FolderPath, "\\", FileName),
              ArchiveProc = tolower(InitiatingProcessFileName);
//
let BurstArchive =
    Bursts
    | project BurstKey, DeviceId, Acct, FirstCreate, LastCreate, BurstQ1Time
    | join kind=leftouter ArchiveEvents on DeviceId, $left.Acct == $right.ArchAcct
    | extend RelPos = case(
          isnull(ArchiveTime), "none",
          ArchiveTime between ((FirstCreate - ArchivePriorWindow) .. FirstCreate), "prior",
          ArchiveTime between (BurstQ1Time .. (LastCreate + ArchiveFollowWindow)), "following",
          "outofwindow")
    | summarize
        ArchivePriorCount  = countif(RelPos == "prior"),
        ArchiveFollowCount = countif(RelPos == "following"),
        PriorArchives      = make_set_if(ArchiveFull, RelPos == "prior", 5),
        FollowingArchives  = make_set_if(ArchiveFull, RelPos == "following", 5),
        FollowingArchProcs = make_set_if(ArchiveProc, RelPos == "following", 5)
      by BurstKey;
//
Bursts
| join kind=leftouter BurstArchive on BurstKey
| extend ArchivePriorCount  = coalesce(ArchivePriorCount, 0),
         ArchiveFollowCount = coalesce(ArchiveFollowCount, 0)
// --- Suppression: likely archive extraction ---
// Command-line verb is timestamp-independent, so suppress unconditionally.
| where ExtractionCmdCount == 0
// Preceding archive is order-based, so only trusted below the volume at which
// local testing showed event ordering becomes unreliable (600 clean / 3000 reordered).
| where ArchivePriorCount == 0 or FileCount >= OrderTrustCeiling
// --- Dedupe gate ---
// Report a burst only on the run during which new rows arrived for it. The burst
// stays in scope on later runs, but with nothing new landed it stays silent.
| where LastIngest > ago(Liveness)
// --- Flatten dynamics for custom details / entity fields ---
| extend FollowingArchivesStr = tostring(strcat_array(FollowingArchives, "; ")),
         PriorArchivesStr     = tostring(strcat_array(PriorArchives, "; ")),
         SampleFoldersStr     = tostring(strcat_array(SampleFolders, "; ")),
         SampleFilesStr       = tostring(strcat_array(SampleFiles, "; ")),
         CmdSampleStr         = tostring(strcat_array(CmdSample, " || ")),
         ProcPathsStr         = tostring(strcat_array(ProcPaths, "; ")),
         OriginalNamesStr     = tostring(strcat_array(OriginalNames, "; "))
// Sentinel needs TimeGenerated on a summarised result for alert timestamping.
// Uses max(TimeGenerated) of contributing rows, NOT Timestamp - Timestamp is skewed
// and could fall outside the lookup period.
| extend TimeGenerated = LastRowTG
| project TimeGenerated, BurstStart, DeviceName, DeviceId, Acct, AcctDomain, AcctUpn, InitProc,
          FileCount, FilesPerMin, BurstSpanSec, DistinctFolders, DistinctExts,
          MismatchCount, OriginalNamesStr,
          NetworkWrites, TempWrites, AppDataWrites, PublicWrites,
          ArchiveFollowCount, FollowingArchivesStr, ArchivePriorCount, PriorArchivesStr,
          FirstCreate, LastCreate, FirstIngest, LastIngest, IngestSpreadSec, MaxLagMin,
          SampleFoldersStr, SampleFilesStr, CmdSampleStr, ProcPathsStr, BurstKey
```

### Block-by-block

| Block | Purpose |
|---|---|
| `ScopedCreates` | Scopes to document-class creates by a listed (or renamed-listed) process under an interactive account on a non-excluded device. Filtering happens here rather than post-aggregation so the summarize operates on a much smaller set. `IngestAt` is captured per row for the later dedupe gate. |
| `Bursts` | Bucketed aggregation by device/account/process/time bin over the **full** lookup period. Only `FileCount` gates. `BurstQ1Time` is the quarter-point of the burst, used as the "following" reference instead of `LastCreate` so late-arriving stragglers cannot push a genuine staging archive out of window. |
| `ArchiveEvents` | All archive creates in period, unscoped by process or account exclusions — an archive written by anything is relevant context. |
| `BurstArchive` | Joins archives to bursts on device + account, classifies each as prior / following / out of window, re-aggregates by `BurstKey`. Split out to avoid carrying every burst column through a `by` clause after the join. |
| Final block | Suppression, dedupe gate, dynamic flattening, `TimeGenerated` reinstatement, projection. |

### Dedupe gate placement

The gate sits **after** the join and the suppression filters, operating on `LastIngest` produced by the summarize. It cannot move:

- **Not in `ScopedCreates`** — that would filter raw rows before counting them, so a batched burst gets counted in slices and fails the threshold on every run. Silent miss.
- **Not inside the `Bursts` summarize** — `LastIngest` does not exist until the summarize completes.
- **After suppression rather than before**, purely for cost: no point evaluating liveness on rows about to be discarded.

---

## 5. Parameters

| Parameter | Value | Status | Sensitive to |
|---|---|---|---|
| `BurstWindow` | `1h` | **UNMEASURED** | Timestamp batch spread. Set from the observed `Timestamp` spread across rows from a single large copy. Too narrow fragments a real burst into sub-threshold pieces (silent miss); too wide dilutes `FilesPerMin` and aggregates unrelated activity (visible at triage). Erred wide because the first failure is silent. |
| `MinFileCount` | `40` | **UNMEASURED** | Baseline distribution. Set from the 7-day run at p99+ of the per-burst distribution. Kept low deliberately because of the emission ceiling. |
| `ArchivePriorWindow` | `30m` | Placeholder | How long before a burst an archive still plausibly explains it. |
| `ArchiveFollowWindow` | `2h` | Placeholder | Operator tempo. Hands-on-keyboard staging is minutes; slower operations may be hours. Wider costs precision, narrower costs recall. Must stay within `Liveness` — see §9. |
| `OrderTrustCeiling` | `500` | **Derived** | Local testing (600 clean, 3,000 reordered). Re-validate after sensor updates. |
| `Liveness` | `2h15m` | **Coupled to wizard frequency** | Rule frequency + jitter. Three hard constraints, all silent on failure — see below. |
| `ServiceAcctRegex` | placeholder | **Unresolved** | Local naming convention. |
| `ExcludedDeviceRegex` | placeholder | **Unresolved** | Prefer a device-group or tag join over a regex. |

### Liveness constraints

1. **`Liveness` < lookup period.** Otherwise every row passing the platform's `TimeGenerated` filter automatically passes the liveness filter and the gate is inert. *(This is the trap `HQ-MassFCStagingKQL` originally fell into: 30m lookback, 60m liveness.)*
2. **`Liveness` ≥ frequency + jitter.** Otherwise a burst landing shortly after an execution is stale by the next one and is never reported. A miss is worse than a duplicate.
3. **`Liveness` must be updated by hand if the wizard frequency changes.** This coupling is invisible from the portal. The comment block in the query is the only protection.

At 1h frequency the tight setting is `1h15m` and the robust setting is `2h15m`. The robust setting tolerates one missed or delayed execution at the cost of at most two alerts per burst. Currently set to the robust value.

---

## 6. Rule configuration

### Scheduling

| Setting | Value | Basis |
|---|---|---|
| Run query every | 1 hour | Detection latency floor is set by ~90m skew, not cadence. If changed, **update `Liveness`**. |
| Lookup period | 8 hours | `BurstWindow` (1h) + `ArchiveFollowWindow` (2h) + skew (~1.5h) + headroom. Must exceed all in-query windows or archive correlation silently truncates. |

**Overlap behaviour.** Lookback exceeds frequency by 8x, deliberately, so a burst straddling an execution boundary or arriving late is still fully visible. Each burst is therefore *evaluated* up to eight times but *reported* once, because of the liveness gate.

### Deduplication — how it works and why it is built this way

**Primary mechanism: post-aggregation liveness gate.**

The aggregation runs over the full lookup period, so every row of a burst is counted regardless of which ingestion batch it arrived in. The threshold always sees the complete picture. The gate then asks, after the fact: *did anything new land for this burst since the last run?*

| Run | Burst in window? | `LastIngest` age | Alert? |
|---|---|---|---|
| 10:00 | yes | 12m | **yes** |
| 11:00 | yes | 72m | no |
| 12:00 | yes | 132m | no |

Report on first sight, then stay quiet.

**Secondary mechanism: alert grouping** (Host + Account, 8h). Now a backstop for residual cases — a genuinely long-tailed burst that keeps refreshing `LastIngest`, or a second distinct burst on the same host and account — rather than the primary control.

**Why not pre-aggregation `ingestion_time()`.** Filtering raw rows by ingestion time before the summarize counts a batched burst in fragments: run 1 sees 50 rows, run 2 sees 200, none reaching threshold, and the burst is never reported. Given the sensor batching documented in §3, this rule is directly exposed to that failure. It is a silent miss and is strictly worse than a duplicate.

**Why alert grouping alone was insufficient (v1.0 → v1.1).** The original design used grouping as the sole dedupe layer, on the reasoning that the liveness gate leaks on long-tail bursts and makes a failed execution unrecoverable. In production this produced **8 identical alerts per burst** — identical `FileCount`, confirming the burst had settled and the re-emissions carried no new information. The long-tail leak the gate was rejected over did not occur. The gate was added in v1.1.

**Residual cases.** Not a guarantee:
- A burst with a genuinely long ingestion tail keeps refreshing `LastIngest` and can re-alert. Grouping absorbs it.
- A failed or delayed execution beyond the liveness window means the burst is never reported. This is the real cost of the gate; the `2h15m` buffer is sized to tolerate one missed run.

### Alerting

| Setting | Value | Note |
|---|---|---|
| Alert threshold | Results > 0 | Volume logic lives in `MinFileCount`, don't duplicate. |
| Event grouping | Trigger an alert for each event | 1 row = 1 burst. Note the 150-alert-per-execution cap — hitting it means `MinFileCount` is too low, and it fails silently. |
| Suppression | **Off** | Stops the whole rule; a second account staging during the window would be missed entirely. |
| Alert grouping | **On** — Host + Account, 8 hours | Backstop. Window must match the lookup period, or residual re-evaluations at the far edge split into a second incident. |
| Reopen closed incidents | Off | |
| Create incidents | On | |

### Severity

**Unresolved.** Set from the baseline run. Severity is a claim about false positive rate and that number is not yet known. Starting High on an unvalidated rule trains analysts to ignore it.

Once the data exists, the likely candidate for a High promotion via alert details override is `ArchiveFollowCount > 0`. Any severity column must contain only `Informational` / `Low` / `Medium` / `High`.

### Entity mapping

| Entity | Identifier | Column |
|---|---|---|
| Host | HostName | `DeviceName` |
| Host | AzureID | `DeviceId` |
| Account | Name | `Acct` |
| Account | NTDomain | `AcctDomain` |
| Account | UPNSuffix | `AcctUpn` |
| Process | ProcessId | `InitProc` |

Account and Host drive investigation graph and UEBA correlation. The Process entity is awkward — it maps a process *name* to a schema expecting a PID or command line; if it maps badly, drop it and keep the process in custom details. `DeviceId` as AzureID assumes MDE device IDs resolve in the workspace — verify.

### Custom details

`FileCount`, `FilesPerMin`, `DistinctFolders`, `ArchiveFollowCount`, `FollowingArchivesStr`, `ArchivePriorCount`, `MismatchCount`, `OriginalNamesStr`, `MaxLagMin`, `CmdSampleStr`, `SampleFoldersStr`

`MaxLagMin` and `ArchivePriorCount` matter most — see triage.

### Automation

**None initially.** No playbooks until the FP rate is known. When added, the sensible first automation is enrichment (device and user context, recent sign-in activity) rather than containment. Given the ~90 minute skew, any isolation or account-disable action is responding to something that happened two hours ago, which materially changes the value calculation.

---

## 7. Analyst triage

```
TRIAGE - HQ-MassDocCreationAnomalousProcess

First: check MaxLagMin. If it is large, the times shown in the incident are not when
this happened. Correlate against sign-in and process telemetry using the user's actual
working pattern, not the alert timestamp.

Second: check ArchivePriorCount. If greater than zero, an archive was created before
this burst - normally indicative of extraction. This alert fired anyway because the
file count exceeded the volume at which local testing showed event ordering becomes
unreliable. Treat the ordering as unknown rather than as evidence of extraction, and
check PriorArchivesStr to see whether the archive plausibly accounts for the files
created.

Third: check ArchiveFollowCount and FollowingArchivesStr. A following archive is the
strongest single indicator here - collection followed by staging. Escalate.

Then assess:
- Is the destination consistent with staging? NetworkWrites, TempWrites, AppDataWrites
  and PublicWrites give the breakdown. Writes into an established Documents tree are
  weaker than writes into temp, ProgramData or a network path.
- Does CmdSampleStr show a plausible business purpose? Batch export, mail merge,
  reporting and migration scripts are the most common true-benign causes.
- Does MismatchCount indicate a renamed binary? OriginalNamesStr shows the compiled-in
  filename. Common and usually benign for installers and vendor tools, but a renamed
  robocopy or a copy utility running from a user-writable path is not.
- Is the account or device a known exception that should be excluded at rule level?

Remember FileCount may be a fraction of reality. A 60-file alert is not necessarily a
small event.

If you see more than one alert for the same BurstKey, the dedupe gate has leaked -
raise it with the rule owner rather than just closing the duplicates. It usually means
either a long ingestion tail or a Liveness value out of step with the rule frequency.
```

---

## 8. Expected false positives

Ranked by likely volume.

| Source | Notes |
|---|---|
| Sync and backup clients | OneDrive first sync, restores, FSLogix/profile container hydration. Mostly attributed to the sync binary and out of scope, but restores under a user account can surface. |
| Batch export and reporting | PowerShell generating CSVs, mail merge, PST exports, eDiscovery collections, finance month-end. The nastiest category: user-initiated, document-typed, legitimately scripted. |
| Profile and share migration | USMT, robocopy in logon scripts, file server consolidation. Better handled as scheduled-window exclusions than blanket process exclusions. |
| Deployment tooling | Anything that slipped the device and account filters. |
| Archive extraction without captured command line | Suppression falls back to the preceding-archive path, which misses extraction of archives already on disk or opened from a share. |

**Tuning order.** Run the noise profile first:

```kql
| summarize Bursts = count(), TotalFiles = sum(FileCount) by InitProc, DeviceName
| sort by Bursts desc
```

If one process or a handful of devices dominates, that is a scoping gap to fix in `ScopedCreates`, not a threshold to raise.

---

## 9. Known blind spots

Mandatory reading before anyone claims coverage from this rule.

- **No visibility of the copy source.** `DeviceFileEvents` records files written, not read. A robocopy pulling from twenty user profiles and one pulling from a single folder are indistinguishable here.
- **Split, renamed or extensionless archives** (`.7z.001`, `.part1.rar`) are not detected by extension matching.
- **In-memory or streamed compression** never touches disk as a recognisable archive.
- **The process list is a noise filter.** A recompiled or unlisted copy utility is not detected. Original-filename checking mitigates simple renaming of in-box binaries only, and fails against stripped or forged version resources.
- **Archiver binaries are out of scope entirely** — they are not in `SuspectProcesses`, so an attacker using 7-Zip or WinRAR to *copy* files never enters the pipeline.
- **Command-line suppression is attacker-influenceable.** Padding a command line with an extraction verb would suppress the alert. Accepted as a noise-filter trade-off, but it is real attack surface.
- **The liveness gate narrows the archive escalator.** *(New in v1.1.)* The gate applies to the burst, not the archive. If a staging archive lands after the burst has gone quiet beyond `Liveness`, the escalator will not retrospectively raise an alert, because the burst itself is stale. At `ArchiveFollowWindow = 2h` and `Liveness = 2h15m` this only bites at the edge, but **`ArchiveFollowWindow` must stay comfortably inside `Liveness`** or the escalator degrades. Widening the follow window requires widening liveness too.
- **A failed or delayed rule execution is unrecoverable.** *(New in v1.1.)* Bursts that would have been new during a missed run are stale by the next one. Rule health monitoring matters more now than it did in v1.0.
- **Bin boundary straddle.** A burst spanning a `bin()` boundary splits into two, each potentially sub-threshold. Inherent to bucketed aggregation. `row_window_session()` sessionises properly but requires serialisation and is expensive at this table's volume.
- **Leading-edge suppression weakness.** A burst near the start of the lookup period cannot see archives that preceded it, so extraction suppression is weaker there.
- **`FileCount` understates volume.** See §3.

### Coverage quality (DeTT&CT framing)

`DeviceFileEvents` is present and streaming, but presence is not usable coverage. For this technique the data source quality is **degraded**: volume is sampled at the sensor, timeliness is unreliable at high volume, and event ordering is not dependable above the order-trust ceiling. Coverage claims for T1074.001 should be qualified accordingly.

**Escape hatch if needed.** For specific high-value paths where counts must be trustworthy, Windows object-access auditing via SACL (event 4663) and file-share access (5145) are not subject to MDE-side sampling. Painful at volume; viable scoped to a handful of sensitive shares as corroboration rather than replacement.

---

## 10. Testing and validation

### Before enabling

1. **Confirm `InitiatingProcessVersionInfoOriginalFileName` exists and is populated:**
   ```kql
   DeviceFileEvents
   | where Timestamp > ago(1h)
   | where ActionType == "FileCreated"
   | take 5
   | project-keep InitiatingProcess*
   ```
   If absent, delete the two `[VERSIONINFO]` lines and record that rename evasion is unmitigated.

2. **Confirm `InitiatingProcessCommandLine` population rate.** If sparse, extraction suppression rests entirely on the preceding-archive path and FP volume will be higher.

3. **Baseline distribution** — run the hunting variant over 7 days with `MinFileCount = 1` and the liveness gate commented out:
   ```kql
   | summarize Bursts = count() by FileCountBand = bin(FileCount, 25)
   | sort by FileCountBand asc
   ```

4. **Inspect suppressions** — invert the filter and read what is being dropped:
   ```kql
   | where ExtractionCmdCount > 0 or (ArchivePriorCount > 0 and FileCount < OrderTrustCeiling)
   ```
   Do this before trusting the rule, not after.

5. **Cross-check Sentinel against Advanced Hunting.** Run as a saved hunting query in Sentinel over a period already characterised in AH and compare row counts. Divergence indicates a `TimeGenerated` / `Timestamp` disagreement on this table worth understanding before it generates incidents.

### Verifying the liveness gate is not inert

The single most likely way this rule breaks silently. Run the query body up to the suppression filters, then:

```kql
| extend LivenessAgeMin = datetime_diff('minute', now(), LastIngest)
| project BurstKey, FileCount, LastIngest, LivenessAgeMin,
          WouldPass = LastIngest > ago(2h15m)
| sort by LivenessAgeMin asc
```

If every row shows `WouldPass = true`, the gate is doing nothing and `Liveness` is too large relative to the lookup period.

**Note:** with the gate active, interactive testing of the full rule returns few or no rows most of the time, because most bursts in an 8h window fail it. That is expected, not broken. Comment the line out to test the rest of the logic.

### Controlled positive

Robocopy a few hundred documents from a share to a local staging folder under a normal (non-admin, non-service) user account, then compress with `Compress-Archive`.

Expect: **one** alert, one incident, `ArchiveFollowCount > 0`, `ArchivePriorCount = 0`.

Leave the rule running for several hours afterwards and confirm no further alerts for the same `BurstKey`. That is the v1.1 regression test.

### Differential skew test — the important one

Repeat the controlled positive at **3,000 files**, then archive immediately.

Check that the archive still classifies as **following** rather than **prior**. This directly probes the assumption the suppression logic rests on. The same run gives the `Timestamp` spread that settles `BurstWindow`, and the `IngestSpreadSec` value that indicates whether long-tail ingestion is a real risk for the liveness gate.

### Controlled negative

Extract a document-heavy zip. Confirm it suppresses via the command-line path (`ExtractionCmdCount > 0`), not only via ordering.

### Atomic Red Team

T1074.001 atomics are thinner than the copy-then-archive scenario above. Treat the manual test as primary and the atomics as supplementary.

---

## 11. Related rules

| Rule | Relationship |
|---|---|
| `HQ-MassFCStagingKQL` | Overlapping scope — mass file creation / staging. Uses the same post-aggregation liveness pattern; the two rules are now consistent. Check for duplicate incident generation across both. |
| `MassSensFilRead_Sentinel` | Sensitive file read → create correlation. **Known issue:** applies `ingestion_time()` *pre*-aggregation, which is exposed to the batch fragmentation described in §3 and §6. That rule has a 100-file threshold on the same telemetry, so a large burst arriving across batches may never reach it. Should be reviewed and converted to the post-aggregation pattern. |

**Cross-cutting actions:**
- Review file-count thresholds on all existing rules against the emission ceiling finding (§3). Any threshold above the ceiling will not fire.
- Audit any other rule using `ingestion_time()` for whether it is applied before or after aggregation, and whether its liveness value is smaller than its lookup period.

---

## 12. Review triggers

Re-validate this rule when any of the following occur:

- **Rule frequency is changed in the wizard** — `Liveness` must be updated to match
- MDE sensor version change (sampling and timestamp behaviour are undocumented and have changed across versions)
- Microsoft response on the timestamp misassignment ticket
- `ArchiveFollowWindow` is widened — must stay inside `Liveness`
- Significant change to device naming or service account conventions
- Deployment of new bulk-document tooling to the estate
- Sentinel / Defender portal changes affecting rule configuration

## Change log

| Version | Date | Change | By |
|---|---|---|---|
| 1.0 | _[date]_ | Initial deployment. Dedupe by alert grouping only, no in-query gate. | _[name]_ |
| 1.1 | _[date]_ | Added post-aggregation liveness gate (`Liveness = 2h15m`) after v1.0 produced 8 identical alerts per burst in production. Alert grouping demoted to backstop. Added blind spots for archive-escalator narrowing and unrecoverable missed executions. Added gate-inertness validation step. | _[name]_ |







































#########################################################################################################################################################################################
# HQ-MassDocCreationAnomalousProcess

**Status:** Deployed — tuning in progress
**Platform:** Microsoft Sentinel (scheduled analytics rule)
**Data source:** `DeviceFileEvents` (MDE, via Defender XDR data connector)
**Owner:** _[fill in]_
**Created:** _[fill in]_
**Last reviewed:** _[fill in]_
**Version:** 1.1 — see change log

---

## 1. What this detects

Bulk creation of document-type files by copy, scripting or admin utilities running under an interactive user account, on devices outside the IT/server estate.

Creation of an archive shortly after the burst is surfaced as a staging escalator. Bursts *preceded* by an archive, or initiated by a command line containing an extraction verb, are suppressed as likely unpacking.

**Hypothesis:** an adversary collecting data prior to exfiltration will copy documents into a staging location using an available copy or scripting utility, and will frequently compress the result before transfer. The copy-then-archive sequence is a structural requirement of that workflow and is rare in normal user activity.

**MITRE ATT&CK**
| | |
|---|---|
| Tactic | Collection (TA0009) |
| Technique | T1074.001 — Local Data Staging |
| Technique | T1560.001 — Archive via Utility *(where a following archive is present)* |

Exfiltration (TA0010) is deliberately **not** mapped. Nothing in this rule observes egress, and the mapping should reflect what the query evidences.

---

## 2. Design rationale

Recorded because the reasoning is not obvious from the query, and because several intuitive alternatives were considered and rejected.

### Why the chain, not just volume

Bulk file creation alone is far too noisy — routine archive extraction alone generates dozens of events per day in a normal estate. Neither bulk creation nor archive creation is convincing in isolation. The ordered pair, on one device under one account within a short window, is what carries the signal.

### Why order is used to suppress rather than to fire

An archive *before* a burst indicates extraction. An archive *after* indicates staging. The same two components appear in both the benign and malicious case; only the direction differs.

This means the archive is not a mandatory firing condition. Requiring it would produce good precision and poor recall — collection is not always followed by local compression (direct cloud upload, staging to a mapped share, exfil in place all skip it). Instead:

- Archive **before** → suppress
- Archive **after** → escalator, raises confidence
- No archive → alert stands on process, volume and destination class

### Why the process list is a noise filter, not a detection boundary

The process list is trivially evaded by renaming, recompiling or substituting a tool. It is retained because it is an effective *noise* filter, not because it is evasion-resistant. Original-filename checking (`InitiatingProcessVersionInfoOriginalFileName`) raises the bar against simple renaming of in-box binaries, but nothing here detects an unlisted or custom copy utility.

This distinction must be preserved in any future review. The list is not the detection.

### Approaches considered and rejected

| Approach | Rejected because |
|---|---|
| Per-user process baseline (first-seen) | Cold-start on new starters, breaks on reimage/role change/VDI, poisonable over a two-week dwell, cannot exceed the 14-day query lookup cap without a precomputed table. Does not suppress the actual FP sources, which are device- and account-class driven. |
| Confidence tiering (multiple rules at different thresholds) | Tier boundaries were invented rather than derived. Replaced by a single rule with corroborated suppression. |
| Numeric severity scoring in-query | Severity is a claim about false positive rate, which cannot be known before the rule runs. Deferred to post-baseline. |
| Pre-aggregation `ingestion_time()` dedupe | Filters raw rows before counting them, so a batched burst is counted in fragments and fails the threshold on every run. Silent miss. See §6. |
| Alert grouping as the *sole* dedupe mechanism | Tried in v1.0 and failed in production — 8 identical alerts per burst. See §6. |
| Distinct-folder count as a filter | Direction is ambiguous — staging into one directory produces a low count; `robocopy /E` preserving tree structure produces a high one. Retained as a triage column only. |

---

## 3. Telemetry findings — read before modifying this rule

These were measured locally in this tenant and directly shape the design. None of this behaviour is documented by Microsoft, and it may change with sensor version.

### Sampling / emission ceiling

| Test | Files written | Events initially returned |
|---|---|---|
| 1 | 300 | complete |
| 2 | 600 | complete |
| 3 | 3,000 | fewer than 100 |

The reliability boundary sits somewhere between 600 and 3,000. The pattern is more consistent with a **ceiling** than with proportional sampling.

**Consequence:** any file-count threshold above that ceiling will never fire, regardless of how much data is actually moved. This is a silent failure mode. `MinFileCount` is therefore set deliberately low, and count is treated as evidence that a burst occurred rather than as a measure of its size.

**This affects other rules.** Any detection with a file-count threshold — mass encryption, wiper, destruction, DLP-adjacent — is exposed to the same ceiling. Existing thresholds should be reviewed against this finding.

### Timestamp misassignment

In test 3, the bulk of events arrived **over an hour late**, and `Timestamp`, `TimeGenerated` and `ingestion_time()` were all shifted together — none of the three accounted for the delay.

Three consequences:

1. **Detection latency is structural**, roughly two hours. Not fixable by increasing rule frequency.
2. **Event ordering cannot be fully trusted at high volume.** If file creates are batch-timestamped and shifted forward while a single archive event is not, a genuine staging sequence can be recorded as an extraction pattern and suppressed. This is why the order-based suppression has a volume ceiling above which it does not apply.
3. **Analyst timelines will be misleading.** Surfaced via the `MaxLagMin` custom detail.

### Production observation (v1.0, first fires)

Eight alerts generated for a single burst, grouped into one incident, with **identical `FileCount` across all eight**.

Identical counts mean no new rows arrived after the first alert — the burst settled quickly and was then re-emitted on each subsequent execution for no informational gain. This contradicts the long-tail ingestion pattern that had been assumed when the dedupe gate was originally rejected, and prompted the v1.1 change.

### Open with Microsoft

_[Record ticket reference and status here.]_

The sampling behaviour will likely be confirmed as by design. The **timestamp misassignment is the defect worth pursuing** — if `Timestamp` reflects batch processing rather than event occurrence, that affects every timeline and every correlation in the tenant, not just this rule. Lead with that; keep sampling as context.

Re-validate all of the above after any MDE sensor version change.

---

## 4. Query

```kql
//==========================================================================
// HQ-MassDocCreationAnomalousProcess
// Sentinel scheduled analytics rule
//
// REQUIRED RULE CONFIG - the in-query logic depends on it:
//   Run query every : 1 hour        <-- if you change this, update Liveness below
//   Lookup period   : 8 hours       -- must exceed BurstWindow + ArchiveFollowWindow + skew
//   Event grouping  : trigger an alert for each event (1 row = 1 burst)
//   Alert grouping  : ON, Host + Account, 8 hours   <-- backstop, not primary dedupe
//==========================================================================
let BurstWindow         = 1h;      // UNMEASURED - set from observed Timestamp spread
let MinFileCount        = 40;      // UNMEASURED - set from baseline distribution run
let ArchivePriorWindow  = 30m;     // UNVALIDATED PLACEHOLDER
let ArchiveFollowWindow = 2h;      // UNVALIDATED PLACEHOLDER
let OrderTrustCeiling   = 500;     // DERIVED - local testing: 600 clean, 3000 reordered
// Dedupe gate. Constraints, all three of which fail silently if broken:
//   1. MUST be < the lookup period, or the filter is inert.
//   2. MUST be >= frequency + jitter, or a burst landing just after a run is
//      never reported. A miss is worse than a duplicate.
//   3. MUST be updated by hand if the wizard frequency changes.
// 2h15m tolerates one missed/delayed execution at the cost of at most two
// alerts per burst. Tight setting for 1h frequency would be 1h15m.
let Liveness            = 2h15m;
//
let DocExtensions = dynamic(["docx","doc","docm","xlsx","xls","xlsm","xlsb","pptx","ppt","pptm",
                             "pdf","csv","rtf","odt","ods","odp","msg","eml","pst","ost","one",
                             "vsdx","vsd","accdb","mdb"]);
let ArchiveExtensions = dynamic(["zip","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","wim",
                                 "arj","lzh","ace","001","z01","r00","r01"]);
let SuspectProcesses = dynamic(["robocopy.exe","xcopy.exe","powershell.exe","pwsh.exe","cmd.exe",
                                "wscript.exe","cscript.exe","mshta.exe","rundll32.exe","certutil.exe",
                                "bitsadmin.exe","esentutl.exe","forfiles.exe","curl.exe","wget.exe",
                                "wmic.exe","ftp.exe","python.exe"]);
let ExcludedAccounts = dynamic(["system","local service","network service","localsystem","-"]);
let ServiceAcctRegex    = @"^(svc|sa|adm|_)[-_.]";        // PLACEHOLDER
let ExcludedDeviceRegex = @"^(srv|bld|vdi|sccm|mgmt)-";   // PLACEHOLDER - prefer device-group join
let ExtractionVerbs = @"(?i)(expand-archive|7z[a]?\s+[xe]\b|\brar\s+[xe]\b|\bunzip\b|tar\s+[^|]*-?x|extractto|\bexpand\s+-)";
//
let ScopedCreates =
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where isnotempty(InitiatingProcessFileName)
    | extend FileExt = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, FileName))
    | where FileExt in (DocExtensions)
    | extend InitProc = tolower(InitiatingProcessFileName)
    // [VERSIONINFO] delete next 2 lines if the field is absent in this tenant
    | extend InitProcOriginal = tolower(tostring(InitiatingProcessVersionInfoOriginalFileName))
    | extend NameMismatch = isnotempty(InitProcOriginal) and InitProcOriginal != InitProc
    | where InitProc in (SuspectProcesses) or InitProcOriginal in (SuspectProcesses)
    | extend Acct       = tolower(InitiatingProcessAccountName),
             AcctDomain = tostring(InitiatingProcessAccountDomain),
             AcctUpn    = tostring(InitiatingProcessAccountUpn)
    | where Acct !in (ExcludedAccounts)
    | where Acct !endswith "$"
    | where not(Acct matches regex ServiceAcctRegex)
    | where not(tolower(DeviceName) matches regex ExcludedDeviceRegex)
    | extend IsExtractionCmd = tostring(InitiatingProcessCommandLine) matches regex ExtractionVerbs
    | extend IngestAt = ingestion_time();
//
// NOTE: aggregation runs over the FULL lookup period. The dedupe gate is applied
// after this, never before it - filtering raw rows by ingestion time would count
// a batched burst in fragments and fail the threshold on every run.
let Bursts =
    ScopedCreates
    | summarize
        FileCount          = count(),
        DistinctFolders    = dcount(FolderPath),
        DistinctExts       = dcount(FileExt),
        ExtractionCmdCount = countif(IsExtractionCmd),
        MismatchCount      = countif(NameMismatch),          // [VERSIONINFO]
        OriginalNames      = make_set(InitProcOriginal, 3),  // [VERSIONINFO]
        NetworkWrites      = countif(FolderPath startswith "\\\\"),
        TempWrites         = countif(FolderPath has @"\AppData\Local\Temp" or FolderPath has @"\Windows\Temp"),
        AppDataWrites      = countif(FolderPath has @"\AppData\"),
        PublicWrites       = countif(FolderPath has @"\Users\Public\" or FolderPath has @"\ProgramData\"),
        FirstCreate        = min(Timestamp),
        LastCreate         = max(Timestamp),
        FirstIngest        = min(IngestAt),
        LastIngest         = max(IngestAt),
        LastRowTG          = max(TimeGenerated),
        AcctDomain         = any(AcctDomain),
        AcctUpn            = any(AcctUpn),
        SampleFolders      = make_set(FolderPath, 8),
        SampleFiles        = make_set(FileName, 8),
        CmdSample          = make_set(substring(tostring(InitiatingProcessCommandLine), 0, 250), 3),
        ProcPaths          = make_set(InitiatingProcessFolderPath, 3)
      by DeviceId, DeviceName, Acct, InitProc, BurstStart = bin(Timestamp, BurstWindow)
    | where FileCount >= MinFileCount
    | extend BurstSpanSec    = datetime_diff('second', LastCreate, FirstCreate)
    | extend IngestSpreadSec = datetime_diff('second', LastIngest, FirstIngest)
    | extend MaxLagMin       = datetime_diff('minute', LastIngest, FirstCreate)
    | extend FilesPerMin     = iff(BurstSpanSec <= 0, todouble(FileCount),
                                   round(FileCount / (BurstSpanSec / 60.0), 1))
    | extend BurstQ1Time     = FirstCreate + (LastCreate - FirstCreate) * 0.25
    | extend BurstKey        = strcat(DeviceId, "|", Acct, "|", InitProc, "|", format_datetime(BurstStart, "yyyyMMddHHmm"));
//
let ArchiveEvents =
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | extend ArchExt = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, FileName))
    | where ArchExt in (ArchiveExtensions)
    | project ArchiveTime = Timestamp, DeviceId,
              ArchAcct    = tolower(InitiatingProcessAccountName),
              ArchiveFull = strcat(FolderPath, "\\", FileName),
              ArchiveProc = tolower(InitiatingProcessFileName);
//
let BurstArchive =
    Bursts
    | project BurstKey, DeviceId, Acct, FirstCreate, LastCreate, BurstQ1Time
    | join kind=leftouter ArchiveEvents on DeviceId, $left.Acct == $right.ArchAcct
    | extend RelPos = case(
          isnull(ArchiveTime), "none",
          ArchiveTime between ((FirstCreate - ArchivePriorWindow) .. FirstCreate), "prior",
          ArchiveTime between (BurstQ1Time .. (LastCreate + ArchiveFollowWindow)), "following",
          "outofwindow")
    | summarize
        ArchivePriorCount  = countif(RelPos == "prior"),
        ArchiveFollowCount = countif(RelPos == "following"),
        PriorArchives      = make_set_if(ArchiveFull, RelPos == "prior", 5),
        FollowingArchives  = make_set_if(ArchiveFull, RelPos == "following", 5),
        FollowingArchProcs = make_set_if(ArchiveProc, RelPos == "following", 5)
      by BurstKey;
//
Bursts
| join kind=leftouter BurstArchive on BurstKey
| extend ArchivePriorCount  = coalesce(ArchivePriorCount, 0),
         ArchiveFollowCount = coalesce(ArchiveFollowCount, 0)
// --- Suppression: likely archive extraction ---
// Command-line verb is timestamp-independent, so suppress unconditionally.
| where ExtractionCmdCount == 0
// Preceding archive is order-based, so only trusted below the volume at which
// local testing showed event ordering becomes unreliable (600 clean / 3000 reordered).
| where ArchivePriorCount == 0 or FileCount >= OrderTrustCeiling
// --- Dedupe gate ---
// Report a burst only on the run during which new rows arrived for it. The burst
// stays in scope on later runs, but with nothing new landed it stays silent.
| where LastIngest > ago(Liveness)
// --- Flatten dynamics for custom details / entity fields ---
| extend FollowingArchivesStr = tostring(strcat_array(FollowingArchives, "; ")),
         PriorArchivesStr     = tostring(strcat_array(PriorArchives, "; ")),
         SampleFoldersStr     = tostring(strcat_array(SampleFolders, "; ")),
         SampleFilesStr       = tostring(strcat_array(SampleFiles, "; ")),
         CmdSampleStr         = tostring(strcat_array(CmdSample, " || ")),
         ProcPathsStr         = tostring(strcat_array(ProcPaths, "; ")),
         OriginalNamesStr     = tostring(strcat_array(OriginalNames, "; "))
// Sentinel needs TimeGenerated on a summarised result for alert timestamping.
// Uses max(TimeGenerated) of contributing rows, NOT Timestamp - Timestamp is skewed
// and could fall outside the lookup period.
| extend TimeGenerated = LastRowTG
| project TimeGenerated, BurstStart, DeviceName, DeviceId, Acct, AcctDomain, AcctUpn, InitProc,
          FileCount, FilesPerMin, BurstSpanSec, DistinctFolders, DistinctExts,
          MismatchCount, OriginalNamesStr,
          NetworkWrites, TempWrites, AppDataWrites, PublicWrites,
          ArchiveFollowCount, FollowingArchivesStr, ArchivePriorCount, PriorArchivesStr,
          FirstCreate, LastCreate, FirstIngest, LastIngest, IngestSpreadSec, MaxLagMin,
          SampleFoldersStr, SampleFilesStr, CmdSampleStr, ProcPathsStr, BurstKey
```

### Block-by-block

| Block | Purpose |
|---|---|
| `ScopedCreates` | Scopes to document-class creates by a listed (or renamed-listed) process under an interactive account on a non-excluded device. Filtering happens here rather than post-aggregation so the summarize operates on a much smaller set. `IngestAt` is captured per row for the later dedupe gate. |
| `Bursts` | Bucketed aggregation by device/account/process/time bin over the **full** lookup period. Only `FileCount` gates. `BurstQ1Time` is the quarter-point of the burst, used as the "following" reference instead of `LastCreate` so late-arriving stragglers cannot push a genuine staging archive out of window. |
| `ArchiveEvents` | All archive creates in period, unscoped by process or account exclusions — an archive written by anything is relevant context. |
| `BurstArchive` | Joins archives to bursts on device + account, classifies each as prior / following / out of window, re-aggregates by `BurstKey`. Split out to avoid carrying every burst column through a `by` clause after the join. |
| Final block | Suppression, dedupe gate, dynamic flattening, `TimeGenerated` reinstatement, projection. |

### Dedupe gate placement

The gate sits **after** the join and the suppression filters, operating on `LastIngest` produced by the summarize. It cannot move:

- **Not in `ScopedCreates`** — that would filter raw rows before counting them, so a batched burst gets counted in slices and fails the threshold on every run. Silent miss.
- **Not inside the `Bursts` summarize** — `LastIngest` does not exist until the summarize completes.
- **After suppression rather than before**, purely for cost: no point evaluating liveness on rows about to be discarded.

---

## 5. Parameters

| Parameter | Value | Status | Sensitive to |
|---|---|---|---|
| `BurstWindow` | `1h` | **UNMEASURED** | Timestamp batch spread. Set from the observed `Timestamp` spread across rows from a single large copy. Too narrow fragments a real burst into sub-threshold pieces (silent miss); too wide dilutes `FilesPerMin` and aggregates unrelated activity (visible at triage). Erred wide because the first failure is silent. |
| `MinFileCount` | `40` | **UNMEASURED** | Baseline distribution. Set from the 7-day run at p99+ of the per-burst distribution. Kept low deliberately because of the emission ceiling. |
| `ArchivePriorWindow` | `30m` | Placeholder | How long before a burst an archive still plausibly explains it. |
| `ArchiveFollowWindow` | `2h` | Placeholder | Operator tempo. Hands-on-keyboard staging is minutes; slower operations may be hours. Wider costs precision, narrower costs recall. Must stay within `Liveness` — see §9. |
| `OrderTrustCeiling` | `500` | **Derived** | Local testing (600 clean, 3,000 reordered). Re-validate after sensor updates. |
| `Liveness` | `2h15m` | **Coupled to wizard frequency** | Rule frequency + jitter. Three hard constraints, all silent on failure — see below. |
| `ServiceAcctRegex` | placeholder | **Unresolved** | Local naming convention. |
| `ExcludedDeviceRegex` | placeholder | **Unresolved** | Prefer a device-group or tag join over a regex. |

### Liveness constraints

1. **`Liveness` < lookup period.** Otherwise every row passing the platform's `TimeGenerated` filter automatically passes the liveness filter and the gate is inert. *(This is the trap `HQ-MassFCStagingKQL` originally fell into: 30m lookback, 60m liveness.)*
2. **`Liveness` ≥ frequency + jitter.** Otherwise a burst landing shortly after an execution is stale by the next one and is never reported. A miss is worse than a duplicate.
3. **`Liveness` must be updated by hand if the wizard frequency changes.** This coupling is invisible from the portal. The comment block in the query is the only protection.

At 1h frequency the tight setting is `1h15m` and the robust setting is `2h15m`. The robust setting tolerates one missed or delayed execution at the cost of at most two alerts per burst. Currently set to the robust value.

---

## 6. Rule configuration

### Scheduling

| Setting | Value | Basis |
|---|---|---|
| Run query every | 1 hour | Detection latency floor is set by ~90m skew, not cadence. If changed, **update `Liveness`**. |
| Lookup period | 8 hours | `BurstWindow` (1h) + `ArchiveFollowWindow` (2h) + skew (~1.5h) + headroom. Must exceed all in-query windows or archive correlation silently truncates. |

**Overlap behaviour.** Lookback exceeds frequency by 8x, deliberately, so a burst straddling an execution boundary or arriving late is still fully visible. Each burst is therefore *evaluated* up to eight times but *reported* once, because of the liveness gate.

### Deduplication — how it works and why it is built this way

**Primary mechanism: post-aggregation liveness gate.**

The aggregation runs over the full lookup period, so every row of a burst is counted regardless of which ingestion batch it arrived in. The threshold always sees the complete picture. The gate then asks, after the fact: *did anything new land for this burst since the last run?*

| Run | Burst in window? | `LastIngest` age | Alert? |
|---|---|---|---|
| 10:00 | yes | 12m | **yes** |
| 11:00 | yes | 72m | no |
| 12:00 | yes | 132m | no |

Report on first sight, then stay quiet.

**Secondary mechanism: alert grouping** (Host + Account, 8h). Now a backstop for residual cases — a genuinely long-tailed burst that keeps refreshing `LastIngest`, or a second distinct burst on the same host and account — rather than the primary control.

**Why not pre-aggregation `ingestion_time()`.** Filtering raw rows by ingestion time before the summarize counts a batched burst in fragments: run 1 sees 50 rows, run 2 sees 200, none reaching threshold, and the burst is never reported. Given the sensor batching documented in §3, this rule is directly exposed to that failure. It is a silent miss and is strictly worse than a duplicate.

**Why alert grouping alone was insufficient (v1.0 → v1.1).** The original design used grouping as the sole dedupe layer, on the reasoning that the liveness gate leaks on long-tail bursts and makes a failed execution unrecoverable. In production this produced **8 identical alerts per burst** — identical `FileCount`, confirming the burst had settled and the re-emissions carried no new information. The long-tail leak the gate was rejected over did not occur. The gate was added in v1.1.

**Residual cases.** Not a guarantee:
- A burst with a genuinely long ingestion tail keeps refreshing `LastIngest` and can re-alert. Grouping absorbs it.
- A failed or delayed execution beyond the liveness window means the burst is never reported. This is the real cost of the gate; the `2h15m` buffer is sized to tolerate one missed run.

### Alerting

| Setting | Value | Note |
|---|---|---|
| Alert threshold | Results > 0 | Volume logic lives in `MinFileCount`, don't duplicate. |
| Event grouping | Trigger an alert for each event | 1 row = 1 burst. Note the 150-alert-per-execution cap — hitting it means `MinFileCount` is too low, and it fails silently. |
| Suppression | **Off** | Stops the whole rule; a second account staging during the window would be missed entirely. |
| Alert grouping | **On** — Host + Account, 8 hours | Backstop. Window must match the lookup period, or residual re-evaluations at the far edge split into a second incident. |
| Reopen closed incidents | Off | |
| Create incidents | On | |

### Severity

**Unresolved.** Set from the baseline run. Severity is a claim about false positive rate and that number is not yet known. Starting High on an unvalidated rule trains analysts to ignore it.

Once the data exists, the likely candidate for a High promotion via alert details override is `ArchiveFollowCount > 0`. Any severity column must contain only `Informational` / `Low` / `Medium` / `High`.

### Entity mapping

| Entity | Identifier | Column |
|---|---|---|
| Host | HostName | `DeviceName` |
| Host | AzureID | `DeviceId` |
| Account | Name | `Acct` |
| Account | NTDomain | `AcctDomain` |
| Account | UPNSuffix | `AcctUpn` |
| Process | ProcessId | `InitProc` |

Account and Host drive investigation graph and UEBA correlation. The Process entity is awkward — it maps a process *name* to a schema expecting a PID or command line; if it maps badly, drop it and keep the process in custom details. `DeviceId` as AzureID assumes MDE device IDs resolve in the workspace — verify.

### Custom details

`FileCount`, `FilesPerMin`, `DistinctFolders`, `ArchiveFollowCount`, `FollowingArchivesStr`, `ArchivePriorCount`, `MismatchCount`, `OriginalNamesStr`, `MaxLagMin`, `CmdSampleStr`, `SampleFoldersStr`

`MaxLagMin` and `ArchivePriorCount` matter most — see triage.

### Automation

**None initially.** No playbooks until the FP rate is known. When added, the sensible first automation is enrichment (device and user context, recent sign-in activity) rather than containment. Given the ~90 minute skew, any isolation or account-disable action is responding to something that happened two hours ago, which materially changes the value calculation.

---

## 7. Analyst triage

```
TRIAGE - HQ-MassDocCreationAnomalousProcess

First: check MaxLagMin. If it is large, the times shown in the incident are not when
this happened. Correlate against sign-in and process telemetry using the user's actual
working pattern, not the alert timestamp.

Second: check ArchivePriorCount. If greater than zero, an archive was created before
this burst - normally indicative of extraction. This alert fired anyway because the
file count exceeded the volume at which local testing showed event ordering becomes
unreliable. Treat the ordering as unknown rather than as evidence of extraction, and
check PriorArchivesStr to see whether the archive plausibly accounts for the files
created.

Third: check ArchiveFollowCount and FollowingArchivesStr. A following archive is the
strongest single indicator here - collection followed by staging. Escalate.

Then assess:
- Is the destination consistent with staging? NetworkWrites, TempWrites, AppDataWrites
  and PublicWrites give the breakdown. Writes into an established Documents tree are
  weaker than writes into temp, ProgramData or a network path.
- Does CmdSampleStr show a plausible business purpose? Batch export, mail merge,
  reporting and migration scripts are the most common true-benign causes.
- Does MismatchCount indicate a renamed binary? OriginalNamesStr shows the compiled-in
  filename. Common and usually benign for installers and vendor tools, but a renamed
  robocopy or a copy utility running from a user-writable path is not.
- Is the account or device a known exception that should be excluded at rule level?

Remember FileCount may be a fraction of reality. A 60-file alert is not necessarily a
small event.

If you see more than one alert for the same BurstKey, the dedupe gate has leaked -
raise it with the rule owner rather than just closing the duplicates. It usually means
either a long ingestion tail or a Liveness value out of step with the rule frequency.
```

---

## 8. Expected false positives

Ranked by likely volume.

| Source | Notes |
|---|---|
| Sync and backup clients | OneDrive first sync, restores, FSLogix/profile container hydration. Mostly attributed to the sync binary and out of scope, but restores under a user account can surface. |
| Batch export and reporting | PowerShell generating CSVs, mail merge, PST exports, eDiscovery collections, finance month-end. The nastiest category: user-initiated, document-typed, legitimately scripted. |
| Profile and share migration | USMT, robocopy in logon scripts, file server consolidation. Better handled as scheduled-window exclusions than blanket process exclusions. |
| Deployment tooling | Anything that slipped the device and account filters. |
| Archive extraction without captured command line | Suppression falls back to the preceding-archive path, which misses extraction of archives already on disk or opened from a share. |

**Tuning order.** Run the noise profile first:

```kql
| summarize Bursts = count(), TotalFiles = sum(FileCount) by InitProc, DeviceName
| sort by Bursts desc
```

If one process or a handful of devices dominates, that is a scoping gap to fix in `ScopedCreates`, not a threshold to raise.

---

## 9. Known blind spots

Mandatory reading before anyone claims coverage from this rule.

- **No visibility of the copy source.** `DeviceFileEvents` records files written, not read. A robocopy pulling from twenty user profiles and one pulling from a single folder are indistinguishable here.
- **Split, renamed or extensionless archives** (`.7z.001`, `.part1.rar`) are not detected by extension matching.
- **In-memory or streamed compression** never touches disk as a recognisable archive.
- **The process list is a noise filter.** A recompiled or unlisted copy utility is not detected. Original-filename checking mitigates simple renaming of in-box binaries only, and fails against stripped or forged version resources.
- **Archiver binaries are out of scope entirely** — they are not in `SuspectProcesses`, so an attacker using 7-Zip or WinRAR to *copy* files never enters the pipeline.
- **Command-line suppression is attacker-influenceable.** Padding a command line with an extraction verb would suppress the alert. Accepted as a noise-filter trade-off, but it is real attack surface.
- **The liveness gate narrows the archive escalator.** *(New in v1.1.)* The gate applies to the burst, not the archive. If a staging archive lands after the burst has gone quiet beyond `Liveness`, the escalator will not retrospectively raise an alert, because the burst itself is stale. At `ArchiveFollowWindow = 2h` and `Liveness = 2h15m` this only bites at the edge, but **`ArchiveFollowWindow` must stay comfortably inside `Liveness`** or the escalator degrades. Widening the follow window requires widening liveness too.
- **A failed or delayed rule execution is unrecoverable.** *(New in v1.1.)* Bursts that would have been new during a missed run are stale by the next one. Rule health monitoring matters more now than it did in v1.0.
- **Bin boundary straddle.** A burst spanning a `bin()` boundary splits into two, each potentially sub-threshold. Inherent to bucketed aggregation. `row_window_session()` sessionises properly but requires serialisation and is expensive at this table's volume.
- **Leading-edge suppression weakness.** A burst near the start of the lookup period cannot see archives that preceded it, so extraction suppression is weaker there.
- **`FileCount` understates volume.** See §3.

### Coverage quality (DeTT&CT framing)

`DeviceFileEvents` is present and streaming, but presence is not usable coverage. For this technique the data source quality is **degraded**: volume is sampled at the sensor, timeliness is unreliable at high volume, and event ordering is not dependable above the order-trust ceiling. Coverage claims for T1074.001 should be qualified accordingly.

**Escape hatch if needed.** For specific high-value paths where counts must be trustworthy, Windows object-access auditing via SACL (event 4663) and file-share access (5145) are not subject to MDE-side sampling. Painful at volume; viable scoped to a handful of sensitive shares as corroboration rather than replacement.

---

## 10. Testing and validation

### Before enabling

1. **Confirm `InitiatingProcessVersionInfoOriginalFileName` exists and is populated:**
   ```kql
   DeviceFileEvents
   | where Timestamp > ago(1h)
   | where ActionType == "FileCreated"
   | take 5
   | project-keep InitiatingProcess*
   ```
   If absent, delete the two `[VERSIONINFO]` lines and record that rename evasion is unmitigated.

2. **Confirm `InitiatingProcessCommandLine` population rate.** If sparse, extraction suppression rests entirely on the preceding-archive path and FP volume will be higher.

3. **Baseline distribution** — run the hunting variant over 7 days with `MinFileCount = 1` and the liveness gate commented out:
   ```kql
   | summarize Bursts = count() by FileCountBand = bin(FileCount, 25)
   | sort by FileCountBand asc
   ```

4. **Inspect suppressions** — invert the filter and read what is being dropped:
   ```kql
   | where ExtractionCmdCount > 0 or (ArchivePriorCount > 0 and FileCount < OrderTrustCeiling)
   ```
   Do this before trusting the rule, not after.

5. **Cross-check Sentinel against Advanced Hunting.** Run as a saved hunting query in Sentinel over a period already characterised in AH and compare row counts. Divergence indicates a `TimeGenerated` / `Timestamp` disagreement on this table worth understanding before it generates incidents.

### Verifying the liveness gate is not inert

The single most likely way this rule breaks silently. Run the query body up to the suppression filters, then:

```kql
| extend LivenessAgeMin = datetime_diff('minute', now(), LastIngest)
| project BurstKey, FileCount, LastIngest, LivenessAgeMin,
          WouldPass = LastIngest > ago(2h15m)
| sort by LivenessAgeMin asc
```

If every row shows `WouldPass = true`, the gate is doing nothing and `Liveness` is too large relative to the lookup period.

**Note:** with the gate active, interactive testing of the full rule returns few or no rows most of the time, because most bursts in an 8h window fail it. That is expected, not broken. Comment the line out to test the rest of the logic.

### Controlled positive

Robocopy a few hundred documents from a share to a local staging folder under a normal (non-admin, non-service) user account, then compress with `Compress-Archive`.

Expect: **one** alert, one incident, `ArchiveFollowCount > 0`, `ArchivePriorCount = 0`.

Leave the rule running for several hours afterwards and confirm no further alerts for the same `BurstKey`. That is the v1.1 regression test.

### Differential skew test — the important one

Repeat the controlled positive at **3,000 files**, then archive immediately.

Check that the archive still classifies as **following** rather than **prior**. This directly probes the assumption the suppression logic rests on. The same run gives the `Timestamp` spread that settles `BurstWindow`, and the `IngestSpreadSec` value that indicates whether long-tail ingestion is a real risk for the liveness gate.

### Controlled negative

Extract a document-heavy zip. Confirm it suppresses via the command-line path (`ExtractionCmdCount > 0`), not only via ordering.

### Atomic Red Team

T1074.001 atomics are thinner than the copy-then-archive scenario above. Treat the manual test as primary and the atomics as supplementary.

---

## 11. Related rules

| Rule | Relationship |
|---|---|
| `HQ-MassFCStagingKQL` | Overlapping scope — mass file creation / staging. Uses the same post-aggregation liveness pattern; the two rules are now consistent. Check for duplicate incident generation across both. |
| `MassSensFilRead_Sentinel` | Sensitive file read → create correlation. **Known issue:** applies `ingestion_time()` *pre*-aggregation, which is exposed to the batch fragmentation described in §3 and §6. That rule has a 100-file threshold on the same telemetry, so a large burst arriving across batches may never reach it. Should be reviewed and converted to the post-aggregation pattern. |

**Cross-cutting actions:**
- Review file-count thresholds on all existing rules against the emission ceiling finding (§3). Any threshold above the ceiling will not fire.
- Audit any other rule using `ingestion_time()` for whether it is applied before or after aggregation, and whether its liveness value is smaller than its lookup period.

---

## 12. Review triggers

Re-validate this rule when any of the following occur:

- **Rule frequency is changed in the wizard** — `Liveness` must be updated to match
- MDE sensor version change (sampling and timestamp behaviour are undocumented and have changed across versions)
- Microsoft response on the timestamp misassignment ticket
- `ArchiveFollowWindow` is widened — must stay inside `Liveness`
- Significant change to device naming or service account conventions
- Deployment of new bulk-document tooling to the estate
- Sentinel / Defender portal changes affecting rule configuration

## Change log

| Version | Date | Change | By |
|---|---|---|---|
| 1.0 | _[date]_ | Initial deployment. Dedupe by alert grouping only, no in-query gate. | _[name]_ |
| 1.1 | _[date]_ | Added post-aggregation liveness gate (`Liveness = 2h15m`) after v1.0 produced 8 identical alerts per burst in production. Alert grouping demoted to backstop. Added blind spots for archive-escalator narrowing and unrecoverable missed executions. Added gate-inertness validation step. | _[name]_ |





















































# Document Staging and Archiving in Unusual Locations

**Rule type:** Scheduled analytics rule (Microsoft Sentinel)
**Severity:** Medium
**Status:** Enabled
**Data source:** DeviceFileEvents (Microsoft Defender XDR connector)
**MITRE ATT&CK:** TA0009 Collection — T1074.001 (Local Data Staging), T1560.001 (Archive via Utility)
**Owner:** [name]
**Created:** [date]
**Last reviewed:** [date]

---

## 1. What it detects

A burst of document-type file creation on an endpoint, followed within a short window by
creation of an archive file (≥10 MB) by a known archiving process, under the same account
on the same device.

Two independent branches, either of which triggers the rule:

| Branch | Staging location | Archive location |
|---|---|---|
| A — `StagingUnusual` | Outside normal user document folders | Anywhere |
| B — `ArchiveUnusual` | Anywhere | Outside normal user document folders |
| Both | Outside normal | Outside normal |

`MatchReason` in the alert's custom details records which branch fired. `Both` is the
strongest signal and should be triaged first.

## 2. Hypothesis

Collection precedes exfiltration, and compressing collected files is a common intermediate
step (T1074 → T1560). Individually these signals are near-useless: bulk document creation
is constant on any endpoint, and archive creation is routine. Correlated — same device,
same account, ordered, within a short window — they are worth investigating.

Location is used as a proxy for intent. This is a weak proxy and is acknowledged as such;
see Limitations.

## 3. How it works

**Anchored on archive creation, not file creation.** Archives are rare relative to document
writes, so the expensive aggregation only runs against devices that produced one. Staging
is never evaluated estate-wide, which means staging noise never has to be tuned away
globally — only on the small number of devices that archived something. This inversion
reduced unfiltered volume from ~40,000 correlated pairs per week to ~300.

**Four constraints do the discriminating:**

| Constraint | Purpose |
|---|---|
| Ordering (`StageTime < ArchiveTime`) | Excludes decompression, where files appear *after* the archive |
| Archiver process allow-list | Excludes Outlook attachment caches, Intune `.cab` writes, Office temp files — archive-shaped files that were never compressed |
| Size ≥10 MB | Removes trivial archives |
| Location flags | Branch logic per section 1 |

**Deduplication:** anchor events are sliced by `ingestion_time()` over a window matching
`queryFrequency`, while `queryPeriod` is set much wider. This is the pattern documented in
*Handle ingestion delay in scheduled analytics rules*. The wide period gives staging
correlation room and tolerates ingestion latency; the narrow ingestion slice ensures each
archive event is processed exactly once, in the run where it lands.

## 4. Configuration

| Setting | Value |
|---|---|
| Run query every | 30 minutes |
| Lookup data from the last | 3 hours |
| Alert threshold | Results > 0 |
| Event grouping | Trigger an alert for each event |
| Suppression | Off |
| Alert grouping | Enabled, 5 hours, matching Host + Account |

**Critical:** the in-query `AnchorSlice` variable must equal `queryFrequency`. Changing one
without the other causes either detection gaps or duplicate alerts.

### Tunable parameters (all environment-specific)

| Variable | Current | Sensitive to |
|---|---|---|
| `StagingFileThreshold` | 100 | Estate size, user workflows, **and MDE reporting fidelity — see Limitations** |
| `ArchiveMinSizeBytes` | 10 MB | Typical archive sizes; lowered from 250 MB once correlation carried the confidence |
| `StagingWindow` | 30 min | Observed spread between staging and archiving |
| `UserDocRegex` | See query | Org OneDrive folder naming |
| Exclusion lists | See query | Application estate — requires periodic review |

### Entity mappings

Host (HostName, MdatpDeviceId), Account (Sid, Name, UPNSuffix), File (Name, Directory),
FileHash (SHA256), Process (CommandLine).

## 5. Triage guidance

Read these custom details in order:

1. **`MatchReason`** — `Both` is strongest. `ArchiveUnusual` alone is weaker.
2. **`StagingUnderArchive`** — if `1`, staged files landed *underneath* the archive path.
   This is the signature of an extraction, not a collection. Likely benign.
3. **`GapToArchiveSeconds`** — very small gaps (a few seconds) suggest a machine process
   completing a copy-and-compress, not a human deciding to archive. Larger gaps are more
   consistent with deliberate activity.
4. **`ArchiveUnderStaging`** — if `1`, the archive was written into the staging folder tree.
   Circumstantial support that the archive relates to the staged files.
5. **`StagingFolders` / `ArchiveFolders`** — do the locations make sense for this user's role?
6. **`ArchiveProcesses` / `ArchiveCmdLines`** — CLI archiving with explicit source paths is
   more interesting than a GUI right-click.
7. **`StagingProcesses`** — what created the documents.

**Important:** the rule does **not** prove the archive contains the staged files. That is not
determinable from `DeviceFileEvents`. Correlation is circumstantial — same device, same
account, correct ordering, within window. Treat the alert as "these two things happened
together", not "this data was collected and packaged".

## 6. Known false positive sources

| Source | Handling |
|---|---|
| Archive extraction (unpacking a deliverable) | Ordering constraint; `StagingUnderArchive` context column |
| OneDrive "download as zip" multipart extraction into `%TEMP%` | Explicit narrow exclusion (process + temp path + volume-suffix directory) |
| Outlook attachment cache / INetCache | Excluded by path + process |
| Application-specific bulk writes | See exclusion list in query |
| Month-end / quarter-end bulk document operations | Expected volume increase; not excluded |

## 7. Limitations and blind spots

**This section is not optional reading. The rule's coverage is narrower than its name suggests.**

### 7.1 Staging and archiving both in normal user document folders is NOT detected

A user (or an attacker with hands-on access) who collects documents into
`Documents\subfolder\` and archives them there is invisible to this rule.

This is deliberate. Testing showed that including user document folders produced 60+ alerts
per week with no way to discriminate — the events are byte-for-byte identical to normal work,
and `DeviceFileEvents` contains no field that separates them. This is a data limitation, not
a tuning gap.

**Compensating controls:** removable media blocked; [proxy/DLP controls — confirm and list].
The residual exfiltration paths for this scenario are constrained by prevention rather than
detection.

### 7.2 C: volume only

Mapped network drives, network shares and non-system volumes are out of scope. Non-Windows
endpoints onboarded to MDE are also excluded as a side effect of the path logic.

### 7.3 MDE does not reliably report high-rate file creation

**Discovered during testing — significant, and affects any rule counting file events.**

Testing with ~3,000 file creations in a short burst resulted in only a few dozen events being
reported by the sensor. Reproduced twice. Nothing logged in
`Microsoft-Windows-SENSE/Operational`. Normal file activity on the same device immediately
before and after the burst reported correctly. Smaller volumes (~200 files at normal copy
rate) reported correctly.

**Implication:** `StagedFileCount` is unreliable above some rate threshold. A genuinely large
collection event may report fewer files than a small one and fail to cross the threshold —
biasing the rule against detecting the largest events.

**Status:** [ticket ref / raised with Microsoft on DATE]
**Outstanding:** graded testing at 500 and 1,000 files to establish where degradation begins.

### 7.4 Precision comes substantially from the exclusion list

The rule's low alert volume is achieved more by exclusions than by detection logic. Coverage
is therefore partly defined by what happened to be noisy in this estate rather than by threat
modelling. Exclusions drift as vendor behaviour changes.

### 7.5 Evasion

- Staging and archiving in normal user document folders (7.1)
- Archiving with a tool not on the archiver allow-list, or a renamed binary
- Splitting output into volumes below the 10 MB gate (e.g. `7z -v5m`)
- Staging fewer than the threshold, or spreading activity across a longer window
- Staging under one account context and archiving under another (e.g. SYSTEM via scheduled task)

## 8. Testing

### Generate a true positive

1. On a test device, create 150+ document files in a folder **outside** the excluded paths
   (e.g. `C:\Temp\test\`) — at a normal copy rate, not a scripted burst (see 7.3).
2. Wait ~1 minute.
3. Compress with 7-Zip or Explorer's built-in compression to a file ≥10 MB.
4. Wait for the next scheduled run (~35–50 minutes allowing for ingestion latency).

### Negative test

Extract a large archive on the same device. Confirm no alert, or that `StagingUnderArchive`
reads `1` if one appears.

### Verifying query logic outside a scheduled run

**Replaying a rule run will not work.** `ingestion_time() > ago(AnchorSlice)` is evaluated
against wall-clock time at execution, so a replay of a historical run finds nothing.

To verify logic, run the query in Log Analytics with the anchor line swapped for
`| where TimeGenerated > ago(7d)`.

Note also that records appear in Defender Advanced Hunting slightly before the Sentinel
workspace copy. A row visible in Advanced Hunting may not yet be queryable in Log Analytics.

## 9. Development history

Notes worth retaining for anyone modifying this rule.

- **`FolderPath` contains the filename** in `DeviceFileEvents`, not just the directory. This
  broke the original folder-concentration logic completely — `count_distinct(FolderPath)` was
  counting files, not folders, so a "≤5 destination folders" constraint could never be
  satisfied. **Any other rule in the estate grouping or counting by `FolderPath` should be
  audited for this.** The query derives `StageFolderNorm` / `ArchiveFolderNorm` defensively
  (strip filename if present) rather than trusting the column.

- **Folder concentration was dropped as a filter.** It was originally a proxy for "deliberate
  staging". The archive correlation does that job better, and the concentration test actively
  excluded structure-preserving collection (`robocopy /e`, `xcopy /s`). Retained as the
  `FilesPerFolder` context column.

- **Restricting archive anchors to known archiver processes** was the single largest noise
  reduction — from ~40,000 to ~300 correlated pairs per week. Most "archive creation" events
  are not archiving at all: Outlook writing `.zip` attachments to cache, Intune writing `.cab`,
  Office temp files. The `ArchiveProcess` column name is misleading; it means "process that
  created a file with an archive extension".

- **Severity is static, not computed in-query.** Deliberate. A hand-weighted score baked into
  KQL is unfalsifiable and obscures the reasoning from the analyst. `MatchReason` gives the
  discrete condition instead.

- **`explorer.exe` in the archiver allow-list** accounted for ~98% of pre-exclusion volume and
  remains the weakest entry. It is retained because it covers native Windows zip creation, the
  most accessible archiving method on any endpoint. First lever to pull if volume climbs.

## 10. Review schedule

| Task | Frequency |
|---|---|
| Audit exclusions (invert each `not()` clause, confirm still catching only what was intended) | Monthly |
| Review alert volume and FP rate | Monthly |
| Re-test true positive generation | Quarterly |
| Revisit 7.3 once Microsoft respond | On response |

## 11. Related

- Hunting query: same logic with location exclusions removed — covers the 7.1 gap for
  investigation and leaver review. [link]
- [Rule 1 — mass file creation — CHECK: may be affected by the `FolderPath` issue in section 9]
- [Unusual locations hunting query — same check applies]



































# Hunting Query: Mass File Creation in Unusual Location

**Status:** Hunting query — not deployed as a scheduled analytics rule
**Data source:** DeviceFileEvents (Microsoft Defender for Endpoint via Defender XDR connector)
**Platform:** Microsoft Sentinel — Logs / Hunting
**Owner:** [OWNER]
**Created:** [DATE]
**Last reviewed:** [DATE]
**Review cadence:** Quarterly, or after any significant endpoint tooling change

---

## Purpose

Identifies bulk creation of document-type files in locations outside network shares
and standard user profile folders. Intended to surface potential data staging prior
to exfiltration — a user or process gathering documents into a location that is not
where work normally happens.

Maps to MITRE ATT&CK:
- **T1074.001** — Data Staged: Local Data Staging
- **T1005** — Data from Local System

---

## Hypothesis

An actor collecting data for exfiltration will gather files into a location they
control, rather than leaving them distributed across normal working locations.
Where an organisation's legitimate bulk file activity occurs predominantly on
network shares and in synced profile folders, document creation outside those
locations at volume is anomalous and worth review.

---

## Detection logic

Fires on a single account, on a single device, creating **[THRESHOLD]** or more
document-type files within a **20-minute window**, where the destination is:

- Not a UNC / network share path
- Not within a standard user profile folder (Documents, Downloads, Desktop, OneDrive sync roots)
- Not matched by the environment-specific exclusion set (see below)

File types in scope: Office documents, PDFs, mail items (msg, eml, pst, ost),
text and CSV, and archive formats.

A sliding window grid (four overlapping 20-minute windows spaced 5 minutes apart)
is used so that bursts straddling a bin boundary are not split. Coverage guarantee
is 15 minutes — any burst shorter than that falls entirely within at least one window.

---

## Why this is a hunting query and not a deployed rule

This was originally scoped as a scheduled analytics rule. It was **not deployed**
after tuning demonstrated that the signal cannot support unattended alerting in
this environment.

**Root cause:** DeviceFileEvents records that files were created, but not where they
came from or whether a human initiated the action. There is no FileRead ActionType,
no source path, and no interactive-versus-programmatic indicator. Benign bulk file
creation (archive extraction, application caching, attachment handling, users
working outside standard folders) and malicious staging are the same shape in this
table on every available dimension: volume, location, folder count, file type mix.

**Tuning outcome:** After approximately 20 exclusions covering process/path
combinations, the query still produced roughly 2 results per day at a threshold of
200 — effectively all benign. At that precision an alert queue would be closed
without being read, which degrades response to unrelated alerts.

**Retained value:** With a human reviewing output in context, the query reliably
surfaces the right activity. It is effective for periodic review, as investigative
context on an account already under scrutiny, and as a contributing signal
alongside identity or process anomalies.

---

## Known limitations and blind spots

| Limitation | Detail |
|---|---|
| No source visibility | Cannot distinguish a copy from a network share, an archive extraction, or a download. All appear as file creation at the destination. |
| Single archive invisible | One large .7z containing thousands of documents is a single file event and will never meet the threshold. |
| Slow staging invisible | Activity spread below the threshold within any 20-minute window is not detected. |
| Excluded paths are documented blind spots | Any path/process combination in the exclusion set is a location an actor could stage in without detection. The list is enumerable by anyone with Sentinel read access. |
| MDE telemetry is not exhaustive | The sensor applies its own filtering and may suppress events under high write volume. Absence of events is not absence of activity. |
| Staging is not exfiltration | Nothing has left the environment when this fires. It is a precursor signal only. |
| [IF C:\ RESTRICTION KEPT] Scoped to system drive | The `FolderPath startswith "C:\"` filter excludes secondary and removable drives, removing USB staging coverage. |

---

## Exclusions

The exclusion set is environment-specific and was derived empirically from 7 days
of baseline data. It consists of two categories:

**Structural exclusions** — stable, low-maintenance:
- Office lock artefacts (`~$` prefix)
- PowerShell transcripts
- Machine accounts (`$` suffix)
- Recycle Bin
- UNC paths and standard user profile folders

**Inventory exclusions** — environment-specific process/path combinations covering
endpoint management agents, Office components, capture and diagnostic tooling, and
application temp/cache paths.

> **Maintenance note:** Inventory exclusions require review whenever endpoint
> tooling changes (Office updates, agent version changes, new software deployments).
> Consider migrating these to a Sentinel watchlist with per-entry owner and review
> date rather than maintaining them inline in query text.

---

## How to run

1. Sentinel → Logs (or Hunting → New query)
2. Paste the query
3. Adjust `Lookback` as required — 7 days is the default; reduce to 3 days if the
   query times out
4. Review results sorted by `FilesCreated` descending

**Performance:** A 7-day run typically takes 30+ seconds due to the sliding window
grid multiplying rows 4x over a high-volume table. For faster iteration, replace the
grid with a static `bin(Timestamp, Bucket)` — boundary precision is not important
for exploratory hunting.

---

## Triage guidance

Review these columns in order:

| Column | What it tells you |
|---|---|
| `InitiatingProcessFileName` | The strongest single indicator. Archive tools, browsers, and Explorer are usually benign. Scripting or admin tooling (robocopy, powershell, cmd, curl) warrants investigation. |
| `FolderSample` | Where the files landed. Application cache and temp paths are typically benign. User-created directories at drive root or in unusual locations are worth reading. |
| `DistinctExt` | A burst spanning many file types is more consistent with deliberate collection than a homogeneous extraction or application artefact. |
| `Actor` | Cross-reference against leavers, PIP, or investigation lists if available. |
| `OutsideHours` | Activity outside 08:00–18:00 is not inherently suspicious but adds weight. |
| `Labels` | Sensitivity labels where MIP coverage exists. Labelled content materially changes the significance. |

**Common benign patterns:**
- Archive extraction to a working folder (`7zG.exe`, `explorer.exe`)
- Application temp staging in `AppData\Local\Temp\<GUID>\`
- Outlook attachment preview and cloud attachment handling
- Users who habitually work in non-standard local directories rather than
  Documents or a network share

---

## Recommended follow-on work

This signal becomes viable for alerting when paired with a second, independent
dimension:

1. **Process anomaly** — flag processes that are unusual *for that specific user*
   rather than globally. A process baseline is a stronger discriminator than
   location because it is harder for benign activity to imitate.
2. **Per-user volume baseline** — replace the static threshold with a comparison
   against the user's own historical activity. Requires summary rule infrastructure
   writing to a custom table.
3. **Identity correlation** — bulk file creation coinciding with a first-seen
   sign-in country, impossible travel, or unusual device for that account.
4. **Egress correlation** — USB device connection, personal cloud upload, or
   archive creation following the burst.

---

## Change log

| Date | Change | By |
|---|---|---|
| [DATE] | Created as hunting query following tuning of scheduled rule variant | [OWNER] |





























































# Analytics Rule: Mass Sensitive File Read Followed by Mass File Creation

**Status:** Draft / provisional — deployed disabled or audit-only pending dry-run validation
**Author:** [your name]
**Date created:** 2026-09-14
**Last updated:** 2026-09-14

---

## 1. Summary

Detects an account reading a large, tunable number of Purview-labeled sensitive
document/archive files, followed by that same account creating a large, tunable
number of document/archive files on the same device, within approximately 30
minutes. Archive file creation (zip, 7z, rar, etc.) during the window is surfaced
as informational enrichment on the alert — it is not required for the alert to fire.

**Intended use case:** identify potential collection-then-staging behaviour ahead
of data exfiltration — e.g. a compromised account or insider reviewing/copying a
large volume of sensitive material and then repackaging or relocating it.

---

## 2. Hypothesis

An account exhibiting an unusually large burst of sensitive-labeled file reads,
followed shortly after by an unusually large burst of file creation on the same
device, is more likely to represent deliberate data collection/staging than
routine work.

---

## 3. Known scope limitation — read this before relying on this rule (critical)

**`SensitiveFileRead` (`DeviceEvents`) is not a general "labeled file was opened"
signal in this environment.** Empirical testing (2026-09-14) confirmed via:

```kql
DeviceEvents
| where ActionType == "SensitiveFileRead"
| where TimeGenerated > ago(14d)
| summarize Count = count() by InitiatingProcessFileName
| order by Count desc
```

...that this ActionType is generated almost entirely by **[document management
app — name it]** and **[PDF viewer/editor — name it]**, with a smaller number of
other processes also present. Opening a labeled Word document directly in Word
did **not** generate this event during testing.

**Practical effect:** this rule detects mass access to sensitive-labeled files
**specifically through the applications above**. It does **not** currently detect:

- Bulk file collection via command-line tools (Robocopy, PowerShell, xcopy, etc.)
  — **not yet empirically tested**; treat as unconfirmed, not as "safe," until
  verified in this environment (see Section 9, Open Items).
- Sensitive file access via any process that does not emit `SensitiveFileRead`.
- A single large archive created from many source files (see Section 4).

**This is a genuine detection gap, not a tuning issue.** If the threat scenario
of concern involves bulk copy via scripting/CLI tools or remote-session tooling
that doesn't touch files through the apps above, this rule will not see the read
half of the correlation and will not fire, regardless of read volume. This has
been flagged to [manager name] as a scoping decision requiring sign-off, not
something resolved unilaterally in this design.

---

## 4. Additional known blind spots and assumptions (mandatory — Palantir ADS)

- **Single-archive staging is not detected.** If an attacker reads N sensitive
  files and creates one archive containing them, `CreateCount` for that action
  is 1, which will never clear `CreateThreshold` regardless of how low it is
  set. This rule detects "many loose document creates," not "one compressed
  container." A separate rule design (small `CreateCount`, but the created
  file is an archive, sized large relative to device baseline) would be needed
  to cover this pattern. Not built as of this version.
- **Requires Purview sensitivity labeling to be actively applied.** If a
  sensitive file is not labeled, `SensitiveFileRead` will never fire on it,
  regardless of actual content sensitivity. Coverage is bounded by labeling
  coverage, which has not been independently audited as part of this rule's
  development.
- **Process-based exclusions were deliberately NOT applied to general-purpose
  interpreters** (`powershell.exe`, `cmd.exe`, `explorer.exe`, etc.), because
  doing so would exclude the exact tooling a remote-access actor is likely to
  use. Expect residual noise from legitimate scripted bulk operations using
  these processes; this is the primary remaining tuning burden (see Section 9).
- **`InitiatingProcessAccountName` can be empty** for SYSTEM/service-context
  file operations (~0.016% of `DeviceFileEvents` `FileCreated` volume measured
  at build time) — these rows are silently dropped from the join. Considered
  negligible.
- **An attacker aware of label-based DLP would target unlabeled copies of
  sensitive data**, or use an access path that doesn't trigger
  `SensitiveFileRead` at all. This detection assumes the attacker either
  doesn't know this or has no choice but to go through a label-aware
  application. It is not resilient to a sophisticated actor who avoids this.
- **Filename/content correlation between the read set and the create set is
  NOT implemented in this version.** `DeviceEvents` does not expose a file
  hash field for `SensitiveFileRead`, ruling out hash-based correlation
  entirely. A filename-overlap enrichment (does the same filename appear in
  both the read burst and the create burst) was prototyped but not included
  in this release — see Section 9.

---

## 5. Query (production, with dedup logic)

```kql
let Lookback = 90m;                 // correlation window — wider than RunFrequency
let RunFrequency = 15m;             // MUST match the rule's actual "Run query every" setting
let ReadThreshold = 100;            // TUNE — see Section 7
let CreateThreshold = 100;          // TUNE — see Section 7
let WindowMinutes = 30;
let DocumentExtensions = dynamic(["doc","docx","xls","xlsx","ppt","pptx","pdf","csv","txt","rtf","odt","ods","odp"]);
let ArchiveExtensions = dynamic(["zip","7z","rar","tar","gz","bz2","cab","iso"]);
let CountedExtensions = array_concat(DocumentExtensions, ArchiveExtensions);
let ExcludedProcesses = dynamic([/* current exclusion list */]);
let ExcludedAccounts = dynamic(["SYSTEM", "NETWORK SERVICE"]);
//
let Reads =
    DeviceEvents
    | where TimeGenerated > ago(Lookback)
    | where ingestion_time() > ago(RunFrequency)
    | where ActionType == "SensitiveFileRead"
    | where InitiatingProcessAccountName !in (ExcludedAccounts)
    | where InitiatingProcessFileName !in (ExcludedProcesses)
    | extend FileExt = tolower(extract(@"\.([0-9a-z]+)$", 1, FileName))
    | where FileExt in (CountedExtensions)
    | extend Bin = bin(TimeGenerated, 30m)
    | summarize ReadCount = count(),
                FirstRead = min(TimeGenerated),
                LastRead = max(TimeGenerated),
                SampleReadFiles = make_set(FileName, 10),
                ReadFolders = make_set(FolderPath, 10),
                DistinctReadFolders = dcount(FolderPath),
                ReadProcesses = make_set(InitiatingProcessFileName, 5),
                DistinctReadProcesses = dcount(InitiatingProcessFileName)
          by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, Bin
    | where ReadCount >= ReadThreshold
    | extend JoinBin = pack_array(Bin - 30m, Bin, Bin + 30m)
    | mv-expand JoinBin to typeof(datetime);
//
let Creates =
    DeviceFileEvents
    | where TimeGenerated > ago(Lookback)
    | where ingestion_time() > ago(RunFrequency)
    | where ActionType == "FileCreated"
    | where InitiatingProcessAccountName !in (ExcludedAccounts)
    | where InitiatingProcessFileName !in (ExcludedProcesses)
    | extend FileExt = tolower(extract(@"\.([0-9a-z]+)$", 1, FileName))
    | where FileExt in (CountedExtensions)
    | extend Bin = bin(TimeGenerated, 30m)
    | summarize CreateCount = count(),
                FirstCreate = min(TimeGenerated),
                LastCreate = max(TimeGenerated),
                SampleCreateFiles = make_set(FileName, 10),
                SampleCreateFolders = make_set(FolderPath, 10),
                DistinctCreateFolders = dcount(FolderPath),
                CreateProcesses = make_set(InitiatingProcessFileName, 5),
                DistinctCreateProcesses = dcount(InitiatingProcessFileName),
                ArchiveCount = countif(FileExt in (ArchiveExtensions)),
                ArchiveFiles = make_set_if(FileName, FileExt in (ArchiveExtensions)),
                ArchiveFolders = make_set_if(FolderPath, FileExt in (ArchiveExtensions))
          by DeviceId, InitiatingProcessAccountName, Bin
    | where CreateCount >= CreateThreshold;
//
Reads
| join kind=inner (Creates) on DeviceId, InitiatingProcessAccountName, $left.JoinBin == $right.Bin
| extend GapMinutes = datetime_diff('minute', FirstCreate, LastRead)
| extend AbsGapMinutes = abs(GapMinutes)
| where GapMinutes between (-5 .. WindowMinutes)
| summarize arg_min(AbsGapMinutes, ReadCount, LastRead, SampleReadFiles, ReadFolders, DistinctReadFolders,
                     ReadProcesses, DistinctReadProcesses,
                     CreateCount, FirstCreate, LastCreate, SampleCreateFiles, SampleCreateFolders, DistinctCreateFolders,
                     CreateProcesses, DistinctCreateProcesses,
                     ArchiveCount, ArchiveFiles, ArchiveFolders,
                     DeviceName, InitiatingProcessAccountDomain)
      by DeviceId, InitiatingProcessAccountName, Bin
| project TimeGenerated = Bin, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName,
          ReadCount, LastRead, SampleReadFiles, ReadFolders, DistinctReadFolders, ReadProcesses, DistinctReadProcesses,
          CreateCount, FirstCreate, LastCreate, SampleCreateFiles, SampleCreateFolders, DistinctCreateFolders,
          CreateProcesses, DistinctCreateProcesses,
          GapMinutes = AbsGapMinutes, ArchiveCount, ArchiveFiles, ArchiveFolders
| order by TimeGenerated desc
```

**Note:** the `ingestion_time()` filters cause this query to return few/no results
when run ad hoc outside the scheduled rule (most historical records fail the
narrow `RunFrequency` ingestion window by design). Comment out both
`ingestion_time()` lines for interactive testing/hunting.

---

## 6. Block-by-block logic

- **`Reads`** — aggregates `SensitiveFileRead` into 30-minute bins per
  device/account, scoped to document + archive extensions, exclusions applied
  pre-aggregation. The `JoinBin` triple-expansion (bin ± 30 min) prevents a
  burst from being lost when it straddles a bin boundary.
- **`Creates`** — same aggregation shape against `DeviceFileEvents`
  `FileCreated`. Archive-extension creates count toward `CreateCount` and are
  also separately broken out via `ArchiveCount`/`ArchiveFiles`/`ArchiveFolders`
  for enrichment.
- **Join + `GapMinutes`** — enforces the ~30 minute proximity between the read
  burst and the create burst using actual timestamps, not just shared bin
  membership.
- **Final `arg_min` summarize** — collapses the triple-bin expansion back down
  to one row per genuine device/account/bin match.
- **`ingestion_time()` gating** — see Section 8.

---

## 7. Thresholds and environment-specific values (all require tuning)

| Value | Current setting | Sensitive to |
|---|---|---|
| `ReadThreshold` | 100 | Labeling coverage; how the two label-aware apps are normally used day-to-day |
| `CreateThreshold` | 100 | Normal document creation volume for bulk-tool users vs. individual users |
| `WindowMinutes` | 30 | How quickly a real staging operation is expected to move from read to create |
| `Lookback` | 90m | Must exceed `RunFrequency`; widening increases query cost |
| `RunFrequency` | 15m | Must match the rule's "Run query every" wizard setting exactly, or dedup logic breaks |
| `DocumentExtensions` / `ArchiveExtensions` | see query | Reflects what this org considers a sensitive document/archive format — revisit if new formats come into use |
| `ExcludedProcesses` / `ExcludedAccounts` | see query | Built from 7-day hunt review on 2026-09-14; will need revisiting as new legitimate bulk tools are onboarded |

None of these values are validated against a full production baseline — they
reflect a single 7-day hunt sample and provisional exclusion pass.

---

## 8. Query frequency, lookback, and duplicate-alert handling

- **Run every:** 15 minutes
- **Lookback:** 90 minutes
- **Boundary tolerance:** the 90-minute lookback intentionally exceeds the
  15-minute run frequency so a read/create pair spanning a rule execution
  boundary is still visible on the next run.
- **Duplicate prevention:** handled via `ingestion_time()` filtering on the raw
  `Reads`/`Creates` pulls (narrowed to `RunFrequency`), separate from the wider
  `TimeGenerated`-based `Lookback` used for the correlation itself. This
  ensures a given raw event is only eligible to contribute to an alert on the
  one run during which it was newly ingested.
- **Known residual gap:** if a read event and its paired create event are
  ingested more than one run cycle apart, partial duplicate incidents remain
  possible. Mitigated via Sentinel incident grouping (see Section 10), not
  further query logic.

---

## 9. Open items / not yet done

- [ ] Confirm empirically whether Robocopy / PowerShell / other CLI copy
      operations against labeled files generate `SensitiveFileRead`. **Test
      plan:** copy labeled test files on a test device via the tool in
      question, then query
      `DeviceEvents | where TimeGenerated > ago(15m) | where DeviceName == "<test device>" | where ActionType == "SensitiveFileRead"`.
      Update Section 3 with the result.
- [ ] Escalate the Section 3 scope limitation to [manager] for explicit
      sign-off on whether current coverage is acceptable or whether a
      complementary detection (e.g. general high-volume `DeviceFileEvents`
      reads from sensitive-labeled paths, independent of app) is required.
- [ ] Add filename-overlap enrichment (`OverlapCount`/`OverlapFiles`) once the
      rule is live — compare filenames between the read burst and create burst
      within the already-small candidate set, using short (run-frequency-scale)
      windows rather than a historical hunt, to avoid the memory-limit issues
      hit during initial hunt development.
- [ ] Design a second, separate detection for the single-large-archive staging
      pattern (Section 4) — not covered by this rule.
- [ ] Continue tightening `ExcludedProcesses`/`ExcludedAccounts` against live
      alert output once the rule is in dry-run, using folder-path-based
      exclusions in preference to process-name exclusions where possible
      (see Section 4 — general interpreters intentionally not excluded).
- [ ] Verify "Lookup data from the last" behaviour in the current Sentinel
      portal version against a hardcoded `ago()` lookback in the KQL itself —
      unconfirmed whether the wizard field applies as an additional hard
      filter or is purely cosmetic once the query defines its own window.

---

## 10. Rule configuration (wizard reference)

**General**
- Tactics: Collection
- Techniques: T1005 (Data from Local System), T1560 (Archive Collected Data)
- Severity: **Medium** (do not promote until dry-run validated)
- Status: disabled / audit-only until dry-run period complete

**Set rule logic**
- Run query every: 15 minutes
- Lookup data from last: 90 minutes
- Trigger: alert when number of results > 0
- Event grouping: group all events into a single alert

**Entity mappings**

| Entity | Identifier | Column |
|---|---|---|
| Account | Name | `InitiatingProcessAccountName` |
| Account | NTDomain | `InitiatingProcessAccountDomain` |
| Host | HostName | `DeviceName` |

*(File entity intentionally not mapped — file-related fields are arrays with
no single representative value; see Custom Details instead.)*

**Custom details**

`DeviceId`, `ReadCount`, `CreateCount`, `GapMinutes`, `SampleReadFiles`,
`SampleCreateFiles`, `ReadFolders`, `SampleCreateFolders`,
`DistinctReadFolders`, `DistinctCreateFolders`, `ReadProcesses`,
`CreateProcesses`, `ArchiveCount`, `ArchiveFiles`, `ArchiveFolders`

**Incident settings**
- Create incidents from alerts: On
- Alert grouping: On — group if all entities match
- Group alerts triggered within: 1 hour (mitigates the ingestion-boundary
  residual duplicate risk noted in Section 8)

**Automated response**
- None configured. Do not attach a playbook until the dry-run period confirms
  low false-positive rate.

---

## 11. Testing / validation before production enablement

1. Deploy to a test workspace or run disabled/audit-only in production for a
   minimum 3–5 day dry-run.
2. Generate a true positive: on a test device, use the confirmed label-aware
   application(s) from Section 3 to open 100+ labeled sensitive documents in
   quick succession, then create 100+ new document files in the same session.
   No stock Atomic Red Team test exists for this chain; this requires a
   custom simulation.
3. Confirm the simulated activity surfaces in query output with expected
   `ReadCount`/`CreateCount`/`GapMinutes` before trusting results against real
   traffic.
4. Review dry-run output for false-positive sources beyond current exclusions
   — expected candidates: legitimate scripted bulk operations run through
   `powershell.exe`/`cmd.exe` (not excluded by design, see Section 4).

---

## 12. Change log

| Date | Change |
|---|---|
| 2026-09-14 | Initial hunt query built; iterative exclusion tuning; document/archive extension scoping added; `SensitiveFileRead` scope limitation discovered and documented; rule drafted for publish (disabled/audit-only) |








































# KB: Archive Creation with Password/Header Encryption Protection

**Rule type:** Microsoft Sentinel Scheduled Analytics Rule
**Data source:** Microsoft Defender for Endpoint — `DeviceProcessEvents`
**Status:** [Draft / Shadow / Production — update on deployment]
**Owner:** [Name]
**Last reviewed:** [Date]
**Related rules:** Large Archive Creation (size-based — see KB, largely superseded by this rule for TA-focused hypotheses)

---

## 1. Summary

This rule detects the use of 7-Zip or WinRAR to create a **password-protected** or **header-encrypted** archive on an endpoint. It fires per invocation of the archiving tool, splitting the result into two confidence tiers based on the encryption method used, and excludes one known legitimate automated process identified during tuning.

**In one sentence:** an actor with access to this machine used an archiver with a password/encryption switch, which has no ordinary business justification at the volume observed and is a known technique for defeating DLP content inspection before data leaves the environment.

---

## 2. Why this rule exists — the hypothesis

**Threat hypothesis:** a threat actor — external, having gained remote access, or an insider with hands-on access — is staging data for exfiltration. Password-protecting the archive is a deliberate step: DLP and content-inspection tooling generally can't see inside an encrypted archive, so this is a way to move data past those controls undetected.

This rule was built as part of a broader effort to replace a single, overly broad "large archive creation" detection with several narrower, higher-confidence rules, each targeting a distinct piece of adversary behaviour rather than one rule trying to catch everything via file size.

### Why we moved away from file size as the primary signal

An earlier version of this detection logic gated on `FileSize` in `DeviceFileEvents`. Testing showed two independent problems with that approach:

1. **It was too noisy.** In a business where staff routinely archive large volumes of data as part of normal work, raising the size threshold did not meaningfully separate legitimate from suspicious activity — it just moved the noise floor without improving fidelity.
2. **It was unreliable in the other direction.** Controlled testing found that `DeviceFileEvents.FileSize` frequently does not reflect a file's true final size. A 1.2GB test archive was recorded with a `FileSize` of ~840KB, because MDE's file telemetry is sampled and the value reflects whatever the size was at the moment a particular event was captured — often very early in the write. This means a size-based rule can silently miss the exact activity it exists to catch, independent of where the threshold is set.

Conclusion: for this hypothesis, **file size is not a reliable gate, in either direction.** This rule does not use it.

---

## 3. What the rule actually does

### Data source choice: `DeviceProcessEvents`, not `DeviceFileEvents`

The password/encryption switch is a **command-line argument** to the archiving tool. It exists in the process-creation event, once, reliably, at the moment the tool is launched — regardless of how the resulting file is written, sampled, or renamed afterward. This sidesteps the file-size reliability problem entirely: we are detecting the *action* (an operator chose to encrypt an archive), not trying to infer it from the *artifact*.

### Logic, plain English

1. Look for process creation events where the binary is a known archiver (`7z.exe`, `7za.exe`, `7zr.exe`, `7zg.exe`, `rar.exe`, `winrar.exe`) — matched on either the actual filename **or** the file's internal version metadata (`ProcessVersionInfoOriginalFileName`), so a renamed copy of the binary is still caught.
2. Check the command line for a password switch (`-p...`) or a header-encryption switch (`-hp...` or `-mhe=on`).
3. If neither is present, discard the event — this is the bulk of all archiving activity and is not what this rule is for.
4. If either is present, exclude one specific known-legitimate combination identified during tuning (see Section 5).
5. Classify what's left as `HeaderEncrypted` (stronger signal) or `PasswordOnly` (weaker but still uncommon), and assign severity accordingly.

### Why two severities, one rule

Header encryption (`-hp` or `7-Zip's -mhe=on`) encrypts filenames and archive metadata, not just file contents — it hides *what* was collected, not only its contents. That's a more deliberate evasion step than a plain password, and our own tenant data supports treating it very differently: fewer than 10 occurrences across 30 days, against roughly 200 for password-only. The rule uses Sentinel's dynamic alert severity (`alertDetailsOverride`) to assign `High` to `HeaderEncrypted` and `Medium` to `PasswordOnly` from a single query, rather than splitting into two rules — this keeps one query, one exclusion list, and one place to maintain both.

---

## 4. What this rule is *not* designed to catch

Documenting known blind spots deliberately, so gaps are understood rather than assumed away.

- **GUI-driven password protection that doesn't shell out with visible switches.** 7-Zip's GUI is known to invoke the console binary with the same command-line arguments, so it is expected to be caught. This has **not been independently confirmed for WinRAR's GUI** in our environment — if WinRAR's GUI encrypts without exposing an equivalent switch in a child process command line, that path is currently invisible to this rule. Flagged as an open verification item (see Section 7).
- **Interactive password prompts with no argument.** A bare `-p` with no attached value still matches (the regex accepts zero characters after `-p`), so this specific case is covered — but any method that avoids a command-line switch entirely (e.g., a GUI dialog with no corresponding child-process argument) is not.
- **Non-supported tools.** WinZip CLI syntax, `tar` piped through `openssl`, and PowerShell's native `Compress-Archive` (which has no built-in password support) are all outside this rule's scope. A TA using `System.IO.Compression` directly from a script to build an encrypted archive would not trigger this.
- **Renamed binaries with stripped version metadata.** The `ProcessVersionInfoOriginalFileName` fallback catches a renamed `7z.exe` in the common case, but this is version-resource metadata, not a cryptographic signature — it can be altered by a sufficiently deliberate operator and should not be treated as a guarantee.
- **Legitimate business use.** Legal, HR, Finance, or vendor-facing teams routinely password-protect archives for external delivery (contracts, payroll data, deliverables under NDA). This rule does not distinguish intent — it flags the *behaviour*. Distinguishing intent is the analyst's job at triage, informed by the custom details on the alert (source path, parent process, remote session flag, account).

**This rule detects a technique, not a verdict.** Every alert requires human triage. It is not, on its own, evidence of malicious activity — it is evidence of a behaviour that is rare enough in our environment to be worth a look.

---

## 5. Tuning history and exclusions

| Date | Change | Evidence |
|---|---|---|
| [Date] | Initial validation query run over 30 days | Baseline: `None` (no password switch) ≈ 6,000+ invocations/30d; `PasswordOnly` ≈ 200/30d; `HeaderEncrypted` <10/30d |
| [Date] | Excluded `[Account]` + `[Tool]` + `[Parent process]` tuple | Breakdown query showed this single combination accounted for the majority of the ~200 `PasswordOnly` hits. Confirmed as [describe the legitimate process — e.g., "the nightly backup job, which password-protects its output archive before shipping it to offsite storage"]. |

**Why this exclusion is scoped to a tuple (account + tool + parent process), not a path.** Excluding a folder path is comparatively easy for an attacker to abuse — staging activity in a directory you've told the detection to ignore is a well-known evasion pattern. Tying the exclusion to a specific account acting as a specific parent process is a much narrower door: an attacker would need to already be operating in that service account's context to inherit the exclusion, which represents a materially larger compromise than this rule alone is meant to catch.

**Review commitment:** this exclusion should be reviewed [quarterly / on a defined cadence] to confirm the underlying automated process is still active and unchanged. Exclusions for decommissioned services are a common source of silent, permanent coverage gaps — remove this line if the process it covers is retired.

---

## 6. Triage guidance

When this alert fires, check in this order:

1. **`PasswordMethod`.** `HeaderEncrypted` warrants immediate, full attention given its rarity. `PasswordOnly` warrants a quick context check before deciding on urgency.
2. **`InitiatingProcessParentFileName`.** Descends from `explorer.exe`? Consistent with an interactive user action. Descends from `powershell.exe`, `cmd.exe`, `wscript.exe`, a remoting host (`wsmprovhost.exe`), or an unexpected parent? Materially more suspicious.
3. **`IsInitiatingProcessRemoteSession`.** True means this happened under an RDP session — raises priority.
4. **`NonStandardBinary`.** True means the executable name doesn't match its internal version metadata — i.e., a renamed archiver. This alone is a strong indicator regardless of the other fields.
5. **Source paths in `ProcessCommandLine`.** Is the account archiving its own files, or someone else's / a shared location it doesn't normally touch?
6. **Business context.** Does the account, team, or role have a known, legitimate reason to send password-protected archives externally (legal, vendor delivery, etc.)? If yes and it's a recurring, identifiable pattern, consider it a candidate for a scoped exclusion per Section 5 — don't let it sit as recurring noise.

**A true positive typically looks like:** the password/encryption switch present, *plus* one or more of: a non-interactive parent process, a remote session, a non-standard binary, or a source path inconsistent with the account's normal work. The password switch alone tells you *evasion intent*; the surrounding context tells you whether *this specific instance* is likely malicious.

---

## 7. Open items / follow-ups

- [ ] Confirm whether WinRAR's GUI exposes the password switch in a child-process command line (test on an isolated host: create a password-protected archive via the WinRAR GUI, inspect `DeviceProcessEvents`). If it does not, document this as a permanent, accepted blind spot rather than continuing to assume coverage.
- [ ] Confirm the exact expected value format for the Sentinel dynamic severity override (`alertDetailsOverride`) in the current portal version — string matching behaviour for this feature has changed across releases.
- [ ] Confirm NRT eligibility of `DeviceProcessEvents` if moving this rule from scheduled (10 min) to near-real-time frequency.
- [ ] Revisit whether `PasswordOnly` volume changes meaningfully after a full quarter (seasonal business processes — e.g., year-end reporting — may not have appeared in the initial 30-day sample).

---

## 8. Related rules and context

This rule is one of a small family of rules replacing a single broad size-based archive detection, each targeting a distinct behaviour associated with the same overall hypothesis (data staging/exfiltration by an actor with access to an endpoint):

- **Archive Creation with Password/Header Encryption Protection** — this rule
- **Large Archive Creation (size-based)** — retained as a hunting query / workbook feed only; not used as a standalone incident-generating rule due to the reliability and noise issues described in Section 2
- [Add as built: Non-standard archiver binary path / non-interactive parent process rule]
- [Add as built: Credential/database material archived rule]
- [Add as built: Rapid succession / multi-archive creation rule]

Splitting the original rule into this family, rather than continuing to tune one rule with an ever-growing exception list, was a deliberate decision — each behaviour has a different false-positive population and a different tuning cycle, and combining them was making all of them harder to maintain and trust.




































# RMM Domain Connection Detection — KB

2026-09-22 · @Someone

## Overview

This rule alerts on network connections from managed devices to domains associated with Remote Monitoring and Management (RMM) or remote-access tooling — for example TeamViewer, AnyDesk, and Tailscale.

**Why it exists:** RMM tools are dual-use. They are legitimate for IT administration but are also one of the most common mechanisms used by attackers, and by scam/fraud actors coaching victims, to establish hands-on-keyboard remote access to a compromised endpoint. Unexpected outbound connections to these domains are a strong behavioral signal, particularly from devices or accounts with no legitimate reason to use RMM software.

**What's new in this version:** the rule now supports an exclusions watchlist so that specific subdomains, optionally scoped to a user and/or an expiry date, can be suppressed without editing the detection logic itself. This addresses vendors (e.g. content-delivery or marketing subdomains) that share a parent domain with a genuine remote-access product but aren't remote-access traffic themselves, and short-lived, approved use of a normally-alerted tool by helpdesk or IT staff.

## Scope and data sources

| Item | Detail |
| --- | --- |
| Table | `DeviceNetworkEvents` (Defender for Endpoint, via Defender XDR connector) |
| Coverage | Onboarded, MDE-managed Windows/macOS/Linux devices only. Unmanaged devices and network egress not seen by the sensor (e.g. non-MDE guest devices) are not covered |
| Domain list | `RMMDomains` watchlist — the parent domains considered RMM/remote-access tooling |
| Exclusion list | `RMMExclusions` watchlist — subdomains, optionally scoped by user and/or expiry, suppressed from alerting |
| Field matched | `RemoteUrl`, parsed to a bare hostname |
| Not covered | Direct-IP connections, connections where `RemoteUrl` is empty, and RMM traffic on domains not yet added to `RMMDomains` |

## How the detection works

The rule runs every 5 minutes and evaluates events by `ingestion_time()`, not `TimeGenerated`, with the ingestion window matched exactly to the run frequency (no overlap). This is a deliberate design choice: the rule alerts per event rather than per incident, so an overlapping window would create duplicate alerts for the same connection. The trade-off is that an event which lands in a scheduling or ingestion-delay gap between two runs can be missed rather than duplicated — acceptable here because RMM sessions typically generate repeated connections, so a single missed slice is usually caught on the next one.

**Match logic, in order:**

1. Events with a non-empty `RemoteUrl` matching any domain in `RMMDomains` (substring pre-filter) are pulled from the lookback window.
2. The hostname is extracted from `RemoteUrl` and matched exactly, or as a subdomain, against the domain list — the longest matching domain wins.
3. **Exclusion check (new):** each matched event is checked against `RMMExclusions`. An event is suppressed if its host equals or is a subdomain of an excluded domain, AND the exclusion is either unscoped or matches the event's user (UPN), AND the exclusion has not expired as of the event's timestamp. Exclusions always win over inclusions.
4. Surviving events are aggregated by domain, device and account into one alert, carrying first/last seen, observed hosts, URLs, IPs, processes and action types.

## Exclusions — the `RMMExclusions` watchlist

SearchKey: `Domain`. Columns:

| Column | Required | Rules |
| --- | --- | --- |
| `Domain` | Yes | Lowercase hostname, no scheme/path/wildcard. Suppresses that host and every subdomain of it |
| `User` | No | UPN as it appears in telemetry. Blank = applies to all users |
| `ExpiresOn` | No | `yyyy-MM-dd` ONLY. Blank = permanent. The listed day is inclusive |
| `Reason` | Convention | Not read by the rule; used for audit and the health check |
| `Owner` | Convention | Not read by the rule; used for audit and the health check |

**Example rows:**

```csv
Domain,User,ExpiresOn,Reason,Owner
cdn.engage.teamviewer.com,,,Marketing CDN - not remote access,jsmith
goto.com,user1@contoso.com,2026-09-30,Helpdesk trial,jsmith
```

**Behavior to know:**

- A non-ISO date (e.g. `30/09/2026`) is not silently coerced. The row is dropped, so the exclusion does NOT apply and the traffic alerts. This fails toward alerting rather than toward an unintended permanent suppression.
- User scoping only works where the sensor actually populates the account UPN on the connection. Agent-style processes running as SYSTEM or a service account may have no UPN, in which case a user-scoped exclusion for that traffic will never match — it will continue to alert.
- Exclusions always take priority over the domain list; there is no "include overrides exclude" case.
- Write access to this watchlist should be restricted — anyone who can edit it can blind the detection for a given domain, user or window.

## Triage guidance

1. **Check the entities.** The alert carries the device, account, observed hostname(s), remote IP, initiating process and a sample URL.
2. **Is this account/device expected to use RMM tools?** Helpdesk, IT admins and MSP integrations are the common legitimate case. If yes and it recurs, consider a scoped, expiring exclusion rather than closing the alert repeatedly (see Maintenance below).
3. **Is the process a browser or an agent binary?** A browser hitting a vendor's marketing or support page is lower concern than a background agent process (e.g. `AnyDesk.exe`, `TeamViewer_Service.exe`) establishing a session with no user context.
4. **Cross-check for known-benign infrastructure.** CDN, analytics or marketing subdomains of an RMM vendor's parent domain are false positives by design of the parent-domain match — these are exclusion-list candidates, not incidents.
5. **If unexpected:** treat as potential attacker-established remote access. Escalate per standard incident handling — isolate the device if warranted, and review `DeviceProcessEvents` and sign-in logs for the account around the alert window.
6. **Remember what this rule does not see:** direct-IP connections, RMM services on domains not yet on `RMMDomains`, and self-hosted remote-access infrastructure. A clean alert history for a device is not proof of no remote-access activity.

## Known limitations and blind spots

- **Direct-IP connections are not seen.** The rule matches on hostname parsed from `RemoteUrl`; RMM traffic that never resolves through a matched domain string is invisible to it.
- **Domain-list dependent.** Coverage is only as good as `RMMDomains`. Self-hosted or bespoke remote-access tooling on an unlisted domain will not trigger.
- **No overlap window (by design).** An event that falls between two 5-minute runs — due to execution jitter or ingestion visibility lag — can be missed rather than caught on a later run. Acceptable for a Medium-severity, dual-use signal where sessions typically produce repeated connections; would need reconsideration for a higher-severity, single-shot detection requirement.
- **User-scoped exclusions depend on the UPN field being populated.** Where it is not (commonly SYSTEM/service-context agent processes), a user-scoped exclusion silently has no effect and the traffic continues to alert. This fails safe (toward alerting) but should be understood before relying on user scoping for a specific process.
- **Exclusions are a deliberate blind spot by definition.** Any domain, user or window covered by an active exclusion will not alert for that traffic. A compromised account covered by a user-scoped exclusion is invisible for that service until the exclusion expires. Watchlist write access should be restricted, and edits should be auditable.
- **Silent expiry.** An expired exclusion reverts to alerting with no notification. Run the watchlist health check (Maintenance, below) on a schedule so this doesn't surface as an unexplained new alert.

## Maintenance

**Adding a new RMM domain to detect:** add its parent domain (e.g. `screenconnect.com`) as a row to `RMMDomains`. No rule changes needed.

**Adding an exclusion:**

1. Confirm the subdomain is genuinely not remote-access traffic (or the user/window is genuinely approved).
2. Add a row to `RMMExclusions` — `Domain` at minimum; `User` and `ExpiresOn` if scoping is wanted. Use `yyyy-MM-dd` only.
3. Fill `Reason` and `Owner` — required for audit, not read by the rule.
4. Prefer an expiring exclusion over a permanent one for anything tied to a specific approval (helpdesk trial, temporary vendor use). Permanent exclusions should be reserved for infrastructure that will never be remote-access traffic (CDN, marketing subdomains).

**Periodic review — run this query and review anything not `Active`:**

```kql
_GetWatchlist("RMMExclusions")
| extend Domain = tolower(trim(@"[\s\*\.]+", tostring(column_ifexists("Domain", SearchKey))))
| extend ExRaw = trim(@"\s+", tostring(column_ifexists("ExpiresOn", "")))
| extend Status = case(
      isempty(ExRaw), "Permanent - review periodically",
      not(ExRaw matches regex @"^\d{4}-\d{2}-\d{2}$") or isnull(todatetime(ExRaw)), "INVALID DATE - exclusion NOT applied",
      todatetime(ExRaw) + 1d < now(), "Expired",
      todatetime(ExRaw) < now() + 14d, "Expiring within 14d",
      "Active")
| project Domain, User = column_ifexists("User", ""), ExpiresOn = ExRaw, Status,
          Reason = column_ifexists("Reason", ""), Owner = column_ifexists("Owner", "")
| order by Status asc
```

Recommended cadence: monthly, or before any compliance/audit review of standing exceptions. Any row showing `INVALID DATE` means the exclusion is not being applied at all — fix the date format immediately.

## Change history

| Date | Change |
| --- | --- |
| 2026-09-22 | Added `RMMExclusions` watchlist support: per-subdomain, optionally user- and date-scoped suppression, applied before alert aggregation. Ingestion window confirmed at exactly the run frequency (no overlap) to preserve alert-per-event behavior. |


















