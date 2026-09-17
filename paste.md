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
