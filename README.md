# OAuth Redirect Abuse Detection Lab

A hands-on lab deploying Sentinel detection content for OAuth redirect abuse,
with explicitly opt-in Entra hardening — the technique Microsoft described in
its [March 2026 advisory](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/).

**Cost:** Uses an existing Sentinel workspace; ingestion, retention, and
licensing charges still apply.

**Cleanup:** Remove the lab-owned Sentinel objects and, only if applied, restore
the captured tenant consent configuration and remove the exact CA policy.

> **Blog Post:** For detailed explanations of the attack technique and detection logic, see [Detecting OAuth Redirect Abuse with Microsoft Sentinel and Entra ID](https://nineliveszerotrust.com/blog/oauth-redirect-abuse-sentinel/).

## Validation Boundary

The August 13, 2026 revision passed twenty offline contract tests, including
PowerShell parsing; mocked preview, foreign-policy rejection, apply, idempotent
rerun, partial-failure compensation, idempotent completed rollback, fresh
pre-delete drift checks, explicit confirmation cancellation, and ownership
behavior, canonical Graph casing, and fail-closed tenant/exclusion checks;
immutable-user/App-ID rule checks; standalone-to-deployed query equality;
AppAddress object/string fixtures; redirect-host matching; workbook time-range
binding; and documented Graph-permission checks. It was not deployed to a
tenant, no live Graph hardening call was made, and no live
Sentinel query or incident was validated for this revision. Rule output depends
on the target workspace's `SigninLogs`/`AuditLogs` schema, data connectors,
volume, and ingestion latency.

Run the current offline suite with `python -m unittest discover -s tests -v`.
The September 26, 2026 remediation passed 53 offline tests, including disabled
consent through apply/rerun/rollback, explicit rejection versus uncertain CA
creation, native argv/error boundaries, private report replacement, and a
2,000-principal/5,000-grant fixture using 100 read-only assignment batches.
It includes paginated Sentinel ownership/collision checks and native-command
failure tests; no Azure or Graph request is forwarded by the test harnesses.
The deployer and hardening script check Azure CLI exit codes explicitly, so a
failed read or delete is fatal even when automatic native-error handling is disabled.

A manifest already recorded as `rolled-back` supports a no-write rerun. For a
pending or applied manifest, an exact policy read returning HTTP 404 does not
prove that this rollback removed it: the script stops and retains the manifest,
just as it does for authorization or service failures. Investigate the exact
tenant and object ID before reconciling external changes; missing data and
failed authorization are never treated as successful cleanup.

---

## What Gets Deployed

| Resource | Type | Details |
|---|---|---|
| 4 Analytics Rules | Sentinel Scheduled | OAuth consent after risky sign-in, suspicious redirect URI, OAuth error patterns, bulk consent |
| 1 Workbook | Azure Workbook | OAuth Security Dashboard (consent timeline, error patterns, URI changes, top apps) |
| Optional consent policy change | Entra ID | Tenant authorization-policy update; applied only with `-ApplyHardening` |
| Optional CA Policy | Entra ID | Newly created report-only step-up policy; same-named policies are never adopted or updated |
| 5 Hunting Queries | KQL files | Delegated permissions audit, non-corporate IPs, new high-priv apps, URI inventory, token replay |
| 1 Audit Script | PowerShell | Enumerate all OAuth apps for suspicious redirect URIs and overprivileged permissions |

---

## Prerequisites

- Azure subscription with an existing **Microsoft Sentinel** workspace
- Azure CLI configured (`az login`)
- PowerShell 7.6+ (`pwsh`)
- **Microsoft Sentinel Contributor** or equivalent rule/workbook write
  permissions on the workspace **and the workbook resource group**
- **Directory.Read.All** Microsoft Graph delegated permission and a supported
  Entra role (such as **Directory Readers**) for the default read-only OAuth
  audit, including `/oauth2PermissionGrants` (omit the audit with `-SkipAudit`)
- For the tenant-wide consent-policy update used by `-ApplyHardening`:
  **Privileged Role Administrator** and **Policy.ReadWrite.Authorization**
- For the report-only Conditional Access policy used by `-ApplyHardening`:
  **Conditional Access Administrator** (or **Security Administrator**) and the
  **Policy.Read.All** plus **Policy.ReadWrite.ConditionalAccess** permissions
- **Microsoft Entra ID P2** (or equivalent suite entitlement) for sign-in-risk
  Conditional Access and full premium risk detail; connectors and retention must
  supply the required `SigninLogs` and `AuditLogs` rows
- Exact Entra object IDs for emergency-access accounts to pass through
  `-ExcludedUserIds` before applying the report-only CA policy
- The exact active Entra tenant GUID to pass through `-ConfirmTenantId`; the
  script rejects a different or missing tenant confirmation before cloud writes

The Graph permission names above describe the published endpoint permission
requirements for an appropriately consented client. An interactive Azure CLI
login uses Microsoft's first-party client and its preauthorized permissions;
this revision does not claim a live validation of those policy endpoints or
that `az login --scope Policy.*` can grant extra scopes to that first-party app.
Use `-WhatIf` to verify the exact tenant and all reads first. A failure stays
fatal and reports only a bounded provider code, never a token or raw response.
Do not add blanket token-claim gates that reject valid first-party authorization
merely because the docs list a different permission name.

The existing Sentinel workspace is a shared target. The deployment creates or
updates rules and a workbook there. Entra hardening is **off by default** because
the consent-policy change is tenant-wide and the CA policy applies to all users
except the object IDs you explicitly exclude.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/j-dahl7/oauth-redirect-abuse-sentinel.git
cd oauth-redirect-abuse-sentinel
```

### 2. Deploy

Preview first:

```powershell
./scripts/Deploy-Lab.ps1 `
  -ResourceGroup "rg-sentinel-lab" `
  -WorkspaceName "law-sentinel-lab" `
  -WhatIf
```

Default deployment writes the four Sentinel rules and workbook, then performs
a read-only Graph audit and writes `oauth-audit-report.csv` locally. It does not
apply tenant hardening:

```powershell
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"
```

To omit the audit and its local CSV:

```powershell
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -SkipAudit
```

Only after capturing the current consent-policy collection, verifying the
tenant, reviewing report-only impact, and identifying emergency-access account
object IDs, opt in to hardening:

```powershell
./scripts/Deploy-Lab.ps1 `
  -ResourceGroup "rg-sentinel-lab" `
  -WorkspaceName "law-sentinel-lab" `
  -ApplyHardening `
  -ConfirmTenantId "<verified-tenant-guid>" `
  -ExcludedUserIds @("<break-glass-object-id-1>","<break-glass-object-id-2>")
```

The script:

1. Verifies the Sentinel workspace exists and Sentinel is enabled
2. Deploys 4 scheduled analytics rules via the Sentinel REST API
3. Deploys the OAuth Security Dashboard workbook
4. Applies OAuth hardening only when `-ApplyHardening` is present
5. Runs the OAuth app audit and saves a CSV report unless `-SkipAudit` is present

`-WhatIf` performs discovery/read calls but skips guarded cloud writes, the
ownership manifest, temporary request-body files, and the audit/CSV. It reports
missing tenant confirmation or emergency-access exclusions without applying
anything. It does not validate KQL results or CA impact. `-SkipHardening` remains only as a deprecated
compatibility switch; absence of `-ApplyHardening` is the normal safe default.
Analytics rules and the workbook use deterministic workspace-scoped IDs plus
explicit ownership markers. Deployment fails closed instead of adopting a
same-named resource or overwriting a deterministic ID whose marker does not match.

Current deployment parameters are `-ResourceGroup`, `-WorkspaceName`,
`-ApplyHardening`, `-ConfirmTenantId`, `-ExcludedUserIds`,
`-HardeningManifestPath`, `-SkipHardening` (deprecated), `-SkipAudit`,
`-Destroy`, and PowerShell's common `-WhatIf` switch.

### 3. Verify Deployment

Open **Microsoft Defender portal** > **Microsoft Sentinel** > **Analytics**:

- You should see 4 new rules prefixed with "LAB -"
- All rules should show as Enabled with Scheduled type

Open **Workbooks**:

- Find "OAuth Security Dashboard" in the list

---

## Analytics Rules

### Rule 1: OAuth Consent After Risky Sign-in (High)

Correlates `SigninLogs` risk indicators with `AuditLogs` consent events within a
15-minute window using nonempty, case-normalized Entra user object IDs. UPN
casing and renames do not control the join. The risk list follows the current
[Microsoft risk table](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks),
including verified threat actor IP, suspicious MFA approval, anomalous token,
and threat intelligence. Values still depend on the emitted tenant schema.
Offline detections such as malicious IP and suspicious browser can arrive later;
inspect `AADUserRiskEvents` separately when that connector is available. This
rule does not claim to join that table or cover all later risk updates.

**MITRE:** T1566 (Phishing). The stable `2024-03-01` deployment payload uses the parent technique; it does not send unsupported `subTechniques`.

### Rule 2: Suspicious OAuth Redirect URI Registered (Medium)

Watches for app registrations adding redirect URIs to tunneling services, free hosting, URL shorteners, or non-HTTPS endpoints. It normalizes the normal `AppAddress` object shape and legacy bare-string records, compares `oldValue` with `newValue`, and evaluates additions only. It exempts the exact `localhost` and `127.0.0.1` HTTP loopback hosts that Microsoft supports for local application development; other HTTP hosts remain suspicious.

**MITRE:** T1098 (Account Manipulation)

### Rule 3: OAuth Error Cluster by Application (Medium)

Groups repeated consent, scope, app-registration, grant, and client-authentication failures by application. These errors can appear during redirect-abuse investigations, but they can also reflect ordinary consent state or broken application configuration. Treat the result as a triage lead and correlate it with redirect-URI changes, consent events, application ownership, and sign-in risk. The error cluster alone does not prove a redirect.

**MITRE:** None assigned. `SigninLogs` error codes alone do not establish phishing-link delivery or user execution.

### Rule 4: Bulk OAuth Consent to Single App (High)

Fires when 3+ distinct, nonempty Entra user object IDs consent to the same app
in the same fixed UTC hour bin. A burst split across an hour boundary can be
missed; this is not a rolling one-hour window. Repeated consent events from one user remain visible in the event
count but do not satisfy the distinct-user threshold.

**MITRE:** T1566 (Phishing). The stable `2024-03-01` deployment payload uses the parent technique; it does not send unsupported `subTechniques`.

---

### Scheduling and alert identity

Rules run hourly over a one-day event-time lookback. Rule 1 captures source
`ingestion_time()` on both join inputs and emits only matches with either input
ingested during the last hour. This retains an old counterpart when the other
side arrives late. Rule 2 filters fresh source events before expansion; rules
3/4 retain full fixed-bin context and emit only bins with newly ingested input.
The ingestion-time policy must be available. Delays beyond the event lookback,
schedule drift, reingestion, and new events in an already alerted bin still need
operator tuning; this is not an exactly-once delivery guarantee.

Each result requests a separate alert. Rule 1 maps its user object ID and IP;
rule 2 maps its initiating user and redirect URL. The aggregate rules keep their
sets in result columns rather than mapping a set to a scalar entity identifier.
Automatic incident grouping is disabled for all four rules so empty aggregate
entity sets cannot collapse unrelated applications or victims. Review grouping
after validating entity output in your own workspace. Sentinel service alert
limits still apply.

## Hunting Queries

Import the queries from `detection/hunting-queries.kql` into Sentinel Hunting:

| Hunt | Purpose | Lookback |
|---|---|---|
| 1. Enumerate Delegated Permissions | Observed user-consent events in retained logs | 90 days |
| 2. Non-Corporate IP Sign-ins | OAuth app auth from unexpected locations | 30 days |
| 3. New High-Privilege Service Principals | Recently provisioned client service principals with observed sensitive grants | 14 days |
| 4. Redirect URI Inventory | Observed redirect URI change history in retained logs | 90 days |
| 5. Authorization Error Followed by New-IP Authentication | Authorization-error/new-IP-success triage lead; does not prove a redirect or relay | 7 days |

Hunts 1 and 3 read the explicit `ServicePrincipal.ObjectID` client property on
grant events; the first target resource may instead name the resource API.
Missing or ambiguous client IDs are not guessed. Hunt 3 joins client service
principal provisioning IDs, not an application-registration object ID or a
display name. These hunts cover retained audit events rather than a complete
current permission inventory. Hunt 5 deliberately correlates the same user ID
and AppId; it does not detect Microsoft's cross-application error/redirect chain.

**Hunt 2** requires customization — replace the `CorporateNetworks` variable with your organization's IP ranges.

---

## Hardening Policies

### User Consent Restriction

`Set-OAuthHardening.ps1` changes a recognized legacy default user-consent
policy to `microsoft-user-default-low`. If self-service user consent is already
disabled, it remains disabled. Existing resource-owner grants and unrelated
policy entries are preserved. A custom self-consent policy stops the apply for
review rather than being replaced with a possibly broader default.

The built-in low-risk policy relies on tenant permission classifications;
`User.Read`, `openid`, and `profile` are not automatically classified by this
script. Review the actual low-impact list and verified-publisher/tenant-owned
application conditions before enabling user consent. See
[configure user consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent).

This updates the tenant's authorization policy, not a lab-scoped resource.
Before its first Graph mutation, the script writes an owner-only manifest with
the tenant ID, complete original and intended `permissionGrantPoliciesAssigned`
collections, intended content hashes, and reviewed exclusions. Graph assigns CA
policy IDs server-side, so the script records the exact returned ID atomically
before changing the tenant authorization policy. Preserve this manifest: it is
the ownership proof and rollback source of truth.

### Conditional Access Policy

Creates a new report-only lab CA policy that applies when:
- Sign-in risk is Medium or High
- Grant controls require **MFA**
- Session sign-in frequency is set to **Every time**

The risk-based policy requires Entra ID P2. Review report-only results and
emergency-access exclusions before deciding whether to enforce it. A fixed
seven-day observation is not a guarantee: this policy neither blocks all OAuth
redirect abuse nor makes MFA immune to adversary-in-the-middle phishing.

The script never finds or adopts a policy by display name. A current or legacy
same-name policy without the exact ID in the manifest is treated as foreign and
causes a failure before writes. Reruns accept only the exact manifest-owned ID
with the exact intended content hash; changing exclusions or policy content
requires rollback followed by a new manifest.

### OAuth App Audit

Run the audit independently:

```powershell
./hardening/Audit-OAuthApps.ps1 -OutputPath "./oauth-audit-report.csv"
```

The read-only audit pages through local application registrations, tenant
service principals (including third-party enterprise apps and managed
identities), delegated permission grants, and each service principal's
outbound `appRoleAssignments`. It joins local registrations to their service
principals without duplicating them, and also checks principals that have no
local registration. Its review checks cover:
- Suspicious redirect URI domains (ngrok, herokuapp, workers.dev, etc.)
- HTTP redirect URIs, except the exact parsed loopback hosts `localhost`,
  `127.0.0.1`, and `[::1]`; loopback text in a remote host, path, or query is not exempt
- High-privilege delegated permissions (Mail.Read, Files.ReadWrite.All, etc.)
- User-consented vs admin-consented permissions
- Multi-tenant audience declarations
- Granted application permissions, resolving each role ID against the resource
  service principal's `appRoles`; custom roles and default access are review
  candidates too, and missing resources/role definitions are labeled unresolved

Application redirect URIs and enterprise-app `replyUrls` are both checked.
The report identifies each object's type, service-principal ID/type, presence
of a local registration, and recorded owner-organization ID (when available), keeps
delegated and application permissions in separate columns, and retains API
resource IDs so identical permission names are not confused across resources.
Permission-name and URI flags are triage heuristics, not proof of maliciousness
or an exhaustive privilege ranking. The numeric score counts matched flags.

The existing **Directory.Read.All** read permission covers this complete audit
path, with an endpoint-supported Entra role for delegated execution. The audit
does not request or require extra Graph write permissions and performs only read operations. Up to 20 app-role collection GETs are sent
inside each POST to Graph's `/$batch`; this envelope does not change cloud data.
Every subresponse must be 200 with a valid collection, and each client keeps its
own guarded continuation path. A partial or throttled batch aborts before export.
Delegated grants are indexed once by client ID instead of rescanned per subject. See Microsoft's [delegated-grant list](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0),
[service-principal list](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0),
and [outbound app-role assignment list](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0).

Output is a CSV sorted by risk score, written through a private staging file
and atomically replaced only after success. Windows grants only the current
owner; Unix uses mode 0600. An existing report with broader permissions is
rejected until you review and secure it. The default filename and `reports/`
directory are ignored by Git; a custom output path still needs deliberate care. Spreadsheet-formula-like text is prefixed
with an apostrophe in exported string fields; the analysis uses original values.
Treat the CSV as sensitive tenant inventory. A failed, malformed, cyclic, or
off-host Graph page aborts before export rather than reporting a partial scan as
clean. Unmatched delegated clients also abort, since replication or an incomplete
inventory can explain them. A failed run leaves any prior output file unchanged;
do not treat that older file as a result from the failed run.

This is an Azure public-cloud, read-only snapshot and can encounter Graph
replication delays or throttling. Batching reduces native CLI starts from roughly one per assignment page to
one per 20 pages, while retaining all pages and per-item checks. It does not
remove Graph throttling or establish a measured wall-clock time; a denied or
throttled read fails the run and can be retried later.
An empty findings set means only that these checks found no candidates. It does
not audit home-tenant registration settings for external apps, effective Azure
RBAC/Entra roles, resource-specific consent, credential validity, sign-in activity,
or permissions requested but never granted. No live tenant result is claimed by
the offline fixtures.

---

## File Structure

```
oauth-redirect-abuse-sentinel/
├── README.md                             # This file
├── detection/
│   ├── analytics-rules.kql              # 4 Sentinel analytics rules (full KQL)
│   └── hunting-queries.kql              # 5 proactive hunting queries
├── hardening/
│   ├── Set-OAuthHardening.ps1           # Consent restriction + CA policy
│   └── Audit-OAuthApps.ps1             # OAuth app security audit
├── scripts/
│   ├── Deploy-Lab.ps1                   # Main deployment orchestrator
│   ├── Invoke-AzChecked.ps1             # Native argv/exit-code handling
│   └── Private-Report.ps1               # Owner-only atomic report writes
├── tests/
│   ├── test_script_contract.py          # Existing offline contracts and fixtures
│   ├── test_rule_pagination.py          # Complete, guarded Sentinel inventory
│   ├── test_native_exit.py              # Native failure and cleanup behavior
│   └── fixtures/                       # AppAddress and bulk-consent events
└── .gitignore                          # Keeps local hardening manifests private
```

---

## Cleanup

### Remove Sentinel Resources

Preview owned-resource cleanup first:

```powershell
./scripts/Deploy-Lab.ps1 `
  -ResourceGroup "rg-sentinel-lab" `
  -WorkspaceName "law-sentinel-lab" `
  -Destroy `
  -WhatIf
```

Then remove the four analytics rules and workbook owned by this lab:

```powershell
./scripts/Deploy-Lab.ps1 `
  -ResourceGroup "rg-sentinel-lab" `
  -WorkspaceName "law-sentinel-lab" `
  -Destroy
```

Cleanup validates every deterministic resource ID and ownership marker before
issuing its first delete. It refuses same-title foreign objects and resources
whose immutable ID, title/display name, or marker does not match. Legacy objects
from older random-ID revisions are intentionally not adopted or deleted; review
and remove those manually only after verifying their immutable IDs and content.

### Remove Hardening (if applied)

Both the deployer and standalone hardening script default to the repository-root
`.oauth-hardening-manifest.json`. If you supplied `-HardeningManifestPath` during
deployment, pass that same file as `-ManifestPath` below. Older standalone runs
may have written `hardening/.oauth-hardening-manifest.json`; explicitly select
that existing record, never copy or invent a manifest to bypass ownership checks.

Preview the drift-aware rollback:

```powershell
./hardening/Set-OAuthHardening.ps1 `
  -ConfirmTenantId "<verified-tenant-guid>" `
  -Rollback `
  -WhatIf
```

Then omit `-WhatIf` to restore the exact captured consent collection and delete
only the exact manifest-owned CA policy. Rollback preflights both surfaces before
its first mutation and refuses consent or CA drift; it never deletes by name.
The completed owner-only manifest is retained as a rollback record. Cleanup does
not remove `oauth-audit-report.csv`; handle that local report according to its
potentially sensitive tenant inventory content.

---

### Rejected or uncertain CA creation

An explicit Graph 400, 401, or 403 response with a structured error code leaves
the manifest `prepared`; fix the request/authorization and retry, or roll back
that prepared record. The empty policy inventory is valid and does not block a
no-change rollback. Timeouts, connection failures, 5xx, missing IDs, and unknown
CLI errors remain `ca-create-uncertain`: apply, rollback, and their previews stop.
Do not rerun POST or delete by display name. Retain the private manifest, confirm
the tenant, and inspect CA audit history plus exact immutable IDs to establish
whether creation occurred. Reconcile an uncertain record only with verified
ownership evidence; this lab deliberately has no automatic adoption command.

An older manifest whose intended consent collection would re-enable disabled
consent cannot continue applying with this revision. Its existing drift-aware
rollback remains available for review before starting a new apply record.

## Troubleshooting

### Rules Don't Fire

Analytics rules need matching data in `SigninLogs` and `AuditLogs`. If you don't have OAuth consent events or risky sign-ins in your tenant, the rules will be silent. Test by:

1. Registering a test app with a redirect URI containing `webhook.site` (triggers Rule 2)
2. Checking that `AuditLogs` contains "Add application" events

### Workbook Shows No Data

Ensure the workspace has `AuditLogs` and `SigninLogs` data connectors enabled. Check:

```kql
AuditLogs | take 1
SigninLogs | take 1
```

### Hardening Script Fails

The hardening script changes two different policy surfaces. Updating the tenant
authorization policy requires **Privileged Role Administrator** and
**Policy.ReadWrite.Authorization**. Creating the report-only Conditional Access
policy requires **Conditional Access Administrator** (or **Security
Administrator**) and **Policy.Read.All** plus
**Policy.ReadWrite.ConditionalAccess**. Run with `-WhatIf` to preview changes:

```powershell
./hardening/Set-OAuthHardening.ps1 `
  -ConfirmTenantId "<verified-tenant-guid>" `
  -ExcludedUserIds @("<break-glass-object-guid>") `
  -WhatIf
```

---

## Resources

- [Blog: Detecting OAuth Redirect Abuse with Microsoft Sentinel and Entra ID](https://nineliveszerotrust.com/blog/oauth-redirect-abuse-sentinel/)
- [Microsoft Security Blog: OAuth Redirection Abuse (March 2, 2026)](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/)
- [Microsoft identity platform: Authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft: Configure user consent settings](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
- [Microsoft: Conditional Access for risky sign-ins](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies)
- [Azure Monitor Logs reference: SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [KQL Reference](https://learn.microsoft.com/en-us/kusto/query/)
