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

The hardened July 25, 2026 revision was checked with offline PowerShell parsing,
mocked safety tests, and KQL/static contract review. It was not deployed to a
tenant, no live Graph hardening call was made, and no live Sentinel query or
incident was validated for this revision. Rule output depends on the target
workspace's `SigninLogs`/`AuditLogs` schema, data connectors, volume, and
ingestion latency.

---

## What Gets Deployed

| Resource | Type | Details |
|---|---|---|
| 4 Analytics Rules | Sentinel Scheduled | OAuth consent after risky sign-in, suspicious redirect URI, OAuth error patterns, bulk consent |
| 1 Workbook | Azure Workbook | OAuth Security Dashboard (consent timeline, error patterns, URI changes, top apps) |
| Optional consent policy change | Entra ID | Tenant authorization-policy update; applied only with `-ApplyHardening` |
| Optional CA Policy | Entra ID | Report-only step-up policy; created/updated only with `-ApplyHardening` |
| 5 Hunting Queries | KQL files | Delegated permissions audit, non-corporate IPs, new high-priv apps, URI inventory, token replay |
| 1 Audit Script | PowerShell | Enumerate all OAuth apps for suspicious redirect URIs and overprivileged permissions |

---

## Prerequisites

- Azure subscription with an existing **Microsoft Sentinel** workspace
- Azure CLI configured (`az login`)
- PowerShell 7.3+ (`pwsh`)
- **Microsoft Sentinel Contributor** or equivalent rule/workbook write
  permissions on the workspace
- **Directory.Read.All** Microsoft Graph delegated permission and a supported
  Entra role (such as **Directory Readers**) for the default read-only OAuth
  audit, including `/oauth2PermissionGrants` (omit the audit with `-SkipAudit`)
- For the tenant-wide consent-policy update used by `-ApplyHardening`:
  **Privileged Role Administrator** and **Policy.ReadWrite.Authorization**
- For the report-only Conditional Access policy used by `-ApplyHardening`:
  **Conditional Access Administrator** (or **Security Administrator**) and the
  **Policy.Read.All** plus **Policy.ReadWrite.ConditionalAccess** permissions
- Exact Entra object IDs for emergency-access accounts to pass through
  `-ExcludedUserIds` before applying the report-only CA policy

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
  -ExcludedUserIds @("<break-glass-object-id-1>","<break-glass-object-id-2>")
```

The script:

1. Verifies the Sentinel workspace exists and Sentinel is enabled
2. Deploys 4 scheduled analytics rules via the Sentinel REST API
3. Deploys the OAuth Security Dashboard workbook
4. Applies OAuth hardening only when `-ApplyHardening` is present
5. Runs the OAuth app audit and saves a CSV report unless `-SkipAudit` is present

`-WhatIf` performs discovery/read calls but skips guarded cloud writes, tenant
hardening, temporary request-body files, and the audit/CSV. It does not validate
KQL results or CA impact. `-SkipHardening` remains only as a deprecated
compatibility switch; absence of `-ApplyHardening` is the normal safe default.
Analytics rules and the workbook use deterministic workspace-scoped IDs plus
explicit ownership markers. Deployment fails closed instead of adopting a
same-named resource or overwriting a deterministic ID whose marker does not match.

Current deployment parameters are `-ResourceGroup`, `-WorkspaceName`,
`-ApplyHardening`, `-ExcludedUserIds`, `-SkipHardening` (deprecated),
`-SkipAudit`, `-Destroy`, and PowerShell's common `-WhatIf` switch.

### 3. Verify Deployment

Open **Microsoft Defender portal** > **Microsoft Sentinel** > **Analytics**:

- You should see 4 new rules prefixed with "LAB -"
- All rules should show as Enabled with Scheduled type

Open **Workbooks**:

- Find "OAuth Security Dashboard" in the list

---

## Analytics Rules

### Rule 1: OAuth Consent After Risky Sign-in (High)

Correlates `SigninLogs` risk indicators with `AuditLogs` consent events within a 15-minute window.

**MITRE:** T1566.002 (Spearphishing Link)

### Rule 2: Suspicious OAuth Redirect URI Registered (Medium)

Watches for app registrations adding redirect URIs to tunneling services, free hosting, URL shorteners, or non-HTTPS endpoints.

**MITRE:** T1098 (Account Manipulation)

### Rule 3: OAuth Error-Based Redirect Pattern (High)

Detects the Entra errors most closely associated with redirect abuse. The strongest signals are `AADSTS65001` and `AADSTS65004`; additional OAuth failures are included as supporting context when they cluster around the same app and time window.

**MITRE:** T1566.002 (Spearphishing Link), T1204.001 (User Execution: Malicious Link)

### Rule 4: Bulk OAuth Consent to Single App (High)

Fires when 3+ users consent to the same app within 1 hour.

**MITRE:** T1566.002 (Spearphishing Link)

---

## Hunting Queries

Import the queries from `detection/hunting-queries.kql` into Sentinel Hunting:

| Hunt | Purpose | Lookback |
|---|---|---|
| 1. Enumerate Delegated Permissions | Baseline audit of all user-granted permissions | 90 days |
| 2. Non-Corporate IP Sign-ins | OAuth app auth from unexpected locations | 30 days |
| 3. New High-Privilege Apps | Recently registered apps with sensitive scopes | 14 days |
| 4. Redirect URI Inventory | Full audit trail of redirect URI changes | 90 days |
| 5. Token Replay After Error | Error redirect followed by successful auth from different IP | 7 days |

**Hunt 2** requires customization — replace the `CorporateNetworks` variable with your organization's IP ranges.

---

## Hardening Policies

### User Consent Restriction

The `Set-OAuthHardening.ps1` script restricts user consent to:
- **Low-risk permissions** only (e.g., `User.Read`, `openid`, `profile`)
- Apps from **verified publishers** and trusted tenant-owned workflows
- Everything else requires **admin approval**
- Existing `managePermissionGrantsForOwnedResource.*` entries are preserved when the policy is updated

This updates the tenant's authorization policy, not a lab-scoped resource.
Record the complete original `permissionGrantPoliciesAssigned` collection
before applying it. The script cannot infer the desired rollback state later.

### Conditional Access Policy

Creates a report-only lab CA policy that applies when:
- Sign-in risk is Medium or High
- Grant controls require **MFA**
- Session sign-in frequency is set to **Every time**

Review the policy for 7 days before enforcing it.

### OAuth App Audit

Run the audit independently:

```powershell
./hardening/Audit-OAuthApps.ps1 -OutputPath "./oauth-audit-report.csv"
```

The audit checks every app registration for:
- Suspicious redirect URI domains (ngrok, herokuapp, workers.dev, etc.)
- Non-HTTPS redirect URIs (excluding localhost)
- High-privilege delegated permissions (Mail.Read, Files.ReadWrite.All, etc.)
- User-consented vs admin-consented permissions
- Multi-tenant app registrations

Output is a CSV sorted by risk score.

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
└── scripts/
    └── Deploy-Lab.ps1                   # Main deployment orchestrator
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

**Revert consent policy:** Restore the complete
`permissionGrantPoliciesAssigned` collection captured immediately before the
lab. Do not replace it with a guessed single value or discard existing
`managePermissionGrantsForOwnedResource.*` entries.

**Delete CA policy:**

```powershell
az rest --method DELETE `
    --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<policy-id>'
```

Use the immutable policy ID returned by deployment and first verify that its
display name, report-only state, conditions, exclusions, and provenance match
this lab. Cleanup does not remove `oauth-audit-report.csv`; handle that local
report according to its potentially sensitive tenant inventory content.

---

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
./hardening/Set-OAuthHardening.ps1 -WhatIf
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
