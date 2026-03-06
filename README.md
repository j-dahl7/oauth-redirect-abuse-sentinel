# OAuth Redirect Abuse Detection Lab

A hands-on lab deploying detection and hardening for OAuth redirect abuse — the technique Microsoft warned about in their [March 2026 advisory](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/).

**Cost:** Uses existing Sentinel workspace (no additional resources)
**Cleanup:** Delete analytics rules and workbook from Sentinel, remove CA policy from Entra

> **Blog Post:** For detailed explanations of the attack technique and detection logic, see [Detecting OAuth Redirect Abuse with Microsoft Sentinel and Entra ID](https://nineliveszerotrust.com/blog/oauth-redirect-abuse-sentinel/).

---

## What Gets Deployed

| Resource | Type | Details |
|---|---|---|
| 4 Analytics Rules | Sentinel Scheduled | OAuth consent after risky sign-in, suspicious redirect URI, OAuth error patterns, bulk consent |
| 1 Workbook | Azure Workbook | OAuth Security Dashboard (consent timeline, error patterns, URI changes, top apps) |
| 1 CA Policy | Entra ID | Report-only step-up policy for risky OAuth-related sign-ins |
| 5 Hunting Queries | KQL files | Delegated permissions audit, non-corporate IPs, new high-priv apps, URI inventory, token replay |
| 1 Audit Script | PowerShell | Enumerate all OAuth apps for suspicious redirect URIs and overprivileged permissions |

---

## Prerequisites

- Azure subscription with an existing **Microsoft Sentinel** workspace
- Azure CLI configured (`az login`)
- PowerShell 7+ (`pwsh`)
- **Security Administrator** or **Sentinel Contributor** role on the workspace
- **Conditional Access Administrator** role (for hardening policies, skip with `-SkipHardening`)
- **Application.Read.All** Graph permission (for the OAuth audit, skip with `-SkipAudit`)

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/j-dahl7/oauth-redirect-abuse-sentinel.git
cd oauth-redirect-abuse-sentinel
```

### 2. Deploy

```powershell
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"
```

Or detection only (no tenant changes):

```powershell
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -SkipHardening -SkipAudit
```

The script will:
1. Verify the Sentinel workspace exists and Sentinel is enabled
2. Deploy 4 scheduled analytics rules via the Sentinel REST API
3. Deploy the OAuth Security Dashboard workbook
4. Apply OAuth hardening policies (consent restriction, CA policy)
5. Run the OAuth app audit and save a CSV report

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

Delete the analytics rules from **Microsoft Defender portal** > **Microsoft Sentinel** > **Analytics**:
- Select rules prefixed with "LAB -" and delete

Delete the workbook from **Workbooks** > "OAuth Security Dashboard"

### Remove Hardening (if applied)

**Revert consent policy:** Restore the `permissionGrantPoliciesAssigned` collection you recorded before running the lab. Do not overwrite the collection with a single legacy value if your tenant already uses `managePermissionGrantsForOwnedResource.*` entries.

**Delete CA policy:**
```powershell
az rest --method DELETE `
    --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<policy-id>'
```

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

The hardening script requires **Conditional Access Administrator** and **Policy.ReadWrite.ConditionalAccess** Graph permission. Run with `-WhatIf` to preview changes:

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
