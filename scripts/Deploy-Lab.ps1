#Requires -Version 7.3
<#
.SYNOPSIS
    Deploys the OAuth Redirect Abuse Detection Lab.

.DESCRIPTION
    Deploys detection and hardening resources to an existing Microsoft Sentinel workspace:
    1. Sentinel analytics rules (4 scheduled rules for OAuth abuse detection)
    2. Sentinel hunting queries (5 proactive hunting packs)
    3. Sentinel workbook (OAuth Security Dashboard)
    4. Optional OAuth hardening policies (user consent restrictions, CA policy)
    5. Runs the OAuth app audit

.PARAMETER ResourceGroup
    Resource group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace with Sentinel enabled.

.PARAMETER ApplyHardening
    Apply tenant-level OAuth hardening policies. Omitted by default so the lab deploys detection-only.

.PARAMETER ExcludedUserIds
    Entra user object IDs, such as emergency-access accounts, to exclude from the report-only Conditional Access policy.

.PARAMETER SkipHardening
    Deprecated compatibility switch. If present, tenant hardening is skipped even when ApplyHardening is present.

.PARAMETER SkipAudit
    Skip running the OAuth app audit.

.PARAMETER WhatIf
    Preview all changes without deploying.

.EXAMPLE
    ./Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"
    Deploy detection rules, workbook, and audit to an existing Sentinel workspace.

.EXAMPLE
    ./Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -ApplyHardening
    Deploy detection content and apply tenant hardening policies.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [Parameter()]
    [switch]$ApplyHardening,

    [Parameter()]
    [string[]]$ExcludedUserIds = @(),

    [Parameter()]
    [switch]$SkipHardening,

    [Parameter()]
    [switch]$SkipAudit
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Split-Path -Parent $ScriptDir

Write-Host "`n=== OAuth Redirect Abuse Detection Lab ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Workspace:      $WorkspaceName"
Write-Host ""

# Verify prerequisites
Write-Host "[0/5] Verifying prerequisites..." -ForegroundColor Yellow
$workspace = az monitor log-analytics workspace show `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName 2>$null | ConvertFrom-Json

if (-not $workspace) {
    Write-Error "Workspace '$WorkspaceName' not found in resource group '$ResourceGroup'"
}

$workspaceId = $workspace.id
$customerId = $workspace.customerId
Write-Host "  Workspace ID: $customerId" -ForegroundColor DarkGray

# Check Sentinel is enabled
$sentinel = az rest --method GET `
    --url "$workspaceId/providers/Microsoft.SecurityInsights/onboardingStates?api-version=2024-03-01" `
    2>$null | ConvertFrom-Json

if (-not $sentinel.value) {
    Write-Error "Microsoft Sentinel is not enabled on workspace '$WorkspaceName'"
}
Write-Host "  Sentinel: Enabled" -ForegroundColor Green

# --- Step 1: Deploy Analytics Rules ---
Write-Host "`n[1/5] Deploying Sentinel analytics rules..." -ForegroundColor Yellow

$rules = @(
    @{
        displayName = "LAB - OAuth Consent After Risky Sign-in"
        description = "Detects OAuth consent grants where the user session shows phishing risk indicators."
        severity    = "High"
        query       = @"
let PhishingWindow = 15m;
let RiskySignIns = SigninLogs
    | where RiskLevelDuringSignIn in ("high", "medium")
        or RiskEventTypes_V2 has_any ("unfamiliarFeatures", "anonymizedIPAddress", "maliciousIPAddress", "suspiciousIPAddress", "malwareInfectedIPAddress", "suspiciousBrowser")
    | project SignInTime = TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn;
AuditLogs
| where OperationName == "Consent to application"
| extend ConsentUser = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| join kind=inner (RiskySignIns) on `$left.ConsentUser == `$right.UserPrincipalName
| where TimeGenerated between (SignInTime .. (SignInTime + PhishingWindow))
| project TimeGenerated, UserPrincipalName = ConsentUser, AppName, RiskLevelDuringSignIn, IPAddress
"@
        tactics        = @("InitialAccess")
        techniques     = @("T1566")
        subTechniques  = @("T1566.002")
    },
    @{
        displayName = "LAB - Suspicious OAuth Redirect URI Registered"
        description = "Detects app registrations with redirect URIs pointing to free hosting, URL shorteners, or non-HTTPS endpoints."
        severity    = "Medium"
        query       = @"
let SuspiciousDomains = dynamic(["ngrok.io","ngrok-free.app","trycloudflare.com","serveo.net","localtunnel.me","workers.dev","pages.dev","herokuapp.com","netlify.app","vercel.app","github.io","gitlab.io","surge.sh","glitch.me","replit.dev","powerappsportals.com","webhook.site","requestbin.com","pipedream.com","bit.ly","tinyurl.com","t.co","rebrand.ly"]);
AuditLogs
| where OperationName in ("Add application", "Update application")
| mv-expand ModifiedProperty = TargetResources[0].modifiedProperties
| where ModifiedProperty.displayName == "AppAddress"
| extend NewRedirectUris = tostring(ModifiedProperty.newValue)
| extend InitiatedBy_ = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend AppName = tostring(TargetResources[0].displayName)
| where NewRedirectUris has_any (SuspiciousDomains) or NewRedirectUris has "http://"
| project TimeGenerated, AppName, NewRedirectUris, InitiatedBy_
"@
        tactics        = @("Persistence")
        techniques     = @("T1098")
        subTechniques  = @()
    },
    @{
        displayName = "LAB - OAuth Error-Based Redirect Pattern"
        description = "Detects sign-in attempts to OAuth apps resulting in error codes used in redirect abuse campaigns."
        severity    = "High"
        query       = @"
SigninLogs
| where ResultType in ("65001","65004","70011","700016","70000","7000218","AADSTS65001","AADSTS65004","AADSTS70011","AADSTS700016")
| where AppDisplayName !in ("Microsoft Office","Azure Portal","Microsoft Teams","Outlook Mobile")
| summarize ErrorCount = count(), DistinctUsers = dcount(UserPrincipalName), Users = make_set(UserPrincipalName, 10), ErrorCodes = make_set(ResultType), IPs = make_set(IPAddress, 10) by AppDisplayName, AppId, bin(TimeGenerated, 1h)
| where ErrorCount > 3 or DistinctUsers > 2
| project TimeGenerated, AppDisplayName, AppId, ErrorCount, DistinctUsers, Users, ErrorCodes, IPs
"@
        tactics        = @("InitialAccess")
        techniques     = @("T1566")
        subTechniques  = @("T1566.002")
    },
    @{
        displayName = "LAB - Bulk OAuth Consent to Single App"
        description = "Detects when multiple users consent to the same OAuth app within a short window, indicating a phishing campaign."
        severity    = "High"
        query       = @"
AuditLogs
| where OperationName == "Consent to application"
| extend ConsentUser = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| summarize ConsentCount = count(), ConsentUsers = make_set(ConsentUser, 20), FirstConsent = min(TimeGenerated), LastConsent = max(TimeGenerated) by AppName, AppId, bin(TimeGenerated, 1h)
| where ConsentCount >= 3
| project TimeGenerated, AppName, AppId, ConsentCount, ConsentUsers
"@
        tactics        = @("InitialAccess")
        techniques     = @("T1566")
        subTechniques  = @("T1566.002")
    }
)

$existingRulesResponse = az rest --method GET `
    --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" `
    2>$null | ConvertFrom-Json
$existingRuleIdsByName = @{}
foreach ($existingRule in @($existingRulesResponse.value)) {
    $existingDisplayName = $existingRule.properties.displayName
    if ($existingDisplayName) {
        $existingRuleIdsByName[$existingDisplayName] = $existingRule.name
    }
}

foreach ($rule in $rules) {
    Write-Host "  Deploying: $($rule.displayName)"

    $ruleBody = @{
        kind       = "Scheduled"
        properties = @{
            displayName           = $rule.displayName
            description           = $rule.description
            severity              = $rule.severity
            query                 = $rule.query
            queryFrequency        = "PT1H"
            queryPeriod           = "P1D"
            triggerOperator       = "GreaterThan"
            triggerThreshold      = 0
            suppressionDuration   = "PT5H"
            suppressionEnabled    = $false
            tactics               = $rule.tactics
            techniques            = $rule.techniques
            subTechniques         = $rule.subTechniques
            enabled               = $true
            incidentConfiguration = @{
                createIncident        = $true
                groupingConfiguration = @{
                    enabled               = $true
                    reopenClosedIncident  = $false
                    lookbackDuration      = "PT5H"
                    matchingMethod        = "AllEntities"
                }
            }
        }
    } | ConvertTo-Json -Depth 10

    $ruleId = if ($existingRuleIdsByName[$rule.displayName]) {
        $existingRuleIdsByName[$rule.displayName]
    } else {
        [guid]::NewGuid().ToString()
    }
    $ruleAction = if ($existingRuleIdsByName[$rule.displayName]) { "Updated" } else { "Created" }

    if ($PSCmdlet.ShouldProcess($rule.displayName, "$ruleAction Sentinel analytics rule")) {
        $bodyFile = New-TemporaryFile
        try {
            [System.IO.File]::WriteAllText($bodyFile.FullName, $ruleBody, [System.Text.Encoding]::UTF8)
            $result = az rest --method PUT `
                --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=2024-03-01" `
                --body "@$($bodyFile.FullName)" `
                --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

            if ($result.name) {
                Write-Host "    ${ruleAction}: $($result.name)" -ForegroundColor Green
            } else {
                throw "Sentinel did not return an analytics rule resource"
            }
        }
        finally {
            Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue
        }
    }
}

# --- Step 2: Deploy Workbook ---
Write-Host "`n[2/5] Deploying Sentinel workbook..." -ForegroundColor Yellow

$workbookContent = @'
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 1,
      "content": { "json": "# OAuth Security Dashboard\nMonitors OAuth application activity, consent grants, and redirect abuse indicators.\n\n**Reference:** [Microsoft Security Blog - OAuth Redirect Abuse](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/)" },
      "name": "header"
    },
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          { "id": "timerange", "version": "KqlParameterItem/1.0", "name": "TimeRange", "label": "Time range", "type": 4,
            "isRequired": true, "isGlobal": true, "value": { "durationMs": 604800000 }, "timeContext": { "durationMs": 604800000 },
            "typeSettings": { "allowCustom": true, "selectableValues": [{"durationMs":86400000},{"durationMs":604800000},{"durationMs":2592000000}] } }
        ]
      },
      "name": "parameters"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AuditLogs\n| where OperationName == \"Consent to application\"\n| extend User = tostring(InitiatedBy.user.userPrincipalName)\n| extend App = tostring(TargetResources[0].displayName)\n| summarize Consents = count() by bin(TimeGenerated, 1d), App\n| render timechart",
        "size": 1,
        "title": "OAuth Consent Grants Over Time",
        "queryType": 0,
        "visualization": "timechart"
      },
      "name": "consent-timeline"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where ResultType in (\"65001\",\"65004\",\"70011\",\"700016\",\"70000\",\"7000218\",\"AADSTS65001\",\"AADSTS65004\",\"AADSTS70011\",\"AADSTS700016\")\n| where AppDisplayName !in (\"Microsoft Office\",\"Azure Portal\",\"Microsoft Teams\",\"Outlook Mobile\")\n| summarize Errors = count() by AppDisplayName, ResultType\n| sort by Errors desc",
        "size": 1,
        "title": "OAuth Error Patterns by Application",
        "queryType": 0,
        "visualization": "table"
      },
      "name": "error-redirects"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AuditLogs\n| where OperationName in (\"Add application\", \"Update application\")\n| mv-expand ModifiedProperty = TargetResources[0].modifiedProperties\n| where ModifiedProperty.displayName == \"AppAddress\"\n| extend RedirectUris = tostring(ModifiedProperty.newValue)\n| extend AppName = tostring(TargetResources[0].displayName)\n| extend ModifiedBy = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))\n| project TimeGenerated, AppName, RedirectUris, ModifiedBy\n| sort by TimeGenerated desc",
        "size": 1,
        "title": "Recent Redirect URI Changes",
        "queryType": 0,
        "visualization": "table"
      },
      "name": "redirect-changes"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AuditLogs\n| where OperationName == \"Consent to application\"\n| extend User = tostring(InitiatedBy.user.userPrincipalName)\n| extend App = tostring(TargetResources[0].displayName)\n| summarize ConsentCount = count() by App\n| sort by ConsentCount desc\n| take 10",
        "size": 1,
        "title": "Top 10 Apps by Consent Count",
        "queryType": 0,
        "visualization": "barchart"
      },
      "name": "top-consent-apps"
    }
  ],
  "fallbackResourceIds": ["placeholder"],
  "fromTemplateId": "sentinel-OAuthSecurityDashboard"
}
'@

$workbookDisplayName = "OAuth Security Dashboard"
$existingWorkbook = @(
    az resource list `
        --resource-group $ResourceGroup `
        --resource-type Microsoft.Insights/workbooks `
        2>$null | ConvertFrom-Json
) | Where-Object {
    $_.properties.displayName -eq $workbookDisplayName -or $_.tags.'hidden-title' -eq $workbookDisplayName
} | Select-Object -First 1
$workbookId = if ($existingWorkbook) { $existingWorkbook.name } else { [guid]::NewGuid().ToString() }
$workbookAction = if ($existingWorkbook) { "Updated" } else { "Created" }
$workbookBody = @{
    location   = $workspace.location
    kind       = "shared"
    tags       = @{
        'hidden-title' = $workbookDisplayName
    }
    properties = @{
        displayName    = $workbookDisplayName
        serializedData = $workbookContent
        category       = "sentinel"
        sourceId       = $workspaceId
    }
} | ConvertTo-Json -Depth 10

if ($PSCmdlet.ShouldProcess($workbookDisplayName, "$workbookAction Sentinel workbook")) {
    $bodyFile = New-TemporaryFile
    try {
        [System.IO.File]::WriteAllText($bodyFile.FullName, $workbookBody, [System.Text.Encoding]::UTF8)
        $wbResult = az rest --method PUT `
            --url "/subscriptions/$(($workspaceId -split '/')[2])/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01" `
            --body "@$($bodyFile.FullName)" `
            --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

        if ($wbResult.name) {
            Write-Host "  Workbook $($workbookAction.ToLower()): $($wbResult.properties.displayName)" -ForegroundColor Green
        } else {
            throw "Azure did not return a workbook resource"
        }
    }
    finally {
        Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue
    }
}

# --- Step 3: Apply Hardening ---
if ($ApplyHardening -and -not $SkipHardening) {
    Write-Host "`n[3/5] Applying OAuth hardening..." -ForegroundColor Yellow
    & "$LabRoot/hardening/Set-OAuthHardening.ps1" `
        -ExcludedUserIds $ExcludedUserIds `
        -WhatIf:$WhatIfPreference
} else {
    Write-Host "`n[3/5] Skipping tenant hardening (add -ApplyHardening to apply)" -ForegroundColor DarkGray
}

# --- Step 4: Run Audit ---
if (-not $SkipAudit -and -not $WhatIfPreference) {
    Write-Host "`n[4/5] Running OAuth app audit..." -ForegroundColor Yellow
    & "$LabRoot/hardening/Audit-OAuthApps.ps1" -OutputPath "$LabRoot/oauth-audit-report.csv"
} else {
    Write-Host "`n[4/5] Skipping audit (disabled explicitly or during -WhatIf preview)" -ForegroundColor DarkGray
}

# --- Step 5: Summary ---
$completionLabel = if ($WhatIfPreference) { 'Deployment preview complete; no changes applied.' } else { 'Deployment complete!' }
Write-Host "`n[5/5] $completionLabel" -ForegroundColor Green
Write-Host ""
Write-Host "=== $(if ($WhatIfPreference) { 'Planned Resources' } else { 'Deployed Resources' }) ===" -ForegroundColor Cyan
Write-Host "  Analytics Rules: 4 scheduled rules"
Write-Host "  Workbook:        OAuth Security Dashboard"
if ($ApplyHardening -and -not $SkipHardening -and -not $WhatIfPreference) {
    Write-Host "  Hardening:       User consent restricted, CA policy (report-only)"
}
if (-not $SkipAudit -and -not $WhatIfPreference) {
    Write-Host "  Audit Report:    $LabRoot/oauth-audit-report.csv"
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Open Microsoft Sentinel > Analytics to review the 4 new rules"
Write-Host "  2. Open Workbooks > 'OAuth Security Dashboard' to see the dashboard"
Write-Host "  3. Run the hunting queries in detection/hunting-queries.kql"
Write-Host "  4. Review the CA policy in Entra admin center (report-only mode)"
Write-Host ""
