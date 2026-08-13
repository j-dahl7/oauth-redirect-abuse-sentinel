#Requires -Version 7.3
<#
.SYNOPSIS
    Deploys the OAuth Redirect Abuse Detection Lab.

.DESCRIPTION
    Deploys detection and hardening resources to an existing Microsoft Sentinel workspace:
    1. Sentinel analytics rules (4 scheduled rules for OAuth abuse detection)
    2. Five KQL hunting queries included in the repository for manual use
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

.PARAMETER Destroy
    Remove only the Sentinel analytics rules and workbook owned by this lab. The operation
    fails closed if a deterministic resource ID or ownership marker does not match.

.PARAMETER WhatIf
    Preview all changes without deploying.

.EXAMPLE
    ./Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"
    Deploy detection rules, workbook, and audit to an existing Sentinel workspace.

.EXAMPLE
    ./Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -ApplyHardening
    Deploy detection content and apply tenant hardening policies.

.EXAMPLE
    ./Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy -WhatIf
    Preview removal of this lab's owned Sentinel resources.
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
    [switch]$SkipAudit,

    [Parameter()]
    [switch]$Destroy
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Split-Path -Parent $ScriptDir
$LabOwnerMarker = 'nine-lives-zero-trust:oauth-redirect-abuse-sentinel'
$LabWorkbookTitle = 'OAuth Security Dashboard'

function Get-LabResourceGuid {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceKey
    )

    $seed = "$workspaceId|$LabOwnerMarker|$ResourceKey"
    $hash = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($seed)
    )
    return [guid]::new([byte[]]$hash[0..15]).ToString()
}

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

# --- Step 1: Validate and Deploy Analytics Rules ---
Write-Host "`n[1/5] $(if ($Destroy) { 'Validating owned Sentinel resources...' } else { 'Deploying Sentinel analytics rules...' })" -ForegroundColor Yellow

$rules = @(
    @{
        displayName = "LAB - OAuth Consent After Risky Sign-in"
        description = "Detects OAuth consent grants where the user session shows phishing risk indicators."
        severity    = "High"
        query       = @"
let PhishingWindow = 15m;
let RiskySignIns = SigninLogs
    | where TimeGenerated > ago(1d)
    | where RiskLevelDuringSignIn in ("high", "medium")
        or RiskEventTypes_V2 has_any ("unfamiliarFeatures", "anonymizedIPAddress", "maliciousIPAddress", "suspiciousIPAddress", "malwareInfectedIPAddress", "suspiciousBrowser")
    | project SignInTime = TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn, RiskEventTypes_V2, CorrelationId;
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "Consent to application"
| extend ConsentInitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| extend ConsentPermissions = tostring(TargetResources[0].modifiedProperties)
| join kind=inner (RiskySignIns) on `$left.ConsentInitiatedBy == `$right.UserPrincipalName
| where TimeGenerated between (SignInTime .. (SignInTime + PhishingWindow))
| project
    TimeGenerated,
    UserPrincipalName = ConsentInitiatedBy,
    AppDisplayName,
    AppId,
    ConsentPermissions,
    RiskLevel = RiskLevelDuringSignIn,
    RiskEvents = RiskEventTypes_V2,
    SourceIP = IPAddress
"@
        tactics        = @("InitialAccess")
        techniques     = @("T1566")
        subTechniques  = @("T1566.002")
    },
    @{
        displayName = "LAB - Suspicious OAuth Redirect URI Registered"
        description = "Detects app registrations with redirect URIs pointing to free hosting, URL shorteners, or non-HTTPS endpoints other than supported loopback development hosts."
        severity    = "Medium"
        query       = @"
// Match exact hosts or their subdomains after parsing each absolute redirect URI.
let SuspiciousHostRegex = @"^([a-z0-9-]+\.)*(ngrok\.io|ngrok-free\.app|trycloudflare\.com|serveo\.net|localtunnel\.me|workers\.dev|pages\.dev|herokuapp\.com|netlify\.app|vercel\.app|github\.io|gitlab\.io|surge\.sh|glitch\.me|replit\.dev|powerappsportals\.com|webhook\.site|requestbin\.com|pipedream\.com|bit\.ly|tinyurl\.com|t\.co|rebrand\.ly)$";
let ApprovedHttpLoopbackHosts = dynamic(["localhost", "127.0.0.1"]);
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Add application", "Update application")
| mv-expand ModifiedProperty = TargetResources[0].modifiedProperties
| where ModifiedProperty.displayName == "AppAddress"
| extend NewRedirectUris = tostring(ModifiedProperty.newValue)
| where NewRedirectUris != "[]"
| extend RedirectUriValues = parse_json(NewRedirectUris)
| mv-expand RedirectUri = RedirectUriValues to typeof(string)
| extend ParsedRedirectUri = parse_url(RedirectUri)
| extend RedirectScheme = tolower(tostring(ParsedRedirectUri.Scheme)),
    RedirectHost = tolower(tostring(ParsedRedirectUri.Host))
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppObjectId = tostring(TargetResources[0].id)
| where RedirectHost matches regex SuspiciousHostRegex
    or (RedirectScheme == "http" and RedirectHost !in~ (ApprovedHttpLoopbackHosts))
| project
    TimeGenerated,
    OperationName,
    AppName,
    AppObjectId,
    NewRedirectUris,
    RedirectUri,
    RedirectHost,
    InitiatedByUser,
    InitiatedByApp
"@
        tactics        = @("Persistence")
        techniques     = @("T1098")
        subTechniques  = @()
    },
    @{
        displayName        = "LAB - OAuth Error Cluster by Application"
        resourceKey        = "rule:LAB - OAuth Error-Based Redirect Pattern"
        legacyDisplayNames = @("LAB - OAuth Error-Based Redirect Pattern")
        description = "Groups repeated OAuth errors by application as a triage lead. Error codes alone do not prove a redirect; correlate with URI changes, consent, ownership, and risk telemetry."
        severity    = "Medium"
        query       = @"
// Immutable application IDs only - display names are attacker-controlled and
// Entra does not reserve first-party names, so an attacker can register a
// multi-tenant app called "Microsoft Teams" and be excluded by this rule's own
// allowlist while running the exact flow the rule exists to catch.
//
// Populate from your own tenant rather than from a published list:
//   SigninLogs
//   | where AppDisplayName in ("Microsoft Office", "Azure Portal", "Microsoft Teams", "Outlook Mobile")
//   | summarize SeenAs = make_set(AppDisplayName) by AppId
//
// Left empty deliberately. An unfilled allowlist suppresses nothing, so the rule
// is noisier rather than blind; a wrong GUID pasted in from memory would be worse.
let ApprovedAppIds = dynamic([
    // "00000000-0000-0000-0000-000000000000",  // Microsoft Office
    // "00000000-0000-0000-0000-000000000000",  // Azure Portal
    // "00000000-0000-0000-0000-000000000000",  // Microsoft Teams
    // "00000000-0000-0000-0000-000000000000"   // Outlook Mobile
]);
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in (
    "65001",   // User or administrator has not consented; interaction is required
    "65004",   // User declined consent
    "70011",   // Invalid scope or other OAuth parameter issue
    "70000",   // Invalid grant; broad authentication-flow failure
    "700016",  // Application not found in tenant
    "7000218", // Request body must contain client_assertion or client_secret
    "AADSTS65001",
    "AADSTS65004",
    "AADSTS70011",
    "AADSTS700016"
)
| extend AppName = AppDisplayName
| extend AppIdUsed = AppId
| where isempty(AppIdUsed) or AppIdUsed !in~ (ApprovedAppIds)
| summarize
    ErrorCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 10),
    ErrorCodes = make_set(ResultType),
    IPs = make_set(IPAddress, 10)
    by AppName, AppIdUsed, bin(TimeGenerated, 1h)
| where ErrorCount > 3 or DistinctUsers > 2
| project
    TimeGenerated,
    AppName,
    AppIdUsed,
    ErrorCount,
    DistinctUsers,
    Users,
    ErrorCodes,
    IPs
"@
        tactics        = @()
        techniques     = @()
        subTechniques  = @()
    },
    @{
        displayName = "LAB - Bulk OAuth Consent to Single App"
        description = "Detects when multiple users consent to the same OAuth app within a short window, indicating a phishing campaign."
        severity    = "High"
        query       = @"
let ConsentThreshold = 3;
let TimeWindow = 1h;
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "Consent to application"
| extend ConsentUser = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| summarize
    ConsentCount = count(),
    ConsentUsers = make_set(ConsentUser, 20),
    FirstConsent = min(TimeGenerated),
    LastConsent = max(TimeGenerated)
    by AppDisplayName, AppId, bin(TimeGenerated, TimeWindow)
| where ConsentCount >= ConsentThreshold
| project
    TimeGenerated,
    AppDisplayName,
    AppId,
    ConsentCount,
    ConsentUsers,
    ConsentWindow = LastConsent - FirstConsent
"@
        tactics        = @("InitialAccess")
        techniques     = @("T1566")
        subTechniques  = @("T1566.002")
    }
)

$existingRulesResponse = az rest --method GET `
    --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" `
    2>$null | ConvertFrom-Json
$existingRules = @($existingRulesResponse.value)
$existingWorkbooks = @(
    az resource list `
        --resource-group $ResourceGroup `
        --resource-type Microsoft.Insights/workbooks `
        2>$null | ConvertFrom-Json
)

$ownedRuleMarker = "[Owner: $LabOwnerMarker]"
$ruleStates = foreach ($rule in $rules) {
    $resourceKey = if ($rule.resourceKey) { [string]$rule.resourceKey } else { "rule:$($rule.displayName)" }
    $allowedDisplayNames = @($rule.displayName) + @($rule.legacyDisplayNames)
    $ruleId = Get-LabResourceGuid -ResourceKey $resourceKey
    $sameNameCollisions = @(
        $existingRules | Where-Object {
            $allowedDisplayNames -contains [string]$_.properties.displayName -and $_.name -ne $ruleId
        }
    )
    if ($sameNameCollisions.Count -gt 0) {
        throw "A non-lab analytics rule already uses display name '$($rule.displayName)'. Refusing to adopt, overwrite, or delete it."
    }

    $existingRule = $existingRules |
        Where-Object { $_.name -eq $ruleId } |
        Select-Object -First 1
    if ($existingRule) {
        $existingDisplayName = [string]$existingRule.properties.displayName
        $existingDescription = [string]$existingRule.properties.description
        if ($allowedDisplayNames -cnotcontains $existingDisplayName -or -not $existingDescription.Contains($ownedRuleMarker)) {
            throw "Refusing to overwrite or delete analytics rule '$ruleId': immutable ID, display name, or ownership marker does not match this lab."
        }
    }

    [pscustomobject]@{
        Definition = $rule
        ResourceId = $ruleId
        Existing   = $existingRule
    }
}

$workbookId = Get-LabResourceGuid -ResourceKey 'workbook'
$workbookTitleCollisions = @(
    $existingWorkbooks | Where-Object {
        ($_.properties.displayName -eq $LabWorkbookTitle -or $_.tags.'hidden-title' -eq $LabWorkbookTitle) -and
        $_.name -ne $workbookId
    }
)
if ($workbookTitleCollisions.Count -gt 0) {
    throw "A non-lab workbook already uses title '$LabWorkbookTitle'. Refusing to adopt, overwrite, or delete it."
}

$existingWorkbook = $existingWorkbooks |
    Where-Object { $_.name -eq $workbookId } |
    Select-Object -First 1
if ($existingWorkbook) {
    $existingWorkbookTitle = [string]$existingWorkbook.tags.'hidden-title'
    $existingWorkbookOwner = [string]$existingWorkbook.tags.'nlzt-owner'
    if ($existingWorkbookTitle -cne $LabWorkbookTitle -or $existingWorkbookOwner -cne $LabOwnerMarker) {
        throw "Refusing to overwrite or delete workbook '$workbookId': immutable ID, title, or ownership marker does not match this lab."
    }
}

$subscriptionId = ($workspaceId -split '/')[2]
$workbookResourceUrl = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01"

if ($Destroy) {
    Write-Host "`n[2/2] Removing owned Sentinel resources..." -ForegroundColor Yellow
    foreach ($state in $ruleStates) {
        if (-not $state.Existing) {
            Write-Host "  Not found: $($state.Definition.displayName)" -ForegroundColor DarkGray
            continue
        }

        if ($PSCmdlet.ShouldProcess($state.Definition.displayName, 'Delete owned Sentinel analytics rule')) {
            $null = az rest --method DELETE `
                --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules/$($state.ResourceId)?api-version=2024-03-01" `
                2>$null
            Write-Host "  Deleted: $($state.Definition.displayName)" -ForegroundColor Green
        }
    }

    if ($existingWorkbook) {
        if ($PSCmdlet.ShouldProcess($LabWorkbookTitle, 'Delete owned Sentinel workbook')) {
            $null = az rest --method DELETE --url $workbookResourceUrl 2>$null
            Write-Host "  Deleted: $LabWorkbookTitle" -ForegroundColor Green
        }
    } else {
        Write-Host "  Not found: $LabWorkbookTitle" -ForegroundColor DarkGray
    }

    $cleanupLabel = if ($WhatIfPreference) {
        'Cleanup preview complete; no resources were deleted.'
    } else {
        'Owned Sentinel resources destroyed.'
    }
    Write-Host "`n$cleanupLabel" -ForegroundColor Green
    return
}

foreach ($state in $ruleStates) {
    $rule = $state.Definition
    Write-Host "  Deploying: $($rule.displayName)"

    $ruleBody = @{
        kind       = "Scheduled"
        properties = @{
            displayName           = $rule.displayName
            description           = "$($rule.description) $ownedRuleMarker"
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

    $ruleId = $state.ResourceId
    $ruleAction = if ($state.Existing) { "Updated" } else { "Created" }

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
        "timeContextFromParameter": "TimeRange",
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
        "query": "let ApprovedAppIds = dynamic([]);\nSigninLogs\n| where ResultType in (\"65001\",\"65004\",\"70011\",\"700016\",\"70000\",\"7000218\",\"AADSTS65001\",\"AADSTS65004\",\"AADSTS70011\",\"AADSTS700016\")\n| extend AppIdUsed = AppId\n| where isempty(AppIdUsed) or AppIdUsed !in~ (ApprovedAppIds)\n| summarize Errors = count() by AppDisplayName, AppId, ResultType\n| sort by Errors desc",
        "timeContextFromParameter": "TimeRange",
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
        "timeContextFromParameter": "TimeRange",
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
        "timeContextFromParameter": "TimeRange",
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

$workbookAction = if ($existingWorkbook) { "Updated" } else { "Created" }
$workbookBody = @{
    location   = $workspace.location
    kind       = "shared"
    tags       = @{
        'hidden-title' = $LabWorkbookTitle
        'nlzt-owner'   = $LabOwnerMarker
    }
    properties = @{
        displayName    = $LabWorkbookTitle
        serializedData = $workbookContent
        category       = "sentinel"
        sourceId       = $workspaceId
    }
} | ConvertTo-Json -Depth 10

if ($PSCmdlet.ShouldProcess($LabWorkbookTitle, "$workbookAction Sentinel workbook")) {
    $bodyFile = New-TemporaryFile
    try {
        [System.IO.File]::WriteAllText($bodyFile.FullName, $workbookBody, [System.Text.Encoding]::UTF8)
        $wbResult = az rest --method PUT `
            --url $workbookResourceUrl `
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
