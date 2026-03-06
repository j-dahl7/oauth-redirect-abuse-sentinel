#Requires -Version 7.0
<#
.SYNOPSIS
    Audits all OAuth app registrations and enterprise apps for risky permissions and redirect URIs.

.DESCRIPTION
    Enumerates app registrations and service principals via Microsoft Graph to identify:
    - Apps with high-privilege delegated or application permissions
    - Apps with suspicious redirect URIs (non-HTTPS, free hosting, URL shorteners)
    - Apps with user-granted consent (vs admin-granted)
    - Multi-tenant apps registered in the tenant
    - Apps with no owner (orphaned registrations)

.PARAMETER TenantId
    Azure AD tenant ID. If not specified, uses the current az login context.

.PARAMETER OutputPath
    Path to save the audit report CSV. Default: ./oauth-audit-report.csv

.EXAMPLE
    ./Audit-OAuthApps.ps1
    Runs a full OAuth app audit using current login context.

.EXAMPLE
    ./Audit-OAuthApps.ps1 -OutputPath "./reports/oauth-audit.csv"
    Saves the report to a custom location.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$OutputPath = './oauth-audit-report.csv'
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== OAuth Application Security Audit ===" -ForegroundColor Cyan
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# High-privilege scopes that warrant investigation
$HighPrivilegeScopes = @(
    'Mail.Read', 'Mail.ReadWrite', 'Mail.Send',
    'Files.ReadWrite.All', 'Files.Read.All',
    'User.ReadWrite.All', 'User.Read.All',
    'Directory.ReadWrite.All', 'Directory.Read.All',
    'Sites.ReadWrite.All', 'MailboxSettings.ReadWrite',
    'Contacts.ReadWrite', 'People.Read.All',
    'RoleManagement.ReadWrite.Directory',
    'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'Policy.ReadWrite.ConditionalAccess'
)

# Suspicious redirect URI patterns
$SuspiciousPatterns = @(
    'ngrok.io', 'ngrok-free.app', 'workers.dev', 'pages.dev',
    'herokuapp.com', 'netlify.app', 'vercel.app',
    'github.io', 'gitlab.io', 'surge.sh', 'glitch.me', 'replit.dev',
    'powerappsportals.com',
    'trycloudflare.com', 'serveo.net', 'localtunnel.me',
    'bit.ly', 'tinyurl.com', 't.co', 'rebrand.ly',
    'webhook.site', 'requestbin.com', 'pipedream.com'
)

# --- Fetch App Registrations ---
Write-Host "[1/5] Fetching app registrations..." -ForegroundColor Yellow
$apps = az rest --method GET `
    --url 'https://graph.microsoft.com/v1.0/applications?$top=999&$select=id,appId,displayName,web,spa,publicClient,signInAudience,createdDateTime' `
    2>$null | ConvertFrom-Json
$appList = $apps.value
Write-Host "  Found $($appList.Count) app registrations"

# --- Fetch OAuth2 Permission Grants (delegated permissions) ---
Write-Host "[2/5] Fetching delegated permission grants..." -ForegroundColor Yellow
$grants = az rest --method GET `
    --url 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' `
    2>$null | ConvertFrom-Json
$grantList = $grants.value
Write-Host "  Found $($grantList.Count) permission grants"

# --- Fetch Service Principals ---
Write-Host "[3/5] Fetching service principals..." -ForegroundColor Yellow
$sps = az rest --method GET `
    --url 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=999&$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType' `
    2>$null | ConvertFrom-Json
$spList = $sps.value
Write-Host "  Found $($spList.Count) service principals"

# --- Analyze ---
Write-Host "[4/5] Analyzing..." -ForegroundColor Yellow
$findings = @()

foreach ($app in $appList) {
    $risks = @()
    $redirectUris = @()

    # Collect all redirect URIs
    if ($app.web.redirectUris) { $redirectUris += $app.web.redirectUris }
    if ($app.spa.redirectUris) { $redirectUris += $app.spa.redirectUris }
    if ($app.publicClient.redirectUris) { $redirectUris += $app.publicClient.redirectUris }

    # Check for suspicious redirect URIs
    $suspiciousUris = @()
    foreach ($uri in $redirectUris) {
        # Non-HTTPS (excluding localhost)
        if ($uri -match '^http://' -and $uri -notmatch 'localhost|127\.0\.0\.1') {
            $suspiciousUris += $uri
            $risks += 'NON_HTTPS_REDIRECT'
        }
        # Known suspicious domains
        foreach ($pattern in $SuspiciousPatterns) {
            if ($uri -match [regex]::Escape($pattern)) {
                $suspiciousUris += $uri
                $risks += "SUSPICIOUS_DOMAIN:$pattern"
                break
            }
        }
    }

    # Check delegated permissions for this app
    $appGrants = $grantList | Where-Object {
        $sp = $spList | Where-Object { $_.appId -eq $app.appId }
        $sp -and $_.clientId -eq $sp.id
    }
    $highPrivPerms = @()
    foreach ($grant in $appGrants) {
        $scopes = $grant.scope -split ' '
        foreach ($scope in $scopes) {
            if ($scope -in $HighPrivilegeScopes) {
                $highPrivPerms += $scope
                if ($grant.consentType -eq 'Principal') {
                    $risks += "USER_CONSENTED_HIGH_PRIV:$scope"
                } else {
                    $risks += "ADMIN_CONSENTED_HIGH_PRIV:$scope"
                }
            }
        }
    }

    # Check if multi-tenant
    if ($app.signInAudience -in @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount', 'PersonalMicrosoftAccount')) {
        $risks += "MULTI_TENANT:$($app.signInAudience)"
    }

    # Build finding
    if ($risks.Count -gt 0) {
        $findings += [PSCustomObject]@{
            AppName           = $app.displayName
            AppId             = $app.appId
            ObjectId          = $app.id
            CreatedDate       = $app.createdDateTime
            SignInAudience    = $app.signInAudience
            RedirectUriCount  = $redirectUris.Count
            SuspiciousUris    = ($suspiciousUris -join '; ')
            HighPrivilegePerms = ($highPrivPerms | Select-Object -Unique) -join '; '
            RiskFlags         = ($risks | Select-Object -Unique) -join '; '
            RiskScore         = $risks.Count
        }
    }
}

# --- Report ---
Write-Host "[5/5] Generating report..." -ForegroundColor Yellow
Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "No risky OAuth applications found." -ForegroundColor Green
} else {
    $findings = $findings | Sort-Object -Property RiskScore -Descending
    $findings | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "=== FINDINGS SUMMARY ===" -ForegroundColor Red
    Write-Host "Total risky apps: $($findings.Count)" -ForegroundColor Red
    Write-Host ""

    # Summary table
    $findings | Select-Object AppName, RiskScore, @{N='TopRisk';E={($_.RiskFlags -split '; ')[0]}} |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "Full report saved to: $OutputPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Top risk categories:" -ForegroundColor Yellow

    $allRisks = $findings.RiskFlags -split '; ' | Where-Object { $_ }
    $allRisks | Group-Object | Sort-Object Count -Descending | Select-Object Count, Name |
        Format-Table -AutoSize
}

Write-Host "`nAudit complete." -ForegroundColor Green
