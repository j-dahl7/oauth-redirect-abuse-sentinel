#Requires -Version 7.4
<#
.SYNOPSIS
    Reviews local app registrations and tenant service principals for permission and redirect-URI findings.

.DESCRIPTION
    Enumerates app registrations and service principals via Microsoft Graph to identify:
    - Apps with high-privilege delegated permissions
    - Granted application permissions, resolved through the resource service principal's appRoles
    - Apps with suspicious redirect URIs (non-HTTPS, free hosting, URL shorteners)
    - Apps with user-granted consent (vs admin-granted)
    - Multi-tenant apps registered in the tenant

.PARAMETER TenantId
    Azure AD tenant ID. If not specified, uses the current az login context.

.PARAMETER OutputPath
    Path to save the audit report CSV. Default: ./oauth-audit-report.csv

.EXAMPLE
    ./Audit-OAuthApps.ps1
    Runs the bounded read-only audit using the current login context.

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
$PSNativeCommandUseErrorActionPreference = $true
. (Join-Path $PSScriptRoot '../scripts/Invoke-AzChecked.ps1')

function Get-GraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $items = @()
    $nextLink = $Uri
    $seenLinks = [System.Collections.Generic.HashSet[string]]::new()

    while ($nextLink) {
        if (-not $seenLinks.Add($nextLink)) {
            throw "Microsoft Graph returned a pagination cycle for '$Uri'"
        }

        $parsedNextLink = $null
        if (
            -not [Uri]::TryCreate($nextLink, [UriKind]::Absolute, [ref]$parsedNextLink) -or
            $parsedNextLink.Scheme -ne 'https' -or
            $parsedNextLink.Host -ne 'graph.microsoft.com' -or
            $parsedNextLink.UserInfo -or
            (-not $parsedNextLink.IsDefaultPort -and $parsedNextLink.Port -ne 443)
        ) {
            throw "Microsoft Graph returned an unsafe pagination URL; refusing to forward credentials"
        }

        $response = Invoke-AzChecked rest --method GET --url $nextLink | ConvertFrom-Json
        if (-not $response -or $response.value -isnot [array]) {
            throw "Microsoft Graph returned an invalid collection response for '$nextLink'"
        }
        if ($response.'@odata.nextLink' -and $response.'@odata.nextLink' -isnot [string]) {
            throw 'Microsoft Graph returned an invalid pagination link'
        }

        $items += @($response.value)
        $nextLink = $response.'@odata.nextLink'
    }

    return $items
}

$account = Invoke-AzChecked account show --output json | ConvertFrom-Json
if (-not $account) {
    throw "Azure CLI is not authenticated. Run 'az login' first."
}
if ($TenantId -and $account.tenantId -ne $TenantId) {
    throw "Current Azure CLI tenant '$($account.tenantId)' does not match requested tenant '$TenantId'."
}

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
Write-Host "[1/6] Fetching app registrations..." -ForegroundColor Yellow
$appList = @(Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/applications?$top=999&$select=id,appId,displayName,web,spa,publicClient,signInAudience,createdDateTime')
Write-Host "  Found $($appList.Count) app registrations"

# --- Fetch OAuth2 Permission Grants (delegated permissions) ---
Write-Host "[2/6] Fetching delegated permission grants..." -ForegroundColor Yellow
$grantList = @(Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants')
Write-Host "  Found $($grantList.Count) permission grants"

# --- Fetch Service Principals ---
Write-Host "[3/6] Fetching service principals..." -ForegroundColor Yellow
$spList = @(Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=100&$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,replyUrls,appRoles,signInAudience')
Write-Host "  Found $($spList.Count) service principals"

$spByAppId = @{}
$spById = @{}
foreach ($sp in $spList) {
    if (-not $sp.id -or -not [guid]::TryParse($sp.id, [ref]([guid]::Empty))) {
        throw 'Microsoft Graph returned a service principal without a valid object ID'
    }
    $spById[$sp.id] = $sp
    if ($sp.appId) { $spByAppId[$sp.appId] = $sp }
}
foreach ($grant in $grantList) {
    if (-not $grant.clientId -or -not $spById.ContainsKey($grant.clientId)) {
        throw 'A delegated grant client was absent from the service-principal inventory. Rerun after directory replication; refusing a partial report.'
    }
}

# Read every client relationship, not appRoleAssignedTo (which lists inbound grants).
# Do not use a nested $expand: each assignment collection can have its own nextLink.
Write-Host "[4/6] Fetching granted application permissions..." -ForegroundColor Yellow
$assignmentsBySpId = @{}
foreach ($sp in $spList) {
    $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $sp.id
    $assignments = @(Get-GraphCollection -Uri $uri)
    foreach ($assignment in $assignments) {
        if ($assignment.principalId -ne $sp.id -or -not $assignment.resourceId -or -not $assignment.appRoleId) {
            throw 'Microsoft Graph returned an invalid client app-role assignment; refusing a partial report'
        }
    }
    $assignmentsBySpId[$sp.id] = $assignments
}

# Include registrations without a tenant SP, and SPs without a local registration
# (for example third-party enterprise apps and managed identities).
$subjects = @()
$includedSpIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($app in $appList) {
    $sp = if ($app.appId) { $spByAppId[$app.appId] } else { $null }
    if ($sp) { [void]$includedSpIds.Add($sp.id) }
    $subjects += [pscustomobject]@{ App = $app; Sp = $sp }
}
foreach ($sp in $spList) {
    if (-not $includedSpIds.Contains($sp.id)) {
        $subjects += [pscustomobject]@{ App = $null; Sp = $sp }
    }
}

# --- Analyze ---
Write-Host "[5/6] Analyzing..." -ForegroundColor Yellow
$findings = @()

foreach ($subject in $subjects) {
    $app = $subject.App
    $sp = $subject.Sp
    $identity = if ($app) { $app } else { $sp }
    $risks = @()
    $redirectUris = @()

    # Collect all redirect URIs
    if ($app.web.redirectUris) { $redirectUris += $app.web.redirectUris }
    if ($app.spa.redirectUris) { $redirectUris += $app.spa.redirectUris }
    if ($app.publicClient.redirectUris) { $redirectUris += $app.publicClient.redirectUris }
    if ($sp.replyUrls) { $redirectUris += $sp.replyUrls }
    $redirectUris = @($redirectUris | Select-Object -Unique)

    # Check for suspicious redirect URIs
    $suspiciousUris = @()
    foreach ($uri in $redirectUris) {
        $parsedUri = $null
        $validUri = [Uri]::TryCreate($uri, [UriKind]::Absolute, [ref]$parsedUri)
        # Only exact parsed loopback hosts are exempt, never path/query substrings.
        if ($validUri -and $parsedUri.Scheme -eq 'http' -and $parsedUri.Host.ToLowerInvariant() -notin @('localhost', '127.0.0.1', '[::1]')) {
            $suspiciousUris += $uri
            $risks += 'NON_HTTPS_REDIRECT'
        }
        # Known suspicious domains. Match the parsed host, not a substring of the
        # whole URI. A bare substring test flags any host that merely contains a
        # pattern - 't.co' matches 'tenant.contoso.com' and 'github.io' matches
        # 'mygithub.iolabs.com' - which buries real findings in false positives.
        $uriHost = $null
        try { $uriHost = ([System.Uri]$uri).Host } catch { $uriHost = $null }
        if ($uriHost) {
            $uriHost = $uriHost.TrimEnd('.').ToLowerInvariant()
            foreach ($pattern in $SuspiciousPatterns) {
                $needle = $pattern.ToLowerInvariant()
                # Exact host, or a subdomain of it.
                if ($uriHost -eq $needle -or $uriHost.EndsWith(".$needle")) {
                    $suspiciousUris += $uri
                    $risks += "SUSPICIOUS_DOMAIN:$pattern"
                    break
                }
            }
        }
    }

    # Check delegated permissions for this app
    $servicePrincipalId = $sp.id
    $appGrants = if ($servicePrincipalId) {
        @($grantList | Where-Object { $_.clientId -eq $servicePrincipalId })
    } else {
        @()
    }
    $highPrivPerms = @()
    foreach ($grant in $appGrants) {
        $scopes = $grant.scope -split ' '
        foreach ($scope in $scopes) {
            if ($scope -in $HighPrivilegeScopes) {
                $highPrivPerms += $scope
                if ($grant.consentType -eq 'Principal') {
                    $risks += "USER_CONSENTED_HIGH_PRIV:$scope"
                } elseif ($grant.consentType -eq 'AllPrincipals') {
                    $risks += "ADMIN_CONSENTED_HIGH_PRIV:$scope"
                } else {
                    $risks += "UNKNOWN_CONSENT_HIGH_PRIV:$scope"
                }
            }
        }
    }

    # Every granted application permission is a review candidate, including
    # custom API roles. Known names are heuristics, not an effective-access proof.
    $applicationPermissions = @()
    if ($servicePrincipalId) {
        foreach ($assignment in $assignmentsBySpId[$servicePrincipalId]) {
            $resource = $spById[$assignment.resourceId]
            $role = @($resource.appRoles | Where-Object { $_.id -eq $assignment.appRoleId })
            $roleValue = if ($assignment.appRoleId -eq '00000000-0000-0000-0000-000000000000') {
                'DEFAULT_ACCESS'
            } elseif ($role.Count -eq 1 -and $role[0].value) {
                $role[0].value
            } else {
                'UNRESOLVED'
            }
            $applicationPermissions += "$($assignment.resourceId)/$($assignment.appRoleId):$roleValue"
            if ($roleValue -eq 'UNRESOLVED') {
                $risks += 'UNRESOLVED_APPLICATION_PERMISSION'
            } elseif ($roleValue -in $HighPrivilegeScopes) {
                $risks += "HIGH_PRIV_APPLICATION_PERMISSION:$roleValue"
            } else {
                $risks += 'APPLICATION_PERMISSION_REVIEW'
            }
        }
    }

    # Check if multi-tenant
    if ($identity.signInAudience -in @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount', 'PersonalMicrosoftAccount')) {
        $risks += "MULTI_TENANT:$($identity.signInAudience)"
    }

    # Build finding
    if ($risks.Count -gt 0) {
        $findings += [PSCustomObject]@{
            AppName           = $identity.displayName
            AppId             = $identity.appId
            ObjectId          = $identity.id
            ObjectType        = if ($app) { 'ApplicationRegistration' } else { 'ServicePrincipal' }
            ServicePrincipalId = $servicePrincipalId
            ServicePrincipalType = $sp.servicePrincipalType
            LocalRegistrationPresent = [bool]$app
            AppOwnerOrganizationId = $sp.appOwnerOrganizationId
            CreatedDate       = $app.createdDateTime
            SignInAudience    = $identity.signInAudience
            RedirectUriCount  = $redirectUris.Count
            SuspiciousUris    = ($suspiciousUris -join '; ')
            HighPrivilegePerms = ($highPrivPerms | Select-Object -Unique) -join '; '
            DelegatedPermissions = ($appGrants | ForEach-Object { "$($_.resourceId):$($_.scope) [$($_.consentType)]" }) -join '; '
            ApplicationPermissions = ($applicationPermissions | Select-Object -Unique) -join '; '
            RiskFlags         = ($risks | Select-Object -Unique) -join '; '
            RiskScore         = $risks.Count
        }
    }
}

# --- Report ---
Write-Host "[6/6] Generating report..." -ForegroundColor Yellow
Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "No findings matched the documented audit checks. This is not a complete effective-access or safety assessment." -ForegroundColor Green
} else {
    $findings = $findings | Sort-Object -Property RiskScore -Descending
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    # Quoting CSV does not stop spreadsheet formula interpretation. Neutralize
    # untrusted text only in the export; retain original values for analysis.
    $csvFindings = foreach ($finding in $findings) {
        $row = [ordered]@{}
        foreach ($property in $finding.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string] -and ($value -match '^\s*[=+@-]' -or $value -match '^[\t\r\n]')) {
                $value = "'$value"
            }
            $row[$property.Name] = $value
        }
        [pscustomobject]$row
    }
    $csvFindings | Export-Csv -LiteralPath $OutputPath -NoTypeInformation
    Write-Host "=== FINDINGS SUMMARY ===" -ForegroundColor Red
    Write-Host "Applications/service principals requiring review: $($findings.Count)" -ForegroundColor Red
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
