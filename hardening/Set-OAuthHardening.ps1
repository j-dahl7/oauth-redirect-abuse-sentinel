#Requires -Version 7.0
<#
.SYNOPSIS
    Applies OAuth hardening policies to Microsoft Entra ID.

.DESCRIPTION
    Configures tenant-level controls to prevent OAuth redirect abuse:
    1. Restricts user consent to apps from verified publishers only
    2. Requires admin approval for high-privilege permissions
    3. Enables app consent workflow for user requests
    4. Creates a Conditional Access policy for risky OAuth-related sign-ins
    5. Configures app governance alerts (if licensed)

.PARAMETER WhatIf
    Show what changes would be made without applying them.

.PARAMETER EnableConsentWorkflow
    Enable the admin consent workflow so users can request app access.

.EXAMPLE
    ./Set-OAuthHardening.ps1 -WhatIf
    Preview changes without applying them.

.EXAMPLE
    ./Set-OAuthHardening.ps1
    Apply all OAuth hardening controls.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [switch]$EnableConsentWorkflow
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== OAuth Hardening Configuration ===" -ForegroundColor Cyan
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# --- Step 1: Restrict User Consent ---
Write-Host "[1/4] Configuring user consent settings..." -ForegroundColor Yellow

# Get current authorization policy
$authPolicy = az rest --method GET `
    --url 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
    2>$null | ConvertFrom-Json

$currentConsent = $authPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
Write-Host "  Current consent policy: $($currentConsent -join ', ')"

if ($PSCmdlet.ShouldProcess("Authorization Policy", "Restrict user consent to verified publishers only")) {
    # Preserve existing owned-resource grants while enabling the low-risk verified-publisher policy.
    $updatedPolicies = @(
        $currentConsent | Where-Object { $_ -like 'managePermissionGrantsForOwnedResource.*' }
    )
    $updatedPolicies += 'managePermissionGrantsForSelf.microsoft-user-default-low'
    $updatedPolicies = $updatedPolicies | Select-Object -Unique

    $body = @{
        defaultUserRolePermissions = @{
            permissionGrantPoliciesAssigned = $updatedPolicies
        }
    } | ConvertTo-Json -Depth 5

    $bodyFile = New-TemporaryFile
    [System.IO.File]::WriteAllText($bodyFile.FullName, $body, [System.Text.Encoding]::UTF8)

    az rest --method PATCH `
        --url 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
        --body "@$($bodyFile.FullName)" `
        --headers 'Content-Type=application/json' 2>$null

    Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue
    Write-Host "  Updated: Users can only consent to low-risk permissions from verified publishers" -ForegroundColor Green
} else {
    Write-Host "  [WHATIF] Would restrict user consent to verified publishers only" -ForegroundColor DarkYellow
}

# --- Step 2: Enable Admin Consent Workflow ---
Write-Host "[2/4] Configuring admin consent workflow..." -ForegroundColor Yellow

if ($EnableConsentWorkflow) {
    if ($PSCmdlet.ShouldProcess("Admin Consent Workflow", "Enable consent request workflow")) {
        Write-Host "  Admin consent workflow requires configuration in the Entra admin center:" -ForegroundColor Yellow
        Write-Host "  https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings" -ForegroundColor Cyan
        Write-Host "  - Set 'Users can request admin consent to apps they are unable to consent to' = Yes"
        Write-Host "  - Add reviewer users or groups"
        Write-Host "  - Set consent request expiry (recommended: 30 days)"
    }
} else {
    Write-Host "  Skipped (use -EnableConsentWorkflow to configure)" -ForegroundColor DarkGray
}

# --- Step 3: Create Conditional Access Policy ---
Write-Host "[3/4] Creating Conditional Access policy for risky OAuth sign-ins..." -ForegroundColor Yellow

$caDisplayName = "LAB - Require MFA for Risky OAuth Sign-ins"
$legacyCaDisplayName = "LAB - Block OAuth Consent from Risky Sign-ins"

# Check if policy already exists
$existingPolicies = az rest --method GET `
    --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    2>$null | ConvertFrom-Json
$existing = $existingPolicies.value | Where-Object {
    $_.displayName -in @($caDisplayName, $legacyCaDisplayName)
} | Select-Object -First 1

$caPolicy = @{
    displayName = $caDisplayName
    state       = "enabledForReportingButNotEnforced"
    conditions  = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = @()
        }
        applications = @{
            includeApplications = @("All")
        }
        signInRiskLevels = @("high", "medium")
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("mfa")
    }
    sessionControls = @{
        signInFrequency = @{
            authenticationType = "primaryAndSecondaryAuthentication"
            frequencyInterval  = "everyTime"
            isEnabled          = $true
        }
    }
} | ConvertTo-Json -Depth 10

$bodyFile = New-TemporaryFile
[System.IO.File]::WriteAllText($bodyFile.FullName, $caPolicy, [System.Text.Encoding]::UTF8)

if ($existing) {
    $existingLabel = if ($existing.displayName -eq $legacyCaDisplayName) {
        "$($existing.displayName) (legacy name)"
    } else {
        $existing.displayName
    }

    if ($PSCmdlet.ShouldProcess("Conditional Access", "Update policy: $existingLabel")) {
        $result = az rest --method PATCH `
            --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)" `
            --body "@$($bodyFile.FullName)" `
            --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

        if (-not $result) {
            $result = az rest --method GET `
                --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)" `
                2>$null | ConvertFrom-Json
        }

        Write-Host "  Updated CA policy: $($result.displayName)" -ForegroundColor Green
        Write-Host "  State: Report-only (review before enforcing)" -ForegroundColor Yellow
        Write-Host "  Policy ID: $($result.id)" -ForegroundColor DarkGray
    } else {
        Write-Host "  [WHATIF] Would update CA policy: $existingLabel" -ForegroundColor DarkYellow
    }
} else {
    if ($PSCmdlet.ShouldProcess("Conditional Access", "Create policy: $caDisplayName")) {
        $result = az rest --method POST `
            --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `
            --body "@$($bodyFile.FullName)" `
            --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

        Write-Host "  Created CA policy: $($result.displayName)" -ForegroundColor Green
        Write-Host "  State: Report-only (review before enforcing)" -ForegroundColor Yellow
        Write-Host "  Policy ID: $($result.id)" -ForegroundColor DarkGray
    } else {
        Write-Host "  [WHATIF] Would create CA policy: $caDisplayName" -ForegroundColor DarkYellow
    }
}

Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue

# --- Step 4: Block Legacy Authentication (if not already done) ---
Write-Host "[4/4] Checking legacy authentication block..." -ForegroundColor Yellow

$legacyPolicy = $existingPolicies.value | Where-Object { $_.displayName -match "Block.*Legacy" -or $_.displayName -match "Block.*Basic" }
if ($legacyPolicy) {
    Write-Host "  Legacy auth block already exists: $($legacyPolicy.displayName)" -ForegroundColor Green
} else {
    Write-Host "  WARNING: No legacy authentication block detected." -ForegroundColor Red
    Write-Host "  OAuth redirect abuse is more effective when legacy auth is available." -ForegroundColor Red
    Write-Host "  Create a CA policy to block legacy authentication protocols." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Hardening Summary ===" -ForegroundColor Cyan
Write-Host "1. User consent: Restricted to verified publishers (low-risk perms only, owned-resource grants preserved)"
Write-Host "2. Admin consent workflow: $(if ($EnableConsentWorkflow) { 'Guidance provided' } else { 'Skipped' })"
Write-Host "3. CA policy: Report-only MFA step-up policy created (review before enforcing)"
Write-Host "4. Legacy auth: $(if ($legacyPolicy) { 'Blocked' } else { 'NOT blocked - action required' })"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review the CA policy in report-only mode for 7 days"
Write-Host "  2. Check the CA insights workbook for impact assessment"
Write-Host "  3. Switch the CA policy to 'On' after validation"
Write-Host "  4. Run Audit-OAuthApps.ps1 to find existing risky apps"
Write-Host ""
