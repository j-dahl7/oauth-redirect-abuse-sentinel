#Requires -Version 7.3
<#
.SYNOPSIS
    Applies or rolls back explicitly owned OAuth hardening changes in Microsoft Entra ID.

.DESCRIPTION
    Restricts tenant user consent and creates one report-only Conditional Access (CA)
    policy. Cloud writes are fail-closed: the operator must confirm the exact tenant,
    supply reviewed emergency-access exclusions, and persist a local owner-only
    manifest. The manifest records the original consent policy, intended policy hashes,
    and the exact server-assigned CA policy ID. A same-named CA policy is never adopted.

    Rollback restores the exact captured consent collection and deletes only the exact
    CA policy ID in the manifest after verifying that its managed content has not drifted.

.PARAMETER ConfirmTenantId
    Exact Entra tenant GUID expected from the active Azure CLI account. Required for
    apply and rollback. This prevents a valid command from changing the wrong tenant.

.PARAMETER ExcludedUserIds
    One or more reviewed Entra user object IDs to exclude from the report-only CA policy.
    Actual apply fails closed when this list is empty or contains a non-GUID value.

.PARAMETER ManifestPath
    Path to the ownership and rollback manifest. It is created with owner-only access
    before the first Graph mutation and updated atomically after each completed stage.

.PARAMETER Rollback
    Restore the captured consent collection and delete only the exact owned CA policy.

.PARAMETER WhatIf
    Perform discovery and validation but skip the manifest and Graph writes.

.EXAMPLE
    ./Set-OAuthHardening.ps1 -ConfirmTenantId '<tenant-guid>' `
      -ExcludedUserIds @('<break-glass-object-guid>') -WhatIf

.EXAMPLE
    ./Set-OAuthHardening.ps1 -ConfirmTenantId '<tenant-guid>' `
      -ExcludedUserIds @('<break-glass-object-guid>')

.EXAMPLE
    ./Set-OAuthHardening.ps1 -ConfirmTenantId '<tenant-guid>' -Rollback
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [switch]$EnableConsentWorkflow,

    [Parameter()]
    [string]$ConfirmTenantId,

    [Parameter()]
    [string[]]$ExcludedUserIds = @(),

    [Parameter()]
    [string]$ManifestPath = (Join-Path $PSScriptRoot '.oauth-hardening-manifest.json'),

    [Parameter()]
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$ManifestOwner = 'nine-lives-zero-trust:oauth-redirect-abuse-sentinel'
$ManifestSchemaVersion = 1
$CaDisplayName = 'LAB - Require MFA for Risky OAuth Sign-ins'
$LegacyCaDisplayName = 'LAB - Block OAuth Consent from Risky Sign-ins'
$AuthorizationPolicyUrl = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
$ConditionalAccessPoliciesUrl = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    return [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Get-NormalizedStringArray {
    param([AllowNull()][object]$Value)

    return @(
        @($Value) |
            ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )
}

function Test-EquivalentStringArrays {
    param(
        [AllowNull()][object]$Left,
        [AllowNull()][object]$Right
    )

    $leftJson = @(Get-NormalizedStringArray $Left) | ConvertTo-Json -Compress
    $rightJson = @(Get-NormalizedStringArray $Right) | ConvertTo-Json -Compress
    return $leftJson -ceq $rightJson
}

function Get-ConditionalAccessFingerprintObject {
    param(
        [Parameter(Mandatory)]
        [object]$Policy
    )

    # Normalize every writable scope/control field that can materially change who
    # the policy targets or what it requires. Missing and empty optional arrays are
    # equivalent; ordering is not meaningful in Graph policy collections.
    return [ordered]@{
        displayName = [string]$Policy.displayName
        state = [string]$Policy.state
        conditions = [ordered]@{
            users = [ordered]@{
                includeUsers = @(Get-NormalizedStringArray $Policy.conditions.users.includeUsers)
                excludeUsers = @(Get-NormalizedStringArray $Policy.conditions.users.excludeUsers)
                includeGroups = @(Get-NormalizedStringArray $Policy.conditions.users.includeGroups)
                excludeGroups = @(Get-NormalizedStringArray $Policy.conditions.users.excludeGroups)
                includeRoles = @(Get-NormalizedStringArray $Policy.conditions.users.includeRoles)
                excludeRoles = @(Get-NormalizedStringArray $Policy.conditions.users.excludeRoles)
                includeGuestTypes = [string]$Policy.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes
                includeExternalTenantMembership = [string]$Policy.conditions.users.includeGuestsOrExternalUsers.externalTenants.membershipKind
                includeExternalTenantIds = @(Get-NormalizedStringArray $Policy.conditions.users.includeGuestsOrExternalUsers.externalTenants.members)
                excludeGuestTypes = [string]$Policy.conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes
                excludeExternalTenantMembership = [string]$Policy.conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind
                excludeExternalTenantIds = @(Get-NormalizedStringArray $Policy.conditions.users.excludeGuestsOrExternalUsers.externalTenants.members)
            }
            clientApplications = [ordered]@{
                includeServicePrincipals = @(Get-NormalizedStringArray $Policy.conditions.clientApplications.includeServicePrincipals)
                excludeServicePrincipals = @(Get-NormalizedStringArray $Policy.conditions.clientApplications.excludeServicePrincipals)
                servicePrincipalFilterMode = [string]$Policy.conditions.clientApplications.servicePrincipalFilter.mode
                servicePrincipalFilterRule = [string]$Policy.conditions.clientApplications.servicePrincipalFilter.rule
            }
            applications = [ordered]@{
                includeApplications = @(Get-NormalizedStringArray $Policy.conditions.applications.includeApplications)
                excludeApplications = @(Get-NormalizedStringArray $Policy.conditions.applications.excludeApplications)
                includeUserActions = @(Get-NormalizedStringArray $Policy.conditions.applications.includeUserActions)
                includeAuthenticationContextClassReferences = @(Get-NormalizedStringArray $Policy.conditions.applications.includeAuthenticationContextClassReferences)
                applicationFilterMode = [string]$Policy.conditions.applications.applicationFilter.mode
                applicationFilterRule = [string]$Policy.conditions.applications.applicationFilter.rule
            }
            clientAppTypes = @(Get-NormalizedStringArray $Policy.conditions.clientAppTypes)
            signInRiskLevels = @(Get-NormalizedStringArray $Policy.conditions.signInRiskLevels)
            userRiskLevels = @(Get-NormalizedStringArray $Policy.conditions.userRiskLevels)
            servicePrincipalRiskLevels = @(Get-NormalizedStringArray $Policy.conditions.servicePrincipalRiskLevels)
            locations = [ordered]@{
                includeLocations = @(Get-NormalizedStringArray $Policy.conditions.locations.includeLocations)
                excludeLocations = @(Get-NormalizedStringArray $Policy.conditions.locations.excludeLocations)
            }
            platforms = [ordered]@{
                includePlatforms = @(Get-NormalizedStringArray $Policy.conditions.platforms.includePlatforms)
                excludePlatforms = @(Get-NormalizedStringArray $Policy.conditions.platforms.excludePlatforms)
            }
            devices = [ordered]@{
                mode = [string]$Policy.conditions.devices.deviceFilter.mode
                rule = [string]$Policy.conditions.devices.deviceFilter.rule
            }
            authenticationFlows = [ordered]@{
                transferMethods = [string]$Policy.conditions.authenticationFlows.transferMethods
            }
            insiderRiskLevels = [string]$Policy.conditions.insiderRiskLevels
        }
        grantControls = [ordered]@{
            operator = [string]$Policy.grantControls.operator
            builtInControls = @(Get-NormalizedStringArray $Policy.grantControls.builtInControls)
            customAuthenticationFactors = @(Get-NormalizedStringArray $Policy.grantControls.customAuthenticationFactors)
            termsOfUse = @(Get-NormalizedStringArray $Policy.grantControls.termsOfUse)
            authenticationStrengthId = [string]$Policy.grantControls.authenticationStrength.id
        }
        sessionControls = [ordered]@{
            signInFrequency = [ordered]@{
                authenticationType = [string]$Policy.sessionControls.signInFrequency.authenticationType
                frequencyInterval = [string]$Policy.sessionControls.signInFrequency.frequencyInterval
                isEnabled = [bool]$Policy.sessionControls.signInFrequency.isEnabled
                type = [string]$Policy.sessionControls.signInFrequency.type
                value = $Policy.sessionControls.signInFrequency.value
            }
            persistentBrowser = [ordered]@{
                isEnabled = [bool]$Policy.sessionControls.persistentBrowser.isEnabled
                mode = [string]$Policy.sessionControls.persistentBrowser.mode
            }
            applicationEnforcedRestrictionsEnabled = [bool]$Policy.sessionControls.applicationEnforcedRestrictions.isEnabled
            cloudAppSecurityEnabled = [bool]$Policy.sessionControls.cloudAppSecurity.isEnabled
            cloudAppSecurityType = [string]$Policy.sessionControls.cloudAppSecurity.cloudAppSecurityType
            continuousAccessEvaluationMode = [string]$Policy.sessionControls.continuousAccessEvaluation.mode
            disableResilienceDefaults = $Policy.sessionControls.disableResilienceDefaults
            secureSignInSessionEnabled = [bool]$Policy.sessionControls.secureSignInSession.isEnabled
        }
    }
}

function Get-ConditionalAccessHash {
    param(
        [Parameter(Mandatory)]
        [object]$Policy
    )

    $canonicalJson = Get-ConditionalAccessFingerprintObject $Policy |
        ConvertTo-Json -Depth 20 -Compress
    return Get-Sha256Hex $canonicalJson
}

function Set-OwnerOnlyFilePermissions {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $acl = [System.Security.AccessControl.FileSecurity]::new()
        $acl.SetOwner($identity.User)
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity.User,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    } else {
        $ownerMode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
        [System.IO.File]::SetUnixFileMode($Path, $ownerMode)
    }
}

function Assert-OwnerOnlyManifest {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType) {
        throw "Refusing manifest symlink/reparse point '$Path'."
    }

    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )) {
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $foreignAllowRules = @(
            (Get-Acl -LiteralPath $Path).Access | Where-Object {
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -ne $currentSid
            }
        )
        if ($foreignAllowRules.Count -gt 0) {
            throw "Manifest '$Path' grants access to a principal other than its owner."
        }
    } else {
        $mode = [System.IO.File]::GetUnixFileMode($Path)
        $nonOwnerBits =
            [System.IO.UnixFileMode]::GroupRead -bor
            [System.IO.UnixFileMode]::GroupWrite -bor
            [System.IO.UnixFileMode]::GroupExecute -bor
            [System.IO.UnixFileMode]::OtherRead -bor
            [System.IO.UnixFileMode]::OtherWrite -bor
            [System.IO.UnixFileMode]::OtherExecute
        if (($mode -band $nonOwnerBits) -ne 0) {
            throw "Manifest '$Path' is not owner-only (expected mode 0600)."
        }
    }
}

function Write-OwnerOnlyManifest {
    param(
        [Parameter(Mandatory)]
        [object]$Manifest,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $directory = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $Manifest.updatedAtUtc = [DateTime]::UtcNow.ToString('o')
    $json = $Manifest | ConvertTo-Json -Depth 30

    if (-not (Test-Path -LiteralPath $fullPath)) {
        $stream = [System.IO.File]::Open(
            $fullPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            $writer = [System.IO.StreamWriter]::new(
                $stream,
                [System.Text.UTF8Encoding]::new($false)
            )
            try {
                $writer.Write($json)
                $writer.Flush()
            } finally {
                $writer.Dispose()
            }
        } finally {
            $stream.Dispose()
        }
        Set-OwnerOnlyFilePermissions $fullPath
    } else {
        Assert-OwnerOnlyManifest $fullPath
        $temporaryPath = "$fullPath.$([guid]::NewGuid().ToString('N')).tmp"
        try {
            [System.IO.File]::WriteAllText(
                $temporaryPath,
                $json,
                [System.Text.UTF8Encoding]::new($false)
            )
            Set-OwnerOnlyFilePermissions $temporaryPath
            [System.IO.File]::Move($temporaryPath, $fullPath, $true)
        } finally {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }

    Assert-OwnerOnlyManifest $fullPath
}

function Read-OwnershipManifest {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        return $null
    }

    Assert-OwnerOnlyManifest $fullPath
    $manifest = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne $ManifestSchemaVersion -or $manifest.owner -cne $ManifestOwner) {
        throw "Manifest '$fullPath' is not owned by this lab or uses an unsupported schema."
    }
    return $manifest
}

function Invoke-GraphJsonRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PATCH', 'POST', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter()]
        [string]$JsonBody
    )

    if ($Method -eq 'DELETE') {
        return az rest --method DELETE --url $Url
    }

    $bodyFile = New-TemporaryFile
    try {
        [System.IO.File]::WriteAllText(
            $bodyFile.FullName,
            $JsonBody,
            [System.Text.UTF8Encoding]::new($false)
        )
        return az rest --method $Method `
            --url $Url `
            --body "@$($bodyFile.FullName)" `
            --headers 'Content-Type=application/json'
    } finally {
        Remove-Item -LiteralPath $bodyFile.FullName -Force -ErrorAction SilentlyContinue
    }
}

function Get-ExactConditionalAccessPolicy {
    param([string]$PolicyId)

    if ([string]::IsNullOrWhiteSpace($PolicyId)) {
        return $null
    }
    return az rest --method GET --url "$ConditionalAccessPoliciesUrl/$PolicyId" `
        2>$null | ConvertFrom-Json
}

function Get-AllConditionalAccessPolicies {
    $nextUrl = $ConditionalAccessPoliciesUrl
    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $policies = [System.Collections.Generic.List[object]]::new()

    while (-not [string]::IsNullOrWhiteSpace($nextUrl)) {
        if (-not $visited.Add($nextUrl)) {
            throw 'Conditional Access policy pagination returned a repeated nextLink.'
        }

        $page = az rest --method GET --url $nextUrl 2>$null | ConvertFrom-Json
        foreach ($policy in @($page.value)) {
            $policies.Add($policy)
        }

        $nextUrl = [string]$page.'@odata.nextLink'
        if (-not [string]::IsNullOrWhiteSpace($nextUrl)) {
            $parsedNextLink = [uri]$nextUrl
            if (
                $parsedNextLink.Scheme -ne 'https' -or
                $parsedNextLink.Host -ne 'graph.microsoft.com' -or
                $parsedNextLink.UserInfo
            ) {
                throw "Refusing unsafe Microsoft Graph pagination URL '$nextUrl'."
            }
        }
    }

    return @($policies)
}

function Assert-ExactTenantConfirmation {
    param(
        [Parameter(Mandatory)]
        [string]$ActualTenantId,

        [AllowEmptyString()]
        [string]$ConfirmedTenantId,

        [switch]$Preview
    )

    $parsed = [guid]::Empty
    $validConfirmation =
        -not [string]::IsNullOrWhiteSpace($ConfirmedTenantId) -and
        [guid]::TryParse($ConfirmedTenantId, [ref]$parsed) -and
        $parsed -ne [guid]::Empty -and
        $ConfirmedTenantId -ieq $ActualTenantId

    if (-not $validConfirmation) {
        if ($Preview) {
            Write-Host "  [WHATIF] Apply/rollback would require -ConfirmTenantId '$ActualTenantId'." -ForegroundColor DarkYellow
            return $false
        }
        throw "Tenant confirmation failed. Re-run with -ConfirmTenantId '$ActualTenantId' after verifying the active tenant."
    }
    return $true
}

function Assert-ReviewedExclusions {
    param(
        [AllowNull()][string[]]$UserIds,
        [switch]$Preview
    )

    $normalized = @(Get-NormalizedStringArray $UserIds)
    $invalid = @(
        $normalized | Where-Object {
            $candidate = [guid]::Empty
            -not [guid]::TryParse($_, [ref]$candidate) -or $candidate -eq [guid]::Empty
        }
    )
    if ($normalized.Count -eq 0 -or $invalid.Count -gt 0) {
        if ($Preview) {
            Write-Host '  [WHATIF] Actual apply would require at least one reviewed, non-zero emergency-access object GUID.' -ForegroundColor DarkYellow
            return @()
        }
        throw 'Apply requires at least one reviewed emergency-access object GUID in -ExcludedUserIds; empty, zero, and non-GUID values fail closed.'
    }
    return $normalized
}

function New-ConditionalAccessPolicyBody {
    param([string[]]$Exclusions)

    return [ordered]@{
        displayName = $CaDisplayName
        state = 'enabledForReportingButNotEnforced'
        conditions = [ordered]@{
            users = [ordered]@{
                includeUsers = @('All')
                excludeUsers = @($Exclusions)
            }
            applications = [ordered]@{
                includeApplications = @('All')
            }
            clientAppTypes = @('all')
            signInRiskLevels = @('high', 'medium')
        }
        grantControls = [ordered]@{
            operator = 'OR'
            builtInControls = @('mfa')
        }
        sessionControls = [ordered]@{
            signInFrequency = [ordered]@{
                authenticationType = 'primaryAndSecondaryAuthentication'
                frequencyInterval = 'everyTime'
                isEnabled = $true
            }
        }
    }
}

function Assert-NoForeignNameCollision {
    param(
        [object[]]$Policies,
        [AllowNull()][string]$OwnedPolicyId
    )

    $collisions = @(
        $Policies | Where-Object {
            $_.displayName -in @($CaDisplayName, $LegacyCaDisplayName) -and
            ([string]::IsNullOrWhiteSpace($OwnedPolicyId) -or $_.id -ne $OwnedPolicyId)
        }
    )
    if ($collisions.Count -gt 0) {
        $labels = $collisions | ForEach-Object { "$($_.displayName) [$($_.id)]" }
        throw "A same-named Conditional Access policy is not the exact manifest-owned ID. Refusing to adopt or overwrite it: $($labels -join ', ')"
    }
}

function Assert-OwnedPolicyUnchanged {
    param(
        [Parameter(Mandatory)]
        [object]$Policy,
        [Parameter(Mandatory)]
        [string]$ExpectedId,
        [Parameter(Mandatory)]
        [string]$ExpectedHash
    )

    if ($Policy.id -cne $ExpectedId -or $Policy.displayName -cne $CaDisplayName) {
        throw 'Conditional Access policy immutable ID or display name does not match the ownership manifest.'
    }
    $actualHash = Get-ConditionalAccessHash $Policy
    if ($actualHash -cne $ExpectedHash) {
        throw "Conditional Access policy '$ExpectedId' drifted from the manifest-intended content; refusing to update or delete it."
    }
}

function Invoke-HardeningRollback {
    param(
        [Parameter(Mandatory)]
        [object]$Manifest,
        [Parameter(Mandatory)]
        [object]$AuthorizationPolicy,
        [Parameter(Mandatory)]
        [object[]]$AllPolicies,
        [Parameter(Mandatory)]
        [string]$ResolvedManifestPath
    )

    $ownedPolicyId = [string]$Manifest.conditionalAccess.id
    Assert-NoForeignNameCollision -Policies $AllPolicies -OwnedPolicyId $ownedPolicyId
    $ownedPolicy = if (-not [string]::IsNullOrWhiteSpace($ownedPolicyId)) {
        Get-ExactConditionalAccessPolicy $ownedPolicyId
    } else {
        $null
    }
    if ($ownedPolicy) {
        Assert-OwnedPolicyUnchanged `
            -Policy $ownedPolicy `
            -ExpectedId $ownedPolicyId `
            -ExpectedHash ([string]$Manifest.conditionalAccess.intendedHash)
    }

    $currentConsent = @($AuthorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
    $originalConsent = @($Manifest.authorizationPolicy.originalPermissionGrantPoliciesAssigned)
    $intendedConsent = @($Manifest.authorizationPolicy.intendedPermissionGrantPoliciesAssigned)
    $consentIsOriginal = Test-EquivalentStringArrays $currentConsent $originalConsent
    $consentIsIntended = Test-EquivalentStringArrays $currentConsent $intendedConsent
    if (-not $consentIsOriginal -and -not $consentIsIntended) {
        throw 'Tenant consent policy drifted from both the captured original and lab-intended collections; refusing rollback.'
    }

    if ($WhatIfPreference) {
        Write-Host '  [WHATIF] Would restore the exact captured consent-policy collection.' -ForegroundColor DarkYellow
        if ($ownedPolicy) {
            Write-Host "  [WHATIF] Would delete exact CA policy ID $ownedPolicyId after the drift check." -ForegroundColor DarkYellow
        }
        return
    }

    if (-not $consentIsOriginal -and $PSCmdlet.ShouldProcess(
        'Authorization Policy',
        'Restore exact captured permissionGrantPoliciesAssigned collection'
    )) {
        $restoreBody = [ordered]@{
            defaultUserRolePermissions = [ordered]@{
                permissionGrantPoliciesAssigned = @($originalConsent)
            }
        } | ConvertTo-Json -Depth 8
        $null = Invoke-GraphJsonRequest `
            -Method PATCH `
            -Url $AuthorizationPolicyUrl `
            -JsonBody $restoreBody
        $Manifest.state = 'rollback-consent-restored'
        Write-OwnerOnlyManifest -Manifest $Manifest -Path $ResolvedManifestPath
    }

    if ($ownedPolicy -and $PSCmdlet.ShouldProcess(
        "Conditional Access policy $ownedPolicyId",
        'Delete exact manifest-owned policy'
    )) {
        try {
            $null = Invoke-GraphJsonRequest `
                -Method DELETE `
                -Url "$ConditionalAccessPoliciesUrl/$ownedPolicyId"
        } catch {
            $Manifest.state = 'rollback-consent-restored-ca-delete-failed'
            $Manifest.lastError = $_.Exception.Message
            Write-OwnerOnlyManifest -Manifest $Manifest -Path $ResolvedManifestPath
            throw
        }
    }

    $Manifest.state = 'rolled-back'
    $Manifest.rolledBackAtUtc = [DateTime]::UtcNow.ToString('o')
    $Manifest.lastError = $null
    Write-OwnerOnlyManifest -Manifest $Manifest -Path $ResolvedManifestPath
    Write-Host '  Restored captured consent settings and removed only the exact owned CA policy.' -ForegroundColor Green
}

Write-Host "`n=== OAuth Hardening Configuration ===" -ForegroundColor Cyan
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

$account = az account show 2>$null | ConvertFrom-Json
$actualTenantId = [string]$account.tenantId
if ([string]::IsNullOrWhiteSpace($actualTenantId)) {
    throw 'Azure CLI did not return an active Entra tenant. Run az login and select the intended subscription.'
}
$tenantConfirmed = Assert-ExactTenantConfirmation `
    -ActualTenantId $actualTenantId `
    -ConfirmedTenantId $ConfirmTenantId `
    -Preview:$WhatIfPreference
Write-Host "Tenant: $actualTenantId"

$resolvedManifestPath = [System.IO.Path]::GetFullPath($ManifestPath)
$manifest = Read-OwnershipManifest -Path $resolvedManifestPath
if ($manifest -and [string]$manifest.tenantId -cne $actualTenantId) {
    throw "Manifest tenant '$($manifest.tenantId)' does not match active tenant '$actualTenantId'."
}

$authorizationPolicy = az rest --method GET --url $AuthorizationPolicyUrl `
    2>$null | ConvertFrom-Json
$allPolicies = @(Get-AllConditionalAccessPolicies)

if ($Rollback) {
    if (-not $manifest) {
        throw "Rollback requires the owner-only manifest '$resolvedManifestPath'."
    }
    if (-not $tenantConfirmed -and $WhatIfPreference) {
        Write-Host '  [WHATIF] Tenant confirmation is missing; no rollback can be applied.' -ForegroundColor DarkYellow
    }
    Invoke-HardeningRollback `
        -Manifest $manifest `
        -AuthorizationPolicy $authorizationPolicy `
        -AllPolicies $allPolicies `
        -ResolvedManifestPath $resolvedManifestPath
    return
}

$reviewedExclusions = @(Assert-ReviewedExclusions `
    -UserIds $ExcludedUserIds `
    -Preview:$WhatIfPreference)
$caPolicyObject = New-ConditionalAccessPolicyBody -Exclusions $reviewedExclusions
$caPolicyJson = $caPolicyObject | ConvertTo-Json -Depth 20
$caPolicyHash = Get-ConditionalAccessHash $caPolicyObject

$currentConsent = @(
    $authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
)
$intendedConsent = @(
    $currentConsent | Where-Object { $_ -like 'managePermissionGrantsForOwnedResource.*' }
)
$intendedConsent += 'managePermissionGrantsForSelf.microsoft-user-default-low'
$intendedConsent = @(Get-NormalizedStringArray $intendedConsent)

if ($manifest) {
    if ($manifest.state -eq 'rolled-back') {
        throw "Manifest '$resolvedManifestPath' is a completed rollback record. Archive it and choose a new manifest path for a new apply operation."
    }
    if ($manifest.state -eq 'ca-create-uncertain') {
        throw 'A prior CA create request has an uncertain outcome. Inspect Conditional Access by immutable ID/audit history; do not rerun or create another policy until ownership is resolved.'
    }
    if (-not (Test-EquivalentStringArrays $manifest.conditionalAccess.excludedUserIds $reviewedExclusions)) {
        throw 'ExcludedUserIds differ from the immutable ownership manifest. Roll back first; do not mutate an owned CA policy in place.'
    }
    if ([string]$manifest.conditionalAccess.intendedHash -cne $caPolicyHash) {
        throw 'The intended Conditional Access content differs from the ownership manifest. Roll back first; do not update the owned policy in place.'
    }
} else {
    Assert-NoForeignNameCollision -Policies $allPolicies -OwnedPolicyId $null
    $manifest = [pscustomobject]@{
        schemaVersion = $ManifestSchemaVersion
        owner = $ManifestOwner
        tenantId = $actualTenantId
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        updatedAtUtc = [DateTime]::UtcNow.ToString('o')
        appliedAtUtc = $null
        rolledBackAtUtc = $null
        state = 'prepared'
        authorizationPolicy = [pscustomobject]@{
            id = [string]$authorizationPolicy.id
            originalPermissionGrantPoliciesAssigned = @($currentConsent)
            intendedPermissionGrantPoliciesAssigned = @($intendedConsent)
            intendedHash = Get-Sha256Hex (
                @($intendedConsent) | ConvertTo-Json -Compress
            )
        }
        conditionalAccess = [pscustomobject]@{
            displayName = $CaDisplayName
            id = $null
            intendedHash = $caPolicyHash
            excludedUserIds = @($reviewedExclusions)
        }
        removedPolicyIds = @()
        lastError = $null
    }
}

$ownedPolicyId = [string]$manifest.conditionalAccess.id
Assert-NoForeignNameCollision -Policies $allPolicies -OwnedPolicyId $ownedPolicyId
$ownedPolicy = if (-not [string]::IsNullOrWhiteSpace($ownedPolicyId)) {
    Get-ExactConditionalAccessPolicy $ownedPolicyId
} else {
    $null
}
if ($ownedPolicy) {
    Assert-OwnedPolicyUnchanged `
        -Policy $ownedPolicy `
        -ExpectedId $ownedPolicyId `
        -ExpectedHash ([string]$manifest.conditionalAccess.intendedHash)
}

if ($WhatIfPreference) {
    Write-Host "  [WHATIF] Would persist owner-only manifest: $resolvedManifestPath" -ForegroundColor DarkYellow
    Write-Host '  [WHATIF] Would create, never adopt, one report-only CA policy and record its exact ID.' -ForegroundColor DarkYellow
    Write-Host '  [WHATIF] Would then restrict user consent while preserving owned-resource grants.' -ForegroundColor DarkYellow
    return
}

if (-not $tenantConfirmed) {
    throw 'Tenant confirmation is required before cloud writes.'
}

# This is deliberately before the first Graph mutation. Graph assigns CA policy
# IDs server-side; the prepared manifest records null, then the exact returned ID
# is atomically persisted before the authorization-policy write.
Write-OwnerOnlyManifest -Manifest $manifest -Path $resolvedManifestPath

if (-not $ownedPolicy) {
    if ($PSCmdlet.ShouldProcess('Conditional Access', "Create new policy: $CaDisplayName")) {
        $createdPolicyId = $null
        try {
            $created = Invoke-GraphJsonRequest `
                -Method POST `
                -Url $ConditionalAccessPoliciesUrl `
                -JsonBody $caPolicyJson | ConvertFrom-Json
            $createdPolicyId = [string]$created.id
            if ([string]::IsNullOrWhiteSpace($createdPolicyId)) {
                throw 'Graph did not return the immutable ID of the created Conditional Access policy.'
            }
            $manifest.conditionalAccess.id = $createdPolicyId
            $manifest.state = 'ca-created'
            $manifest.lastError = $null
            Write-OwnerOnlyManifest -Manifest $manifest -Path $resolvedManifestPath
            $ownedPolicyId = $createdPolicyId
            $ownedPolicy = $caPolicyObject
            $ownedPolicy | Add-Member -NotePropertyName id -NotePropertyValue $createdPolicyId
        } catch {
            $manifest.state = if ($createdPolicyId) { 'ca-created-manifest-failed' } else { 'ca-create-uncertain' }
            $manifest.lastError = $_.Exception.Message
            if ($createdPolicyId) {
                try {
                    $null = Invoke-GraphJsonRequest `
                        -Method DELETE `
                        -Url "$ConditionalAccessPoliciesUrl/$createdPolicyId"
                    $manifest.removedPolicyIds = @($manifest.removedPolicyIds) + $createdPolicyId
                    $manifest.conditionalAccess.id = $null
                    $manifest.state = 'prepared'
                } catch {
                    # Preserve the known exact ID. A rerun can only act on that ID.
                    $manifest.conditionalAccess.id = $createdPolicyId
                }
            }
            try {
                Write-OwnerOnlyManifest -Manifest $manifest -Path $resolvedManifestPath
            } catch {
                # The original exception remains the actionable failure.
            }
            throw
        }
        Write-Host "  Created exact owned CA policy ID: $ownedPolicyId" -ForegroundColor Green
    }
}

$manifestOriginalConsent = @(
    $manifest.authorizationPolicy.originalPermissionGrantPoliciesAssigned
)
$manifestIntendedConsent = @(
    $manifest.authorizationPolicy.intendedPermissionGrantPoliciesAssigned
)
$consentIsOriginal = Test-EquivalentStringArrays $currentConsent $manifestOriginalConsent
$consentIsIntended = Test-EquivalentStringArrays $currentConsent $manifestIntendedConsent
if (-not $consentIsOriginal -and -not $consentIsIntended) {
    throw 'Tenant consent policy drifted from both the manifest original and intended collections; refusing to overwrite it.'
}

if ($consentIsOriginal -and $PSCmdlet.ShouldProcess(
    'Authorization Policy',
    'Restrict user consent using the manifest-intended collection'
)) {
    $consentBody = [ordered]@{
        defaultUserRolePermissions = [ordered]@{
            permissionGrantPoliciesAssigned = @($manifestIntendedConsent)
        }
    } | ConvertTo-Json -Depth 8
    try {
        $null = Invoke-GraphJsonRequest `
            -Method PATCH `
            -Url $AuthorizationPolicyUrl `
            -JsonBody $consentBody
    } catch {
        $applyError = $_
        $manifest.state = 'consent-update-failed'
        $manifest.lastError = $applyError.Exception.Message
        try {
            $exactPolicy = Get-ExactConditionalAccessPolicy $ownedPolicyId
            if ($exactPolicy) {
                Assert-OwnedPolicyUnchanged `
                    -Policy $exactPolicy `
                    -ExpectedId $ownedPolicyId `
                    -ExpectedHash ([string]$manifest.conditionalAccess.intendedHash)
                $null = Invoke-GraphJsonRequest `
                    -Method DELETE `
                    -Url "$ConditionalAccessPoliciesUrl/$ownedPolicyId"
                $manifest.removedPolicyIds = @($manifest.removedPolicyIds) + $ownedPolicyId
                $manifest.conditionalAccess.id = $null
                $manifest.state = 'prepared'
            }
        } catch {
            $manifest.state = 'consent-update-failed-ca-cleanup-required'
            $manifest.lastError = "$($applyError.Exception.Message) | CA cleanup: $($_.Exception.Message)"
        }
        Write-OwnerOnlyManifest -Manifest $manifest -Path $resolvedManifestPath
        throw $applyError
    }
}

$manifest.state = 'applied'
$manifest.appliedAtUtc = [DateTime]::UtcNow.ToString('o')
$manifest.lastError = $null
Write-OwnerOnlyManifest -Manifest $manifest -Path $resolvedManifestPath

Write-Host '  User consent restricted to the intended low-risk policy collection.' -ForegroundColor Green
Write-Host "  CA policy remains report-only; exact ID: $ownedPolicyId" -ForegroundColor Green
Write-Host "  Ownership/rollback manifest: $resolvedManifestPath" -ForegroundColor Green

if ($EnableConsentWorkflow) {
    Write-Host '  Admin consent workflow is configured separately in the Entra admin center:' -ForegroundColor Yellow
    Write-Host '  https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings' -ForegroundColor Cyan
}

$legacyPolicies = @($allPolicies | Where-Object {
    $_.displayName -match 'Block.*Legacy' -or $_.displayName -match 'Block.*Basic'
})
$enforcedLegacyPolicy = $legacyPolicies | Where-Object { $_.state -eq 'enabled' } | Select-Object -First 1
if ($enforcedLegacyPolicy) {
    Write-Host "  Legacy authentication block enabled: $($enforcedLegacyPolicy.displayName)" -ForegroundColor Green
} elseif ($legacyPolicies.Count -gt 0) {
    Write-Warning 'A legacy-authentication CA policy exists but is not enforcing.'
} else {
    Write-Warning 'No enforced legacy-authentication block was detected.'
}
