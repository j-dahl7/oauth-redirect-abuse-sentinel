"""Offline review regressions: no Azure credentials or cloud requests."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOAD = r'''
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $env:LAB_ROOT 'hardening/Set-OAuthHardening.ps1'),[ref]$tokens,[ref]$errors)
foreach($definition in $ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)) {
    Invoke-Expression $definition.Extent.Text
}
$ConditionalAccessPoliciesUrl='https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
'''


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7.6 required')
class ReviewRuntimeTests(unittest.TestCase):
    def run_ps(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'test.ps1'
            path.write_text(source, encoding='utf-8')
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-File', str(path)],
                env={**os.environ, 'LAB_ROOT': str(ROOT), 'REVIEW_TEMP': directory, 'NATIVE_PYTHON': sys.executable},
                capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_disabled_and_owned_resource_consent_are_preserved_custom_is_not_widened(self):
        self.run_ps(LOAD+r'''
if (@(Get-IntendedConsentCollection -Current @()).Count -ne 0) { throw 'Disabled consent was enabled' }
$owner='managePermissionGrantsForOwnedResource.custom'
if ((@(Get-IntendedConsentCollection -Current @($owner)) -join ',') -ne $owner) { throw 'Resource-owned grant changed' }
$result=@(Get-IntendedConsentCollection -Current @($owner,'managePermissionGrantsForSelf.microsoft-user-default-legacy'))
if ($result.Count -ne 2 -or $result -notcontains $owner -or $result -notcontains 'managePermissionGrantsForSelf.microsoft-user-default-low') { throw 'Known default restriction wrong' }
$failed=$false
try { Get-IntendedConsentCollection -Current @('managePermissionGrantsForSelf.custom-restrictive') } catch { $failed=$true }
if (-not $failed) { throw 'Custom policy was widened' }
''')

    def test_ca_page_shapes_ids_and_continuation_are_validated_before_following(self):
        self.run_ps(LOAD+r'''
$global:readCount=0
function Invoke-AzChecked { $global:readCount++; return $global:response }
foreach($response in @('{"value":null}','{"value":{}}','{}','{"value":[{}]}',
    '{"value":[],"@odata.nextLink":{}}',
    '{"value":[],"@odata.nextLink":"https://graph.microsoft.com:444/v1.0/identity/conditionalAccess/policies"}',
    '{"value":[],"@odata.nextLink":"https://graph.microsoft.com/v1.0/users"}',
    '{"value":[],"@odata.nextLink":"https://user@graph.microsoft.com/v1.0/identity/conditionalAccess/policies"}',
    '{"value":[],"@odata.nextLink":"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"}')) {
    $global:response=$response; $global:readCount=0; $failed=$false
    try { Get-AllConditionalAccessPolicies } catch { $failed=$true }
    if (-not $failed -or $global:readCount -ne 1) { throw "Invalid CA page accepted or followed: $response" }
}
$global:response='{"value":[]}'
if (@(Get-AllConditionalAccessPolicies).Count -ne 0) { throw 'Empty CA collection invalid' }
''')

    def test_prepared_manifest_with_empty_ca_inventory_can_finish_no_write_rollback(self):
        self.run_ps('[CmdletBinding(SupportsShouldProcess)] param()\n'+LOAD+r'''
function Get-AuthorizationPolicy { return @{defaultUserRolePermissions=@{permissionGrantPoliciesAssigned=@()}} }
function Write-OwnerOnlyManifest { param($Manifest,$Path) }
function Invoke-GraphJsonRequest { throw 'Empty rollback attempted mutation' }
$manifest=[pscustomobject]@{conditionalAccess=@{id=$null};authorizationPolicy=@{originalPermissionGrantPoliciesAssigned=@();intendedPermissionGrantPoliciesAssigned=@()};state='prepared';lastError=$null;rolledBackAtUtc=$null}
Invoke-HardeningRollback -Manifest $manifest -AuthorizationPolicy (Get-AuthorizationPolicy) -AllPolicies @() -ResolvedManifestPath 'unused.json'
if ($manifest.state -ne 'rolled-back') { throw 'Prepared empty manifest did not finish' }
''')

    def test_native_transport_preserves_url_arguments_and_classifies_only_explicit_rejections(self):
        self.run_ps(r'''
$ErrorActionPreference='Stop'
. (Join-Path $env:LAB_ROOT 'scripts/Invoke-AzChecked.ps1')
function Get-Command { param($Name,$ErrorAction) return @{CommandType='Application';Source=$env:NATIVE_PYTHON} }
$url='https://graph.microsoft.com/v1.0/applications?$top=999&$select=id,appId'
$json=Invoke-AzChecked '-c' 'import json,sys; print(json.dumps(sys.argv[1:]))' $url 'quote " with spaces' | ConvertFrom-Json
if ($json[0] -cne $url -or $json[1] -cne 'quote " with spaces') { throw 'Native argument boundary changed' }
foreach($reason in @('Bad Request','Unauthorized','Forbidden','Internal Server Error','Gateway Timeout','timeout')) {
    $message=if($reason -eq 'timeout') {'connection timeout'} else {$reason+'({"error":{"code":"FixtureCode","message":"private-body"}})'}
    $failed=$null
    try { Invoke-AzChecked '-c' 'import sys; print(sys.argv[1],file=sys.stderr); sys.exit(1)' $message } catch { $failed=$_.Exception }
    if (-not $failed -or $failed.Message -match 'private-body') { throw 'Native failure escaped or leaked' }
    $expected=$reason -in @('Bad Request','Unauthorized','Forbidden')
    if ($failed.Data['DefinitiveRejection'] -ne $expected) { throw "Wrong rejection class for $reason" }
}
''')

    def test_private_report_is_atomic_and_permissions_precede_sensitive_content(self):
        self.run_ps(r'''
$ErrorActionPreference='Stop'
. (Join-Path $env:LAB_ROOT 'scripts/Private-Report.ps1')
$path=Join-Path $env:REVIEW_TEMP 'report.csv'
Write-OwnerOnlyReport -Path $path -Content 'first'
Write-OwnerOnlyReport -Path $path -Content 'second'
if ([IO.File]::ReadAllText($path) -ne 'second') { throw 'Private replacement failed' }
if ($IsWindows) {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $other=@((Get-Acl -LiteralPath $path).Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $sid })
    if ($other.Count) { throw 'Report readable by other principals' }
} elseif (([int][IO.File]::GetUnixFileMode($path) -band 63) -ne 0) { throw 'Report has non-owner permissions' }
function Set-OwnerOnlyFilePermissions { throw 'simulated ACL failure' }
try { Write-OwnerOnlyReport -Path $path -Content 'must-not-replace' } catch {}
if ([IO.File]::ReadAllText($path) -ne 'second') { throw 'Failed private write replaced report' }
''')

    def test_disabled_consent_survives_full_apply_rerun_and_rollback(self):
        self.run_ps(r'''
$ErrorActionPreference='Stop'
$global:policy=$null; $global:patchCount=0; $global:postCount=0; $global:deleteCount=0
function global:az {
    $global:LASTEXITCODE=0
    $request=$args -join ' '
    if ($request -match '^account show') { return '{"tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}' }
    if ($request -match '--method GET' -and $request -match 'authorizationPolicy') {
        return '{"id":"authorizationPolicy","defaultUserRolePermissions":{"permissionGrantPoliciesAssigned":[]}}'
    }
    if ($request -match '--method GET' -and $request -match 'policies/cccccccc') { return ($global:policy | ConvertTo-Json -Depth 30) }
    if ($request -match '--method GET') { return (@{value=@(if($global:policy){$global:policy})} | ConvertTo-Json -Depth 30) }
    if ($request -match '--method POST') {
        $global:postCount++
        $path=$args[([array]::IndexOf($args,'--body')+1)].Substring(1)
        $global:policy=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $global:policy | Add-Member id 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        return ($global:policy | ConvertTo-Json -Depth 30)
    }
    if ($request -match '--method DELETE') { $global:deleteCount++; $global:policy=$null; return }
    if ($request -match '--method PATCH') { $global:patchCount++; throw 'Disabled consent was changed' }
    throw 'Unexpected fixture call'
}
$script=Join-Path $env:LAB_ROOT 'hardening/Set-OAuthHardening.ps1'
$path=Join-Path $env:REVIEW_TEMP 'manifest.json'
1..2 | ForEach-Object { & $script -ManifestPath $path -ConfirmTenantId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -ExcludedUserIds @('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb') }
$manifest=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if ($manifest.authorizationPolicy.intendedPermissionGrantPoliciesAssigned.Count -ne 0 -or $global:postCount -ne 1 -or $global:patchCount -ne 0) { throw 'Disabled consent or idempotent apply failed' }
& $script -ManifestPath $path -ConfirmTenantId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -Rollback
if ($global:deleteCount -ne 1 -or $global:patchCount -ne 0) { throw 'Disabled consent rollback changed state' }
''')

    def test_definitive_native_rejection_leaves_prepared_manifest(self):
        self.run_ps(r'''
$ErrorActionPreference='Stop'
function global:az {
    $global:LASTEXITCODE=0
    $request=$args -join ' '
    if ($request -match '^account show') { return '{"tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}' }
    if ($request -match '--method GET' -and $request -match 'authorizationPolicy') { return '{"id":"authorizationPolicy","defaultUserRolePermissions":{"permissionGrantPoliciesAssigned":[]}}' }
    if ($request -match '--method GET') { return '{"value":[]}' }
    if ($request -match '--method POST') {
        & $env:NATIVE_PYTHON -c 'import sys; print("Forbidden({\"error\":{\"code\":\"Authorization_RequestDenied\"}})",file=sys.stderr); sys.exit(1)'
        return
    }
    throw 'Unexpected mutation'
}
$script=Join-Path $env:LAB_ROOT 'hardening/Set-OAuthHardening.ps1'
$path=Join-Path $env:REVIEW_TEMP 'manifest.json'
$failed=$false
try { & $script -ManifestPath $path -ConfirmTenantId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -ExcludedUserIds @('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb') } catch { $failed=$true }
$manifest=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if (-not $failed -or $manifest.state -ne 'prepared' -or $manifest.conditionalAccess.id) { throw 'Explicit rejected POST was treated as uncertain' }
& $script -ManifestPath $path -ConfirmTenantId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -Rollback
''')


class QueryReviewTests(unittest.TestCase):
    def test_correlation_keeps_old_counterpart_but_only_new_matches_emit(self):
        # Timestamp fixture: old sign-in + newly ingested consent and the inverse.
        def emits(signin_ingested, consent_ingested, now=120):
            return max(signin_ingested, consent_ingested) > now-60
        self.assertTrue(emits(10, 100))
        self.assertTrue(emits(100, 10))
        self.assertFalse(emits(10, 20))
        source=(ROOT/'detection/analytics-rules.kql').read_text()
        rule1=source.split('// RULE 2:')[0]
        self.assertIn('on $left.ConsentUserId == $right.SignInUserId', rule1)
        self.assertIn('max_of(ConsentIngested, SignInIngested) > ago(1h)', rule1)
        self.assertNotIn('| where ingestion_time() > ago(1h)', rule1)

    def test_host_family_refresh_and_exact_suffix_matching(self):
        source=(ROOT/'detection/analytics-rules.kql').read_text()
        pattern=re.search(r'SuspiciousHostRegex = @"(.*?)";', source).group(1)
        for host in ('a.ngrok-free.dev','a.ngrok.app','a.ngrok.dev','a.ngrok.pizza','a.loca.lt'):
            self.assertRegex(host, pattern)
        for host in ('ngrok.app.example.com','evilngrok.app','a.loca.lt.example.com'):
            self.assertIsNone(re.fullmatch(pattern, host))

    def test_grants_use_explicit_client_id_and_never_display_name_join(self):
        source=(ROOT/'detection/hunting-queries.kql').read_text()
        self.assertIn('ServicePrincipal.ObjectID', source)
        self.assertIn('on ClientServicePrincipalId', source)
        self.assertNotIn('$left.AppName == $right.PermApp', source)
        self.assertIn('same-AppId hunt does not correlate a cross-application', source)

    def test_rules_do_not_group_empty_entity_sets_or_send_unsupported_subtechniques(self):
        source=(ROOT/'scripts/Deploy-Lab.ps1').read_text()
        self.assertIn('aggregationKind = "AlertPerResult"', source)
        self.assertRegex(source, r'groupingConfiguration\s*=\s*@\{\s*enabled\s*=\s*\$false')
        self.assertNotIn('subTechniques         = $rule.subTechniques', source)
        self.assertNotIn('"fallbackResourceIds": ["placeholder"]', source)


if __name__ == '__main__':
    unittest.main()
