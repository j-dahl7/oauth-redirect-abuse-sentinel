import os
import shutil
import subprocess
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OAuthScriptContractTests(unittest.TestCase):
    def test_hardening_preview_uses_planned_summaries_and_scoped_temp_files(self):
        script = (ROOT / "hardening" / "Set-OAuthHardening.ps1").read_text(
            encoding="utf-8"
        )

        self.assertIn("$consentSummary = 'Planned restriction", script)
        self.assertIn("$caSummary = 'Planned report-only", script)
        self.assertIn("function Invoke-GraphJsonRequest", script)
        self.assertIn("finally {", script)
        self.assertEqual(script.count("New-TemporaryFile"), 1)
        self.assertNotIn("CA policy: Report-only MFA step-up policy created", script)

    def test_deploy_forwards_emergency_access_exclusions(self):
        script = (ROOT / "scripts" / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        self.assertIn("[string[]]$ExcludedUserIds = @()", script)
        self.assertIn("-ExcludedUserIds $ExcludedUserIds", script)

    def test_deploy_uses_deterministic_ids_and_explicit_ownership(self):
        script = (ROOT / "scripts" / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        self.assertIn("function Get-LabResourceGuid", script)
        self.assertIn(
            "$LabOwnerMarker = 'nine-lives-zero-trust:oauth-redirect-abuse-sentinel'",
            script,
        )
        self.assertIn("'nlzt-owner'   = $LabOwnerMarker", script)
        self.assertIn("[switch]$Destroy", script)
        self.assertIn("Refusing to adopt, overwrite, or delete it.", script)
        self.assertIn("ownership marker does not match this lab", script)
        self.assertNotIn("$existingRuleIdsByName", script)
        self.assertNotIn("[guid]::NewGuid()", script)

    def test_deployed_oauth_rule_and_workbook_use_immutable_app_ids(self):
        script = (ROOT / "scripts" / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        self.assertGreaterEqual(script.count("let ApprovedAppIds = dynamic([]);"), 2)
        self.assertGreaterEqual(
            script.count("AppIdUsed !in~ (ApprovedAppIds)"),
            2,
        )
        self.assertNotIn("AppDisplayName !in (", script)
        self.assertIn('displayName        = "LAB - OAuth Error Cluster by Application"', script)
        self.assertIn('resourceKey        = "rule:LAB - OAuth Error-Based Redirect Pattern"', script)
        self.assertIn('legacyDisplayNames = @("LAB - OAuth Error-Based Redirect Pattern")', script)
        self.assertIn('severity    = "Medium"', script)
        self.assertIn('tactics        = @()', script)
        self.assertIn('techniques     = @()', script)
        self.assertIn('subTechniques  = @()', script)
        self.assertIn('$allowedDisplayNames -cnotcontains $existingDisplayName', script)

    def test_hunts_never_trust_application_display_names(self):
        hunts = (ROOT / "detection" / "hunting-queries.kql").read_text(
            encoding="utf-8"
        )

        self.assertIn("let ApprovedAppIds = dynamic([]);", hunts)
        self.assertIn("AppIdUsed !in~ (ApprovedAppIds)", hunts)
        self.assertNotIn("AppDisplayName !in (", hunts)

    def test_redirect_rule_parses_uri_hosts_and_schemes(self):
        standalone = (ROOT / "detection" / "analytics-rules.kql").read_text(
            encoding="utf-8"
        )
        deployed = (ROOT / "scripts" / "Deploy-Lab.ps1").read_text(
            encoding="utf-8"
        )

        for source in (standalone, deployed):
            self.assertIn("parse_json(NewRedirectUris)", source)
            self.assertIn("parse_url(RedirectUri)", source)
            self.assertIn("RedirectHost matches regex SuspiciousHostRegex", source)
            self.assertIn(
                'let ApprovedHttpLoopbackHosts = dynamic(["localhost", "127.0.0.1"]);',
                source,
            )
            self.assertIn(
                'RedirectScheme == "http" and RedirectHost !in~ (ApprovedHttpLoopbackHosts)',
                source,
            )
            self.assertNotIn("NewRedirectUris has_any", source)
            self.assertNotIn('NewRedirectUris has "http://"', source)

    def test_every_workbook_query_is_bound_to_the_time_range_parameter(self):
        script = (ROOT / "scripts" / "Deploy-Lab.ps1").read_text(encoding="utf-8")

        self.assertEqual(script.count('"version": "KqlItem/1.0"'), 4)
        self.assertEqual(
            script.count('"timeContextFromParameter": "TimeRange"'),
            4,
        )

    def test_documented_permissions_match_graph_endpoints(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("Directory.Read.All", readme)
        self.assertIn("Policy.ReadWrite.Authorization", readme)
        self.assertIn("Policy.ReadWrite.ConditionalAccess", readme)
        self.assertNotIn("Application.Read.All", readme)

    def test_audit_pagination_never_forwards_credentials_off_graph(self):
        script = (ROOT / "hardening" / "Audit-OAuthApps.ps1").read_text(
            encoding="utf-8"
        )

        guard = script.index("$parsedNextLink.Host -ne 'graph.microsoft.com'")
        request = script.index("az rest --method GET --url $nextLink")
        self.assertLess(guard, request)
        self.assertIn("$parsedNextLink.Scheme -ne 'https'", script)
        self.assertIn("$parsedNextLink.UserInfo", script)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
    def test_deploy_and_destroy_enforce_runtime_ownership_contract(self):
        harness = textwrap.dedent(
            r"""
            $ErrorActionPreference = 'Stop'
            $workspaceId = '/subscriptions/sub-1/resourceGroups/rg-lab/providers/Microsoft.OperationalInsights/workspaces/law-lab'
            $marker = 'nine-lives-zero-trust:oauth-redirect-abuse-sentinel'
            $ruleNames = @(
                'LAB - OAuth Consent After Risky Sign-in',
                'LAB - Suspicious OAuth Redirect URI Registered',
                'LAB - OAuth Error-Based Redirect Pattern',
                'LAB - Bulk OAuth Consent to Single App'
            )

            function Get-ExpectedGuid {
                param([string]$ResourceKey)
                $seed = "$workspaceId|$marker|$ResourceKey"
                $hash = [System.Security.Cryptography.SHA256]::HashData(
                    [System.Text.Encoding]::UTF8.GetBytes($seed)
                )
                [guid]::new([byte[]]$hash[0..15]).ToString()
            }

            function Get-OwnedRulesJson {
                param([int]$Count = 4)
                $items = for ($index = 0; $index -lt $Count; $index++) {
                    $name = $ruleNames[$index]
                    [pscustomobject]@{
                        name = Get-ExpectedGuid "rule:$name"
                        properties = [pscustomobject]@{
                            displayName = $name
                            description = "Owned [Owner: $marker]"
                        }
                    }
                }
                @{ value = @($items) } | ConvertTo-Json -Depth 8 -Compress
            }

            function Get-OwnedWorkbookJson {
                $item = [pscustomobject]@{
                    name = Get-ExpectedGuid 'workbook'
                    tags = [pscustomobject]@{
                        'hidden-title' = 'OAuth Security Dashboard'
                        'nlzt-owner' = $marker
                    }
                    properties = [pscustomobject]@{
                        displayName = 'OAuth Security Dashboard'
                    }
                }
                ConvertTo-Json -InputObject @($item) -Depth 8 -Compress
            }

            $global:rulesJson = '{"value":[]}'
            $global:workbooksJson = '[]'
            $global:mutations = @()
            function global:az {
                $request = $args -join ' '
                if ($request -match '--method (PUT|DELETE)') {
                    $global:mutations += $request
                    return
                }
                if ($request -match 'monitor log-analytics workspace show') {
                    [pscustomobject]@{
                        id = $workspaceId
                        customerId = 'customer-1'
                        location = 'eastus'
                    } | ConvertTo-Json -Compress
                    return
                }
                if ($request -match 'onboardingStates') {
                    '{"value":[{"name":"default"}]}'
                    return
                }
                if ($request -match '--method GET' -and $request -match 'alertRules') {
                    $global:rulesJson
                    return
                }
                if ($request -match '^resource list') {
                    $global:workbooksJson
                    return
                }
                throw "Unexpected mocked az call: $request"
            }
            function global:New-TemporaryFile {
                throw 'Ownership preflight or WhatIf attempted to create a temporary file'
            }

            # Owned resources remain mutation-free in both deployment and cleanup previews.
            $global:rulesJson = Get-OwnedRulesJson
            $global:workbooksJson = Get-OwnedWorkbookJson
            $deployPreview = & $env:OAUTH_DEPLOY_SCRIPT `
                -ResourceGroup 'rg-lab' -WorkspaceName 'law-lab' -SkipAudit -WhatIf 6>&1 |
                Out-String
            $destroyPreview = & $env:OAUTH_DEPLOY_SCRIPT `
                -ResourceGroup 'rg-lab' -WorkspaceName 'law-lab' -Destroy -WhatIf 6>&1 |
                Out-String
            if ($deployPreview -notmatch 'Deployment preview complete; no changes applied') {
                throw "Deployment preview summary was missing: $deployPreview"
            }
            if ($destroyPreview -notmatch 'Cleanup preview complete; no resources were deleted') {
                throw "Cleanup preview summary was missing: $destroyPreview"
            }
            if ($global:mutations.Count -ne 0) {
                throw "Preview attempted Azure mutations: $($global:mutations -join '; ')"
            }

            # A foreign resource with the same display name must never be adopted.
            $global:rulesJson = @{
                value = @([pscustomobject]@{
                    name = '11111111-1111-1111-1111-111111111111'
                    properties = [pscustomobject]@{
                        displayName = $ruleNames[0]
                        description = 'Foreign rule'
                    }
                })
            } | ConvertTo-Json -Depth 8 -Compress
            $global:workbooksJson = '[]'
            $collisionMessage = ''
            try {
                $null = & $env:OAUTH_DEPLOY_SCRIPT `
                    -ResourceGroup 'rg-lab' -WorkspaceName 'law-lab' -SkipAudit 6>&1
            } catch {
                $collisionMessage = $_.Exception.Message
            }
            if ($collisionMessage -notmatch 'non-lab analytics rule already uses display name') {
                throw "Foreign rule collision was not rejected: $collisionMessage"
            }
            if ($global:mutations.Count -ne 0) {
                throw 'A foreign rule collision caused a mutation'
            }

            # A resource at the deterministic ID without the marker is still foreign.
            $global:rulesJson = @{
                value = @([pscustomobject]@{
                    name = Get-ExpectedGuid "rule:$($ruleNames[0])"
                    properties = [pscustomobject]@{
                        displayName = $ruleNames[0]
                        description = 'Marker deliberately absent'
                    }
                })
            } | ConvertTo-Json -Depth 8 -Compress
            $markerMessage = ''
            try {
                $null = & $env:OAUTH_DEPLOY_SCRIPT `
                    -ResourceGroup 'rg-lab' -WorkspaceName 'law-lab' -Destroy 6>&1
            } catch {
                $markerMessage = $_.Exception.Message
            }
            if ($markerMessage -notmatch 'ownership marker does not match this lab') {
                throw "Forged deterministic rule ID was not rejected: $markerMessage"
            }
            if ($global:mutations.Count -ne 0) {
                throw 'A forged deterministic rule ID caused a deletion'
            }

            # Workbook validation is completed before an otherwise-owned rule can be deleted.
            $global:rulesJson = Get-OwnedRulesJson -Count 1
            $foreignWorkbook = [pscustomobject]@{
                name = '22222222-2222-2222-2222-222222222222'
                tags = [pscustomobject]@{ 'hidden-title' = 'OAuth Security Dashboard' }
                properties = [pscustomobject]@{ displayName = 'OAuth Security Dashboard' }
            }
            $global:workbooksJson = ConvertTo-Json -InputObject @($foreignWorkbook) -Depth 8 -Compress
            $workbookMessage = ''
            try {
                $null = & $env:OAUTH_DEPLOY_SCRIPT `
                    -ResourceGroup 'rg-lab' -WorkspaceName 'law-lab' -Destroy 6>&1
            } catch {
                $workbookMessage = $_.Exception.Message
            }
            if ($workbookMessage -notmatch 'non-lab workbook already uses title') {
                throw "Foreign workbook collision was not rejected: $workbookMessage"
            }
            if ($global:mutations.Count -ne 0) {
                throw 'Workbook preflight did not prevent partial rule deletion'
            }

            # A real cleanup targets all and only the five deterministically owned resources.
            $global:rulesJson = Get-OwnedRulesJson
            $global:workbooksJson = Get-OwnedWorkbookJson
            $destroyOutput = & $env:OAUTH_DEPLOY_SCRIPT `
                -ResourceGroup 'rg-lab' -WorkspaceName 'law-lab' -Destroy 6>&1 |
                Out-String
            if ($destroyOutput -notmatch 'Owned Sentinel resources destroyed') {
                throw "Destroy summary was missing: $destroyOutput"
            }
            if ($global:mutations.Count -ne 5) {
                throw "Expected five owned deletes, got $($global:mutations.Count)"
            }
            if (@($global:mutations | Where-Object { $_ -notmatch '--method DELETE' }).Count -ne 0) {
                throw "Destroy issued a non-delete mutation: $($global:mutations -join '; ')"
            }
            $allDeletes = $global:mutations -join "`n"
            foreach ($name in $ruleNames) {
                $expectedId = Get-ExpectedGuid "rule:$name"
                if ($allDeletes -notmatch [regex]::Escape($expectedId)) {
                    throw "Destroy omitted owned rule ID $expectedId"
                }
            }
            $expectedWorkbookId = Get-ExpectedGuid 'workbook'
            if ($allDeletes -notmatch [regex]::Escape($expectedWorkbookId)) {
                throw "Destroy omitted owned workbook ID $expectedWorkbookId"
            }
            "OK"
            """
        )
        env = os.environ.copy()
        env["OAUTH_DEPLOY_SCRIPT"] = str(ROOT / "scripts" / "Deploy-Lab.ps1")
        result = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-Command", harness],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("OK", result.stdout)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
    def test_whatif_performs_no_temp_or_graph_writes(self):
        harness = textwrap.dedent(
            r"""
            $ErrorActionPreference = 'Stop'
            function global:az {
                $request = $args -join ' '
                if ($request -match 'policies/authorizationPolicy') {
                    '{"defaultUserRolePermissions":{"permissionGrantPoliciesAssigned":[]}}'
                    return
                }
                if ($request -match 'identity/conditionalAccess/policies') {
                    '{"value":[]}'
                    return
                }
                throw "Unexpected mocked az call: $request"
            }
            function global:New-TemporaryFile {
                throw 'WhatIf attempted to create a temporary file'
            }

            $output = & $env:OAUTH_HARDENING_SCRIPT -WhatIf 6>&1 | Out-String
            if ($output -notmatch 'Planned restriction to verified publishers') {
                throw "Preview consent summary was missing: $output"
            }
            if ($output -notmatch 'Planned report-only MFA policy creation') {
                throw "Preview CA summary was missing: $output"
            }
            if ($output -match 'User consent: Restricted') {
                throw "Preview falsely reported an applied consent restriction: $output"
            }
            "OK"
            """
        )
        env = os.environ.copy()
        env["OAUTH_HARDENING_SCRIPT"] = str(
            ROOT / "hardening" / "Set-OAuthHardening.ps1"
        )
        result = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-Command", harness],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
