"""Exercise deployment and cleanup with mocked Azure responses only."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


DEPLOY_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "Deploy-Lab.ps1"

HARNESS = r"""
$ErrorActionPreference = 'Stop'
$global:Calls = [System.Collections.Generic.List[object]]::new()
$global:TempWrites = 0
$global:PageCount = 0
$workspaceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/lab-rg/providers/Microsoft.OperationalInsights/workspaces/lab-law'
$owner = 'nine-lives-zero-trust:oauth-redirect-abuse-sentinel'
$firstName = 'LAB - OAuth Consent After Risky Sign-in'
$lastName = 'LAB - Bulk OAuth Consent to Single App'
$armOrigin = if ($env:PAGINATION_CASE -eq 'sovereign_owned') { 'https://management.usgovcloudapi.net' } else { 'https://management.azure.com' }
$collection = "$armOrigin$workspaceId/providers/Microsoft.SecurityInsights/alertRules"
$initialUrl = "${collection}?api-version=2024-03-01"
$secondUrl = "${initialUrl}&page=2"

function New-Rule([string]$Name, [bool]$Owned = $true) {
    $hash = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes("$workspaceId|$owner|rule:$Name")
    )
    @{
        name = [guid]::new([byte[]]$hash[0..15]).ToString()
        properties = @{
            displayName = $Name
            description = if ($Owned) { "[Owner: $owner]" } else { 'Existing resource owned by someone else' }
        }
    }
}

function global:az {
    $request = $args -join ' '
    $global:Calls.Add($request)
    if ($request -match 'monitor log-analytics workspace show') {
        @{id=$workspaceId; customerId='11111111-1111-1111-1111-111111111111'; location='eastus'} | ConvertTo-Json
    }
    elseif ($request -match 'onboardingStates') { '{"value":[{"name":"default"}]}' }
    elseif ($request -match 'cloud show') { "$armOrigin/" }
    elseif ($request -match '--method GET' -and $request -match 'alertRules') {
        $global:PageCount++
        if ($global:PageCount -gt 101) { throw 'Test guard: pagination did not stop' }
        $page = @{value=@(); nextLink=$secondUrl}
        if ($global:PageCount -eq 1) {
            if ($env:PAGINATION_CASE -in @('foreign_id', 'foreign_name', 'foreign_cleanup', 'duplicate_id')) {
                $page.value = @((New-Rule $firstName))
            }
            switch ($env:PAGINATION_CASE) {
                'hostile_host' { $page.nextLink = 'https://example.invalid/alertRules?page=2' }
                'hostile_scheme' { $page.nextLink = $secondUrl.Replace('https:', 'http:') }
                'hostile_port' { $page.nextLink = $secondUrl.Replace('management.azure.com', 'management.azure.com:8443') }
                'hostile_credentials' { $page.nextLink = $secondUrl.Replace('management.azure.com', 'user@management.azure.com') }
                'hostile_workspace' { $page.nextLink = $secondUrl.Replace('/workspaces/lab-law/', '/workspaces/other-law/') }
                'hostile_fragment' { $page.nextLink = "$secondUrl#fragment" }
                'malformed_link' { $page.nextLink = @('not-a-string') }
                'relative_owned' { $page.nextLink = $secondUrl.Replace('https://management.azure.com', '') }
            }
        }
        else {
            $page.Remove('nextLink')
            switch ($env:PAGINATION_CASE) {
                'foreign_id' { $page.value = @((New-Rule $lastName $false)) }
                'foreign_cleanup' { $page.value = @((New-Rule $lastName $false)) }
                'foreign_name' {
                    $foreign = New-Rule $lastName $false
                    $foreign.name = '22222222-2222-2222-2222-222222222222'
                    $page.value = @($foreign)
                }
                'owned_cleanup' { $page.value = @((New-Rule $lastName)) }
                'relative_owned' { $page.value = @((New-Rule $lastName)) }
                'sovereign_owned' { $page.value = @((New-Rule $lastName)) }
                'cycle' { $page.nextLink = $initialUrl }
                'page_limit' { $page.nextLink = "${initialUrl}&page=$($global:PageCount + 1)" }
                'missing_value' { $page.Remove('value') }
                'invalid_value' { $page.value = @{name='not-an-array'} }
                'duplicate_id' { $page.value = @((New-Rule $firstName)) }
                'missing_id' { $page.value = @(@{properties=@{displayName='Incomplete record'}}) }
                'read_failure' { throw 'Simulated next-page read failure' }
                default { throw 'Test guard: followed a forbidden continuation' }
            }
        }
        $page | ConvertTo-Json -Depth 10 -Compress
    }
    elseif ($request -match '--method DELETE' -and $env:PAGINATION_CASE -in @('owned_cleanup', 'relative_owned', 'sovereign_owned')) {
        # Simulated success: no command is forwarded to the real Azure CLI.
    }
    elseif ($request -match '(--method PUT|--method PATCH|--method POST|--method DELETE)') {
        throw "Unexpected cloud mutation: $request"
    }
    elseif ($request -match 'resource list|monitor log-analytics query') { '[]' }
    else { throw "Unexpected mocked az call: $request" }
}

function global:New-TemporaryFile {
    $global:TempWrites++
    throw 'Unexpected temporary write before inventory preflight completed'
}

$failure = $null
try {
    if ($env:PAGINATION_ACTION -eq 'destroy') {
        & $env:SESSION_DEPLOY_SCRIPT -ResourceGroup lab-rg -WorkspaceName lab-law -Destroy
    }
    else {
        & $env:SESSION_DEPLOY_SCRIPT -ResourceGroup lab-rg -WorkspaceName lab-law -SkipAudit
    }
}
catch { $failure = $_.Exception.Message }
'RESULT:' + (@{error=$failure; calls=@($global:Calls.ToArray()); tempWrites=$global:TempWrites; pageCount=$global:PageCount} | ConvertTo-Json -Depth 10 -Compress)
"""


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
class RulePaginationTests(unittest.TestCase):
    def run_case(self, case, action="deploy"):
        completed = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", HARNESS],
            env={**os.environ, "SESSION_DEPLOY_SCRIPT": str(DEPLOY_SCRIPT),
                 "PAGINATION_CASE": case, "PAGINATION_ACTION": action},
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        result_lines = [line[7:] for line in completed.stdout.splitlines() if line.startswith("RESULT:")]
        self.assertEqual(len(result_lines), 1, completed.stdout + completed.stderr)
        return json.loads(result_lines[0])

    def assert_no_writes(self, result):
        self.assertEqual(result["tempWrites"], 0, result)
        self.assertFalse(any(f"--method {method}" in call
                             for call in result["calls"] for method in ("PUT", "PATCH", "POST", "DELETE")), result)

    def test_later_page_foreign_id_stops_deploy_before_any_write(self):
        result = self.run_case("foreign_id")
        self.assertIn("ownership marker", result["error"] or "")
        self.assertEqual(result["pageCount"], 2)
        self.assert_no_writes(result)

    def test_later_page_same_name_stops_deploy_before_any_write(self):
        result = self.run_case("foreign_name")
        self.assertIn("non-lab analytics rule", result["error"] or "")
        self.assert_no_writes(result)

    def test_later_page_foreign_id_stops_cleanup_before_any_delete(self):
        result = self.run_case("foreign_cleanup", "destroy")
        self.assertIn("ownership marker", result["error"] or "")
        self.assert_no_writes(result)

    def test_cleanup_finds_owned_rule_on_a_later_page(self):
        for case in ("owned_cleanup", "relative_owned", "sovereign_owned"):
            with self.subTest(case=case):
                result = self.run_case(case, "destroy")
                self.assertIsNone(result["error"], result)
                self.assertEqual(result["pageCount"], 2)
                deletes = [call for call in result["calls"] if "--method DELETE" in call]
                self.assertEqual(len(deletes), 1, result)
                self.assertIn("/alertRules/", deletes[0])
                self.assertEqual(result["tempWrites"], 0)
                if case == "sovereign_owned":
                    pages = [call for call in result["calls"] if '--method GET' in call and 'alertRules' in call]
                    self.assertTrue(all('https://management.usgovcloudapi.net/' in call for call in pages), result)

    def test_invalid_continuations_fail_before_request_or_write(self):
        cases = ("hostile_host", "hostile_scheme", "hostile_port", "hostile_credentials",
                 "hostile_workspace", "hostile_fragment", "malformed_link")
        for action in ("deploy", "destroy"):
            for case in cases:
                with self.subTest(action=action, case=case):
                    result = self.run_case(case, action)
                    self.assertIn("pagination", (result["error"] or "").lower(), result)
                    self.assertEqual(result["pageCount"], 1, result)
                    self.assert_no_writes(result)

    def test_incomplete_inventory_never_reaches_mutations(self):
        cases = {
            'cycle': ('repeated a page', 2),
            'page_limit': ('exceeded 100 pages', 100),
            'missing_value': ('invalid value array', 2),
            'invalid_value': ('invalid value array', 2),
            'duplicate_id': ('missing or duplicate resource ID', 2),
            'missing_id': ('missing or duplicate resource ID', 2),
            'read_failure': ('Simulated next-page read failure', 2),
        }
        for action in ("deploy", "destroy"):
            for case, (message, expected_pages) in cases.items():
                with self.subTest(action=action, case=case):
                    result = self.run_case(case, action)
                    self.assertIsNotNone(result["error"], result)
                    self.assertNotIn("Test guard", result["error"], result)
                    self.assertIn(message, result["error"], result)
                    self.assert_no_writes(result)
                    self.assertEqual(result["pageCount"], expected_pages)


if __name__ == "__main__":
    unittest.main()
