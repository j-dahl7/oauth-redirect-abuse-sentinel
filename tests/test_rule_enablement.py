"""Rules deploy disabled unless -EnableRules is supplied; mocked Azure responses only."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = ROOT / "scripts" / "Deploy-Lab.ps1"
RULE_NAMES = [
    "LAB - OAuth Consent After Risky Sign-in",
    "LAB - Suspicious OAuth Redirect URI Registered",
    "LAB - OAuth Error Cluster by Application",
    "LAB - Bulk OAuth Consent to Single App",
]
DISABLE_NOTICE = "Currently enabled; deploying without -EnableRules sets it to disabled."

# Runs the real deployer. Every az call is answered locally and each PUT body is
# captured exactly as it was written for the request; nothing reaches Azure.
HARNESS = r"""
$ErrorActionPreference = 'Stop'
$global:WorkspaceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/lab-rg/providers/Microsoft.OperationalInsights/workspaces/lab-law'
$owner = 'nine-lives-zero-trust:oauth-redirect-abuse-sentinel'
# Display name and deterministic-ID key of each lab rule.
$labRules = @(
    @('LAB - OAuth Consent After Risky Sign-in', 'rule:LAB - OAuth Consent After Risky Sign-in'),
    @('LAB - Suspicious OAuth Redirect URI Registered', 'rule:LAB - Suspicious OAuth Redirect URI Registered'),
    @('LAB - OAuth Error Cluster by Application', 'rule:LAB - OAuth Error-Based Redirect Pattern'),
    @('LAB - Bulk OAuth Consent to Single App', 'rule:LAB - Bulk OAuth Consent to Single App')
)
$global:Calls = [System.Collections.Generic.List[string]]::new()
$global:Puts = [System.Collections.Generic.List[object]]::new()
$global:TempFiles = [System.Collections.Generic.List[string]]::new()
$global:Inventory = @()
if ($env:RULE_STATE_EXISTING -in @('enabled', 'disabled')) {
    $global:Inventory = @(foreach ($labRule in $labRules) {
        $hash = [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.Encoding]::UTF8.GetBytes("$($global:WorkspaceId)|$owner|$($labRule[1])")
        )
        @{
            name = [guid]::new([byte[]]$hash[0..15]).ToString()
            properties = @{
                displayName = $labRule[0]
                description = "Owned [Owner: $owner]"
                enabled = $env:RULE_STATE_EXISTING -eq 'enabled'
            }
        }
    })
}

function global:az {
    $request = $args -join ' '
    $global:Calls.Add($request)
    if ($request -match '^monitor log-analytics workspace show') {
        return (@{ id = $global:WorkspaceId; customerId = '11111111-1111-1111-1111-111111111111'; location = 'eastus' } | ConvertTo-Json -Compress)
    }
    if ($request -match 'onboardingStates') { return '{"value":[{"name":"default"}]}' }
    if ($request -match '^cloud show') { return 'https://management.azure.com/' }
    if ($request -match '--method GET' -and $request -match 'alertRules') {
        return (@{ value = @($global:Inventory) } | ConvertTo-Json -Depth 8 -Compress)
    }
    if ($request -match '^resource list') { return '[]' }
    if ($request -match '--method PUT') {
        $url = [string]$args[[array]::IndexOf($args, '--url') + 1]
        $bodyArgument = [string]$args[[array]::IndexOf($args, '--body') + 1]
        if (-not $bodyArgument.StartsWith('@')) { throw 'Expected a local JSON body file' }
        $raw = Get-Content -LiteralPath $bodyArgument.Substring(1) -Raw
        $global:Puts.Add(@{ url = $url; raw = $raw })
        $body = $raw | ConvertFrom-Json
        if ($url -match '/alertRules/([^/?]+)\?api-version=2024-03-01$') {
            $properties = @{ displayName = $body.properties.displayName }
            switch ($env:RULE_STATE_ECHO) {
                'opposite' { $properties.enabled = -not $body.properties.enabled }
                'missing' { }
                default { $properties.enabled = $body.properties.enabled }
            }
            return (@{ name = $Matches[1]; properties = $properties } | ConvertTo-Json -Depth 5 -Compress)
        }
        if ($url -match '/workbooks/([^/?]+)\?api-version=2022-04-01$') {
            return (@{ name = $Matches[1]; properties = @{ displayName = $body.properties.displayName } } | ConvertTo-Json -Depth 5 -Compress)
        }
        throw "Unexpected mocked PUT target: $url"
    }
    throw "Unexpected mocked az call: $request"
}

function global:New-TemporaryFile {
    if ($env:RULE_STATE_WHATIF -eq 'true') { throw 'Preview attempted to create a temporary request file' }
    $file = Microsoft.PowerShell.Utility\New-TemporaryFile
    $global:TempFiles.Add($file.FullName)
    return $file
}

$parameters = @{ ResourceGroup = 'lab-rg'; WorkspaceName = 'lab-law' }
if ($env:RULE_STATE_DESTROY -eq 'true') { $parameters.Destroy = $true } else { $parameters.SkipAudit = $true }
if ($env:RULE_STATE_SWITCH) { $parameters[$env:RULE_STATE_SWITCH] = $true }
if ($env:RULE_STATE_WHATIF -eq 'true') { $parameters.WhatIf = $true }

# Collect host output line by line so a failed run still shows what it printed.
$lines = [System.Collections.Generic.List[string]]::new()
$failure = $null
try {
    & $env:RULE_STATE_DEPLOY_SCRIPT @parameters 6>&1 | ForEach-Object { $lines.Add([string]$_) }
}
catch { $failure = $_.Exception.Message }
'RESULT:' + (@{
    error = $failure
    output = $lines -join "`n"
    calls = @($global:Calls.ToArray())
    puts = @($global:Puts.ToArray())
    inventoryIds = @($global:Inventory | ForEach-Object { $_.name })
    tempFilesLeft = @($global:TempFiles | Where-Object { Test-Path -LiteralPath $_ }).Count
} | ConvertTo-Json -Depth 6 -Compress)
"""


class RuleEnablementContractTests(unittest.TestCase):
    def test_deployer_source_keeps_the_disabled_default(self):
        script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("[switch]$EnableRules", script)
        self.assertIn("[Alias('EnableSentinelRules')]", script)
        self.assertIn("$RulesEnabled = [bool]$EnableRules", script)
        self.assertIn("enabled               = $RulesEnabled", script)
        # A switch initializer, a second assignment, or a literal true would
        # make "enabled" the state an operator gets without asking for it.
        self.assertIsNone(re.search(r"\[switch\]\s*\$EnableRules\s*=", script))
        self.assertEqual(len(re.findall(r"\$RulesEnabled\s*=(?!=)", script)), 1)
        self.assertIsNone(re.search(r"(?im)^\s*enabled\s*=\s*\$true\b", script))
        self.assertIn(".PARAMETER EnableRules", script)
        self.assertRegex(
            script, r"Without this switch the\s+rules are created or updated disabled"
        )
        self.assertIn("cannot be combined with -Destroy", script)

    def test_readme_documents_the_disabled_default_and_the_opt_in(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("-EnableRules", readme)
        self.assertIn("-EnableSentinelRules", readme)
        self.assertIn("created disabled", readme)
        self.assertNotIn("All rules should show as Enabled", readme)


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
class RuleEnablementTests(unittest.TestCase):
    def run_deploy(self, switch="", whatif=False, existing="none", echo="request", destroy=False):
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory) / "harness.ps1"
            harness.write_text(HARNESS, encoding="utf-8")
            completed = subprocess.run(
                ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
                env={**os.environ, "RULE_STATE_DEPLOY_SCRIPT": str(DEPLOY_SCRIPT),
                     "RULE_STATE_SWITCH": switch, "RULE_STATE_WHATIF": str(whatif).lower(),
                     "RULE_STATE_EXISTING": existing, "RULE_STATE_ECHO": echo,
                     "RULE_STATE_DESTROY": str(destroy).lower()},
                capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        result_lines = [line[7:] for line in completed.stdout.splitlines() if line.startswith("RESULT:")]
        self.assertEqual(len(result_lines), 1, completed.stdout + completed.stderr)
        return json.loads(result_lines[0])

    def rule_requests(self, result):
        return [(put["url"], json.loads(put["raw"])) for put in result["puts"] if "/alertRules/" in put["url"]]

    def assert_rule_bodies(self, result, enabled):
        requests = self.rule_requests(result)
        self.assertEqual([body["properties"]["displayName"] for _, body in requests], RULE_NAMES)
        for _, body in requests:
            properties = body["properties"]
            with self.subTest(rule=properties["displayName"]):
                self.assertEqual(body["kind"], "Scheduled")
                # A JSON boolean, never a string, an absent key, or a serialized switch.
                self.assertIs(properties.get("enabled"), enabled)
                # Incident settings stay ready for the moment an operator opts in.
                self.assertIs(properties["incidentConfiguration"]["createIncident"], True)
                self.assertIs(properties["incidentConfiguration"]["groupingConfiguration"]["enabled"], False)
                self.assertEqual(properties["eventGroupingSettings"], {"aggregationKind": "AlertPerResult"})
        self.assertEqual(result["tempFilesLeft"], 0, result)
        return requests

    def test_default_deployment_creates_every_rule_disabled(self):
        result = self.run_deploy()
        self.assertIsNone(result["error"], result)
        self.assert_rule_bodies(result, False)
        self.assertEqual(len(result["puts"]), 5, result)  # four rules and the workbook
        output = result["output"]
        self.assertIn("Rule state:     DISABLED (safe default; add -EnableRules to enable)", output)
        self.assertEqual(output.count("(disabled)"), 4, output)
        self.assertIn("Deployment complete!", output)
        self.assertIn("Rule state:      DISABLED (safe default; disabled rules do not run", output)
        # The summary says how to enable later, for this workspace.
        self.assertIn(
            "./scripts/Deploy-Lab.ps1 -ResourceGroup 'lab-rg' -WorkspaceName 'lab-law' -EnableRules -SkipAudit",
            output,
        )
        self.assertIn("A later run without", output)
        self.assertNotIn("ENABLED", output)
        self.assertNotIn(DISABLE_NOTICE, output)

    def test_enable_rules_and_its_family_alias_enable_every_rule(self):
        for switch in ("EnableRules", "EnableSentinelRules"):
            with self.subTest(switch=switch):
                result = self.run_deploy(switch=switch)
                self.assertIsNone(result["error"], result)
                self.assert_rule_bodies(result, True)
                output = result["output"]
                self.assertIn("Rule state:     ENABLED by -EnableRules", output)
                self.assertEqual(output.count("(enabled)"), 4, output)
                self.assertIn("Rule state:      ENABLED by -EnableRules (hourly runs", output)
                self.assertIn("To disable them, rerun without", output)
                self.assertNotIn("DISABLED", output)

    def test_rerun_without_the_switch_disables_enabled_rules_and_says_so(self):
        result = self.run_deploy(existing="enabled")
        self.assertIsNone(result["error"], result)
        requests = self.assert_rule_bodies(result, False)
        # The same four owned rules are updated in place, not recreated beside them.
        updated_ids = [url.split("/alertRules/")[1].split("?")[0] for url, _ in requests]
        self.assertEqual(updated_ids, result["inventoryIds"])
        self.assertEqual(result["output"].count(DISABLE_NOTICE), 4, result["output"])
        self.assertEqual(result["output"].count("Updated: "), 4, result["output"])

        for existing, switch in (("disabled", ""), ("enabled", "EnableRules")):
            with self.subTest(existing=existing, switch=switch):
                quiet = self.run_deploy(existing=existing, switch=switch)
                self.assertIsNone(quiet["error"], quiet)
                self.assert_rule_bodies(quiet, bool(switch))
                self.assertNotIn(DISABLE_NOTICE, quiet["output"])

    def test_preview_reports_the_planned_rule_state_without_writes(self):
        for switch, state, notices in (("", "DISABLED (safe default", 4), ("EnableRules", "ENABLED by -EnableRules", 0)):
            with self.subTest(switch=switch):
                result = self.run_deploy(switch=switch, whatif=True, existing="enabled")
                self.assertIsNone(result["error"], result)
                self.assertEqual(result["puts"], [])
                self.assertFalse(any(f"--method {method}" in call for call in result["calls"]
                                     for method in ("PUT", "PATCH", "POST", "DELETE")), result)
                output = result["output"]
                self.assertIn("Deployment preview complete; no changes applied.", output)
                self.assertIn("=== Planned Resources ===", output)
                self.assertIn(f"Rule state:      {state}", output)
                self.assertEqual(output.count(DISABLE_NOTICE), notices, output)

    def test_unconfirmed_rule_state_stops_the_deployment(self):
        for switch, echo in (("", "opposite"), ("EnableRules", "opposite"), ("", "missing")):
            with self.subTest(switch=switch, echo=echo):
                result = self.run_deploy(switch=switch, echo=echo)
                expected = "enabled" if switch else "disabled"
                self.assertIn(
                    f"did not confirm analytics rule '{RULE_NAMES[0]}' as {expected}",
                    result["error"] or "",
                )
                self.assertEqual(len(result["puts"]), 1, result)
                self.assertEqual(result["tempFilesLeft"], 0, result)
                self.assertIn(f"Deploying: {RULE_NAMES[0]}", result["output"])
                self.assertNotIn("Created: ", result["output"])
                self.assertNotIn("Deployment complete!", result["output"])
                self.assertNotIn("Deployed Resources", result["output"])

    def test_enable_rules_is_rejected_with_destroy_before_any_azure_call(self):
        result = self.run_deploy(switch="EnableRules", destroy=True, existing="enabled")
        self.assertIn("cannot be combined with -Destroy", result["error"] or "")
        self.assertEqual(result["calls"], [])

    def test_get_help_explains_the_disabled_default(self):
        completed = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
             "Get-Help $env:RULE_STATE_DEPLOY_SCRIPT -Parameter EnableRules | Out-String -Width 200"],
            env={**os.environ, "RULE_STATE_DEPLOY_SCRIPT": str(DEPLOY_SCRIPT)},
            capture_output=True, text=True, timeout=60, check=False,
        )
        help_text = " ".join(completed.stdout.split())
        self.assertIn(
            "Without this switch the rules are created or updated disabled",
            help_text, completed.stderr or completed.stdout,
        )
        self.assertIn("Alias: -EnableSentinelRules", help_text)


if __name__ == "__main__":
    unittest.main()
