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
