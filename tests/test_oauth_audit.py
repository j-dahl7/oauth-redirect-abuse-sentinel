"""Run the real read-only audit against inert, paged Graph responses; no login/network."""
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GRAPH = "https://graph.microsoft.com/v1.0/"


def guid(number):
    return f"00000000-0000-0000-0000-{number:012d}"


def principal(number, **extra):
    return {"id": guid(number), "appId": guid(number + 100),
            "displayName": f"Fixture principal {number}", "servicePrincipalType": "Application",
            "replyUrls": [], "appRoles": [], **extra}


def app(number, **extra):
    return {"id": guid(number + 200), "appId": guid(number + 100),
            "displayName": f"Fixture app {number}", "signInAudience": "AzureADMyOrg",
            "web": {"redirectUris": []}, "spa": {"redirectUris": []},
            "publicClient": {"redirectUris": []}, **extra}


def collection(items, next_link=None):
    result = {"value": items}
    if next_link:
        result["@odata.nextLink"] = GRAPH + next_link
    return result


def fixture():
    """Local+external delegated clients and a managed identity with app-only grants."""
    role = {"id": guid(500), "value": "Mail.Read", "allowedMemberTypes": ["Application"]}
    resource = principal(9, appRoles=[role])
    routes = {
        "applications": collection([app(1)], "applications?page=2"),
        "applications?page=2": collection([app(4, web={"redirectUris": ["http://remote.example/"]})]),
        "oauth2PermissionGrants": collection([], "oauth2PermissionGrants?page=2"),
        "oauth2PermissionGrants?page=2": collection([
            {"clientId": guid(1), "resourceId": guid(9), "scope": "Mail.Read", "consentType": "AllPrincipals"},
            {"clientId": guid(2), "resourceId": guid(9), "scope": "Mail.ReadWrite", "consentType": "Principal"}]),
        "servicePrincipals": collection([principal(1), principal(2)], "servicePrincipals?page=2"),
        "servicePrincipals?page=2": collection([principal(3, servicePrincipalType="ManagedIdentity"), resource]),
    }
    for number in (1, 2, 3, 9):
        routes[f"servicePrincipals/{guid(number)}/appRoleAssignments"] = collection([])
    roles_path = f"servicePrincipals/{guid(3)}/appRoleAssignments"
    routes[roles_path] = collection([], roles_path + "?page=2")
    routes[roles_path + "?page=2"] = collection([
        {"principalId": guid(3), "resourceId": guid(9), "appRoleId": guid(500)}])
    return {"routes": routes}


HARNESS = r'''
$ErrorActionPreference='Stop'
$global:fixture=Get-Content -LiteralPath $env:AUDIT_FIXTURE -Raw | ConvertFrom-Json -AsHashtable
$global:requests=[Collections.Generic.List[string]]::new()
function global:az {
    $global:LASTEXITCODE=0
    if ($args[0] -eq 'account' -and $args[1] -eq 'show') {
        if ($global:fixture.accountFailure) {
            & $env:NATIVE_PYTHON -c 'import sys; sys.exit(7)'
            return
        }
        return (@{tenantId='11111111-1111-1111-1111-111111111111'} | ConvertTo-Json -Compress)
    }
    if ($args[0] -ne 'rest' -or $args[([array]::IndexOf($args,'--method')+1)] -ne 'GET') {
        throw 'Unexpected non-read command in fixture'
    }
    $url=$args[([array]::IndexOf($args,'--url')+1)]
    $global:requests.Add($url)
    $uri=[Uri]$url
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'graph.microsoft.com' -or $uri.UserInfo) { throw 'Unsafe request reached fixture transport' }
    $key=$uri.AbsolutePath -replace '^/v1.0/',''
    if ($uri.Query -match 'page=') { $key += $uri.Query }
    if (-not $global:fixture.routes.ContainsKey($key)) { throw "Unexpected fixture URL: $key" }
    $response=$global:fixture.routes[$key]
    if ($response.ContainsKey('nativeFailure')) {
        & $env:NATIVE_PYTHON -c 'import sys; print("denied-fixture-output"); sys.exit(int(sys.argv[1]))' $response.nativeFailure
        return
    }
    return ($response | ConvertTo-Json -Depth 20 -Compress)
}
try {
    & $env:AUDIT_SCRIPT -TenantId $env:AUDIT_TENANT -OutputPath $env:AUDIT_OUTPUT
} finally {
    ConvertTo-Json -InputObject @($global:requests) | Set-Content -LiteralPath $env:AUDIT_REQUESTS
}
'''


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7.4+ is required")
class OAuthAuditTests(unittest.TestCase):
    def run_audit(self, scenario, tenant="11111111-1111-1111-1111-111111111111", previous=None):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "fixture.json").write_text(json.dumps(scenario), encoding="utf-8")
            (folder / "harness.ps1").write_text(HARNESS, encoding="utf-8")
            output = folder / "report.csv"
            if previous:
                output.write_bytes(previous.encode("utf-8"))
            env = {**os.environ, "AUDIT_FIXTURE": str(folder / "fixture.json"),
                   "AUDIT_SCRIPT": os.environ.get("OAUTH_AUDIT_SOURCE", str(ROOT / "hardening/Audit-OAuthApps.ps1")),
                   "AUDIT_OUTPUT": str(output), "AUDIT_REQUESTS": str(folder / "requests.json"),
                   "AUDIT_TENANT": tenant, "NATIVE_PYTHON": sys.executable}
            result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(folder / "harness.ps1")],
                                    env=env, capture_output=True, text=True, timeout=30, check=False)
            raw = output.read_bytes().decode("utf-8-sig") if output.exists() else None
            rows = list(csv.DictReader(raw.splitlines())) if raw and raw != previous else []
            requests = json.loads((folder / "requests.json").read_text(encoding="utf-8-sig"))
            return result, rows, requests, raw

    def test_paged_external_delegated_and_managed_identity_app_roles_are_reported(self):
        result, rows, requests, _ = self.run_audit(fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        by_id = {row["AppId"]: row for row in rows}
        self.assertEqual(set(by_id), {guid(101), guid(102), guid(103), guid(104)})
        self.assertEqual(len(rows), 4, "Local application and SP must not produce duplicate findings")
        self.assertEqual(by_id[guid(101)]["ObjectType"], "ApplicationRegistration")
        self.assertIn("ADMIN_CONSENTED_HIGH_PRIV:Mail.Read", by_id[guid(101)]["RiskFlags"])
        self.assertEqual(by_id[guid(102)]["ObjectType"], "ServicePrincipal")
        self.assertIn("USER_CONSENTED_HIGH_PRIV:Mail.ReadWrite", by_id[guid(102)]["RiskFlags"])
        self.assertIn(guid(9), by_id[guid(102)]["DelegatedPermissions"])
        managed = by_id[guid(103)]
        self.assertEqual(managed["ServicePrincipalType"], "ManagedIdentity")
        self.assertIn(f"{guid(9)}/{guid(500)}:Mail.Read", managed["ApplicationPermissions"])
        self.assertIn("HIGH_PRIV_APPLICATION_PERMISSION:Mail.Read", managed["RiskFlags"])
        self.assertEqual(sum("appRoleAssignments" in url for url in requests), 5)
        self.assertTrue(any("servicePrincipals?$top=100&" in url for url in requests))

    def test_custom_default_and_unresolved_roles_remain_visible(self):
        scenario = fixture()
        scenario["routes"]["servicePrincipals?page=2"]["value"][1]["appRoles"].append({"id": guid(501), "value": "Custom.Reader"})
        path = f"servicePrincipals/{guid(3)}/appRoleAssignments?page=2"
        scenario["routes"][path]["value"] = [
            {"principalId": guid(3), "resourceId": guid(9), "appRoleId": guid(501)},
            {"principalId": guid(3), "resourceId": guid(9), "appRoleId": guid(0)},
            {"principalId": guid(3), "resourceId": guid(9), "appRoleId": guid(502)},
            {"principalId": guid(3), "resourceId": guid(88), "appRoleId": guid(500)}]
        result, rows, _, _ = self.run_audit(scenario)
        self.assertEqual(result.returncode, 0, result.stderr)
        managed = next(row for row in rows if row["AppId"] == guid(103))
        self.assertIn("Custom.Reader", managed["ApplicationPermissions"])
        self.assertIn("DEFAULT_ACCESS", managed["ApplicationPermissions"])
        self.assertEqual(managed["ApplicationPermissions"].count("UNRESOLVED"), 2)
        self.assertIn("UNRESOLVED_APPLICATION_PERMISSION", managed["RiskFlags"])
        self.assertNotIn("HIGH_PRIV_APPLICATION_PERMISSION", managed["RiskFlags"])

    def test_http_exemption_uses_exact_loopback_host_and_checks_enterprise_reply_urls(self):
        uris = ["http://localhost/cb", "http://127.0.0.1:9000/cb", "http://[::1]/cb",
                "http://localhost.evil.example/cb", "http://127.0.0.1.evil.example/cb",
                "http://remote.example/localhost", "http://remote.example/?host=127.0.0.1",
                "http://localhost@remote.example/cb", "https://remote.example/cb"]
        scenario = {"routes": {"applications": collection([]), "oauth2PermissionGrants": collection([]),
                               "servicePrincipals": collection([principal(i + 20, replyUrls=[uri]) for i, uri in enumerate(uris)])}}
        for i in range(len(uris)):
            scenario["routes"][f"servicePrincipals/{guid(i + 20)}/appRoleAssignments"] = collection([])
        result, rows, _, _ = self.run_audit(scenario)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({row["AppId"] for row in rows}, {guid(i + 120) for i in range(3, 8)})
        self.assertTrue(all("NON_HTTPS_REDIRECT" in row["RiskFlags"] for row in rows))

    def test_formula_like_names_are_neutralized_only_in_csv(self):
        names = ["=fixture", "+fixture", "-fixture", "@fixture", "  =fixture", "\tfixture", "\rfixture", "\nfixture", "Normal fixture"]
        scenario = {"routes": {"applications": collection([
            app(i + 20, displayName=name, signInAudience="AzureADMultipleOrgs") for i, name in enumerate(names)]),
            "oauth2PermissionGrants": collection([]), "servicePrincipals": collection([])}}
        result, _, _, raw = self.run_audit(scenario)
        self.assertEqual(result.returncode, 0, result.stderr)
        import io
        rows = list(csv.DictReader(io.StringIO(raw)))
        self.assertEqual([row["AppName"] for row in rows], ["'" + name for name in names[:-1]] + [names[-1]])
        self.assertTrue(all(row["RiskScore"] == "1" for row in rows))
        self.assertIn("=fixture", result.stdout)

    def test_registration_http_uri_cannot_hide_loopback_text_in_remote_host_path_or_query(self):
        uris = ["http://localhost.evil.example/cb", "http://remote.example/localhost",
                "http://remote.example/?host=127.0.0.1"]
        scenario = {"routes": {"applications": collection([
            app(i + 20, web={"redirectUris": [uri]}) for i, uri in enumerate(uris)]),
            "oauth2PermissionGrants": collection([]), "servicePrincipals": collection([])}}
        result, rows, _, _ = self.run_audit(scenario)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({row["AppId"] for row in rows}, {guid(i + 120) for i in range(3)})
        self.assertTrue(all("NON_HTTPS_REDIRECT" in row["RiskFlags"] for row in rows))

    def test_later_page_native_failures_never_export_partial_or_clean_results(self):
        for code in (1, 7, 29):
            with self.subTest(code=code):
                scenario = fixture()
                path = f"servicePrincipals/{guid(3)}/appRoleAssignments?page=2"
                scenario["routes"][path] = {"nativeFailure": code}
                result, rows, _, raw = self.run_audit(scenario, previous="prior report\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(raw, "prior report\n")
                self.assertFalse(rows)
                self.assertNotIn("Audit complete", result.stdout)
                self.assertNotIn("denied-fixture-output", result.stdout + result.stderr)

    def test_invalid_cyclic_and_off_host_pages_abort_before_export(self):
        variants = [{"value": {}}, {"value": None}, {"value": [], "@odata.nextLink": {"url": "bad"}},
                    {"value": [], "@odata.nextLink": GRAPH + "applications"},
                    {"value": [], "@odata.nextLink": "https://graph.microsoft.com.evil.example/page"},
                    {"value": [], "@odata.nextLink": "https://user@graph.microsoft.com/page"},
                    {"value": [], "@odata.nextLink": "http://graph.microsoft.com/page"}]
        for response in variants:
            with self.subTest(response=response):
                scenario = fixture()
                scenario["routes"]["applications"] = response
                result, _, requests, raw = self.run_audit(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(raw)
                self.assertLessEqual(len(requests), 2)
                self.assertTrue(all("evil.example" not in uri and "user@" not in uri for uri in requests))

    def test_unmatched_grant_and_wrong_assignment_client_cannot_silently_disappear(self):
        for kind in ("grant", "assignment"):
            scenario = fixture()
            if kind == "grant":
                scenario["routes"]["oauth2PermissionGrants?page=2"]["value"][0]["clientId"] = guid(88)
            else:
                path = f"servicePrincipals/{guid(3)}/appRoleAssignments?page=2"
                scenario["routes"][path]["value"][0]["principalId"] = guid(88)
            result, _, _, raw = self.run_audit(scenario)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(raw)

    def test_account_failure_or_tenant_mismatch_stops_before_graph_reads(self):
        for failure in (True, False):
            scenario = fixture()
            scenario["accountFailure"] = failure
            result, _, requests, raw = self.run_audit(scenario, tenant=guid(77))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(requests, [])
            self.assertIsNone(raw)


if __name__ == "__main__":
    unittest.main()
