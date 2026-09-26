[CmdletBinding()]
param([Parameter(Mandatory)][string]$KustoAssembly)
$ErrorActionPreference = 'Stop'
Add-Type -Path $KustoAssembly
# These are documented column types, not a tenant data fixture. Dynamic payload
# property presence and production matching still require a workspace check.
$signins = '(TimeGenerated:datetime,UserId:string,UserPrincipalName:string,IPAddress:string,AppDisplayName:string,AppId:string,ResourceDisplayName:string,ResultType:string,RiskLevelDuringSignIn:string,RiskEventTypes_V2:string,CorrelationId:string,Location:string,LocationDetails:dynamic,TokenIssuerType:string)'
$audits = '(TimeGenerated:datetime,OperationName:string,InitiatedBy:dynamic,TargetResources:dynamic,Id:string,CorrelationId:string)'
$tables = @(
    [Kusto.Language.Symbols.TableSymbol]::new('SigninLogs', $signins, 'Documented sign-in column types'),
    [Kusto.Language.Symbols.TableSymbol]::new('AuditLogs', $audits, 'Documented audit column types')
)
$database = [Kusto.Language.Symbols.DatabaseSymbol]::new('OfflineValidation', [Kusto.Language.Symbols.Symbol[]]$tables)
$kustoState = [Kusto.Language.GlobalState]::Default.WithDatabase($database)
function Assert-Query {
    param([string]$Query, [string]$Name, [string[]]$RequiredStringColumns = @())
    $code = [Kusto.Language.KustoCode]::ParseAndAnalyze($Query, $kustoState, [Kusto.Language.Utils.CancellationToken]::new())
    $diagnostics = @($code.GetDiagnostics())
    if ($diagnostics.Count) {
        $diagnostics | Select-Object Code, Severity, Message | Format-Table
        throw "$Name failed offline KQL semantic analysis."
    }
    foreach ($column in $RequiredStringColumns) {
        $result = @($code.ResultType.Columns | Where-Object Name -eq $column)
        if ($result.Count -ne 1 -or $result[0].Type.Name -ne 'string') {
            throw "$Name is missing the mapped/correlation string column $column."
        }
    }
}
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Deploy-Lab.ps1') -Raw
$queries = [regex]::Matches($source, '(?s)query\s+= @"\r?\n(.*?)\r?\n"@')
if ($queries.Count -ne 4) { throw 'Expected all four deployed queries.' }
$required = @{ 0=@('ConsentUserId','SourceIP'); 1=@('InitiatedByUserId','RedirectUri'); 2=@('AppIdUsed'); 3=@('AppId') }
for ($index=0; $index -lt $queries.Count; $index++) {
    Assert-Query -Query $queries[$index].Groups[1].Value.Replace('`$', '$') -Name "Rule $($index+1)" -RequiredStringColumns $required[$index]
}
$hunts = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../detection/hunting-queries.kql') -Raw
$parts = [regex]::Split($hunts, '// HUNT [1-5]:')
if ($parts.Count -ne 6) { throw 'Expected all five hunting queries.' }
for ($index=1; $index -lt $parts.Count; $index++) {
    # Strip each section's title/purpose comments before its closing separator.
    $query = [regex]::Split($parts[$index], '// -+\r?\n', 2)[1]
    Assert-Query -Query $query -Name "Hunt $index"
}
$workbookQueries = [regex]::Matches($source, '"version": "KqlItem/1.0",\s*"query": ("(?:\\.|[^"\\])*")')
if ($workbookQueries.Count -ne 4) { throw 'Expected all four workbook queries.' }
foreach ($query in $workbookQueries) {
    Assert-Query -Query ($query.Groups[1].Value | ConvertFrom-Json) -Name 'Workbook query'
}
Write-Host 'PASS: four deployed rules, five hunts, and four workbook queries parse and bind; mapped string columns exist. No tenant query was run.'
