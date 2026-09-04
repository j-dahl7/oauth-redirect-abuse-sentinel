# Explicit native exit checking also works when PowerShell's native-error
# experimental feature is unavailable or disabled. Never stream failed output
# into a JSON parser or let an unsuccessful delete look like a completed write.
function Invoke-AzChecked {
    $previousNativePreference = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
    $global:LASTEXITCODE = 0
    try {
        $output = & az @args
        $exitCode = $LASTEXITCODE
    }
    finally {
        $PSNativeCommandUseErrorActionPreference = $previousNativePreference
    }
    if ($exitCode -ne 0) {
        # Do not echo arguments, response bodies, or credentials in the error.
        throw "Azure CLI command failed with exit code $exitCode."
    }
    return $output
}
