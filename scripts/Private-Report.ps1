#Requires -Version 7.6
function New-OwnerOnlyFileStream {
    param([Parameter(Mandatory)][string]$Path)
    if ($IsWindows) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $acl = [System.Security.AccessControl.FileSecurity]::new()
        $acl.SetOwner($identity.User)
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity.User, [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow))
        return [System.IO.FileSystemAclExtensions]::Create(
            [System.IO.FileInfo]::new($Path), [System.IO.FileMode]::CreateNew,
            [System.Security.AccessControl.FileSystemRights]::Write,
            [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::None, $acl)
    }
    $options = [System.IO.FileStreamOptions]::new()
    $options.Mode = [System.IO.FileMode]::CreateNew
    $options.Access = [System.IO.FileAccess]::Write
    $options.Share = [System.IO.FileShare]::None
    $options.UnixCreateMode = [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
    return [System.IO.FileStream]::new($Path, $options)
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

function Assert-OwnerOnlyReport {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType) {
        throw "Refusing report symlink/reparse point '$Path'."
    }

    if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )) {
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $acl = Get-Acl -LiteralPath $Path
        $ownerSid = $acl.GetOwner(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
        if ($ownerSid -ne $currentSid) {
            throw "Report '$Path' is not owned by the current Windows identity."
        }
        $foreignAllowRules = @(
            $acl.Access | Where-Object {
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -ne $currentSid
            }
        )
        if ($foreignAllowRules.Count -gt 0) {
            throw "Report '$Path' grants access to a principal other than its owner."
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
            throw "Report '$Path' is not owner-only (expected mode 0600)."
        }
    }
}

function Write-OwnerOnlyReport {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $directory = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $json = $Content

    $targetExists = Test-Path -LiteralPath $fullPath
    if ($targetExists) {
        Assert-OwnerOnlyReport $fullPath
    }

    # Owner-only access is part of creation, before any process could open the
    # staging inode/file. Tightening permissions after creation would not revoke
    # another local user's already-open read handle.
    $temporaryPath = "$fullPath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $stream = New-OwnerOnlyFileStream -Path $temporaryPath
        try {
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }

        Assert-OwnerOnlyReport $temporaryPath
        $contentStream = [System.IO.File]::Open(
            $temporaryPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            $reportWriter = [System.IO.StreamWriter]::new(
                $contentStream,
                [System.Text.UTF8Encoding]::new($false),
                4096,
                $true
            )
            try {
                $reportWriter.Write($json)
                $reportWriter.Flush()
                $contentStream.Flush($true)
            } finally {
                $reportWriter.Dispose()
            }
        } finally {
            $contentStream.Dispose()
        }
        Assert-OwnerOnlyReport $temporaryPath

        if ($targetExists) {
            # Revalidate immediately before replacement. The final assertion
            # below also verifies the ACL/mode that survived the atomic move.
            Assert-OwnerOnlyReport $fullPath
            [System.IO.File]::Move($temporaryPath, $fullPath, $true)
        } else {
            [System.IO.File]::Move($temporaryPath, $fullPath, $false)
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }

    Assert-OwnerOnlyReport $fullPath
}
