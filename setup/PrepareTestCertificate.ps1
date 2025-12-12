<#
.SYNOPSIS
    Generate a .cer file and install a private key into development machine, or
    Migrate a .cer file to a target machine, install it and have it recognized by the OS

.PARAMETER GenerateSelfSign
    Generate a self signed certificate on the development machine. Locate it on certmgr.msc,
    Personal -> Certificates -> github.com/armaber.

.PARAMETER PrepareBcdEdit
    Set "testsigning on" for the {current} bcdedit store. Use it on a target machine,
    where a self signed driver package is about to be installed. It must be launched
    with elevation.

.PARAMETER CerPath
    File where the certificate is stored. Copy it to the target machine, relaunch with
    -PrepareBcdEdit -CerPath <RemotePath>.
#>

[CmdletBinding(DefaultParameterSetName="LocalDevelopment")]
param(
    [Parameter(ParameterSetName="LocalDevelopment", Position=0)]
    [switch]$GenerateSelfSign,
    [Parameter(ParameterSetName="TargetInstall", Position=0)]
    [switch]$PrepareBcdEdit,
    [Parameter(ParameterSetName="LocalDevelopment", Position=1)]
    [Parameter(ParameterSetName="TargetInstall", Position=1)]
    [string]$CerPath = ".\testcertificate.cer"
)

function GeneratePfxCertificate
{
    param([string]$CerPath)

    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=github.com/armaber" -CertStoreLocation "Cert:\CurrentUser\My" -FriendlyName "Selfsign from $PSCommandPath";
    Export-Certificate -Cert $cert -FilePath $CerPath -Type CERT;
    Write-Warning "The private key is not protected by a password";
}

function InstallPfxOnTarget
{
    param([string]$CerPath)

    [Security.Principal.WindowsPrincipal]$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent();
    $isAdmin = $currentIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
    if (-not $isAdmin) {
        throw "Launch the script with elevation";
    }
    if (-not (& bcdedit.exe /enum `{current`} | Select-String -Pattern "testsigning\s+Yes" -Quiet)) {
        & bcdedit.exe /set testsigning on;
        if ($LASTEXITCODE) {
            throw "bcdedit failed with $LASTEXITCODE";
        }
    }
    Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction Stop | Out-Null;
    Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -ErrorAction Stop | Out-Null;
    Write-Host "Restart the OS to apply changes";
}

if ($PSCmdlet.ParameterSetName -eq "LocalDevelopment") {
    GeneratePfxCertificate $CerPath;
} else {
    InstallPfxOnTarget $CerPath;
}

