#Requires -RunAsAdministrator

param([Switch]$Remove)

$ErrorActionPreference = "Stop";

$driverPath = "${env:SystemRoot}\System32\drivers\Review7B.sys";
if ($Remove) {
    if (Test-Path $driverPath) {
        sc.exe stop Review7B;
        sc.exe delete Review7B;
        Remove-Item $driverPath;
    }
    return;
}

Copy-Item $PSScriptRoot\Review7B.sys $driverPath;
sc.exe create Review7B binPath= System32\Drivers\Review7B.sys DisplayName= "Research INACCESSIBLE_BOOT_DEVICE BSOD" start= boot type= kernel error= normal group= "System Bus Extender";

"Restart the system to load the driver during early startup stage.";
