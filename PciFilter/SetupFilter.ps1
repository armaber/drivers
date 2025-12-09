<#
.SYNOPSIS
    Install or uninstall the filter driver on the target machine.

.PARAMETER DeviceInstanceId
    Filter a PCI device instead of the whole system class.

.PARAMETER Uninstall
    Set this switch for uninstall. The absence implies "install" mode.

.PARAMETER FromFile
    Filter driver has its start mode identical with the FDO driver. Use this
    switch to copy the source to default Windows folder, where "boot start"
    drivers are mandatory to be located.

.DESCRIPTION
    With a default install mode, the filter prepares the HKLM registry key and
    configures a kernel boot service. Use -Uninstall to revert the operation.
#>
#Requires -PSEdition Core

[CmdletBinding(DefaultParameterSetName="Install")]
param([Parameter(ParameterSetName="Install", Position=0)]
      [string]$FromFile,
      [Parameter(ParameterSetName="Install", Position=1)]
      [Parameter(ParameterSetName="Uninstall", Position=1)]
      [Alias("DeviceId")]
      [string]$DeviceInstanceId,
      [Parameter(ParameterSetName="Uninstall", Position=0)]
      [switch]$Uninstall)

$FilterName = "PciFilter";
$ret = $false;
. $PSScriptRoot\functions.ps1;

switch ($PSCmdlet.ParameterSetName)
{
    "Install" {
        $baseName = "$FilterName.sys";
        if ($FromFile) {
            $baseName = Split-Path -Leaf $FromFile;
            Copy-Item $FromFile $env:SystemRoot\System32\drivers\$baseName;
        } elseif (! (Test-Path $env:SystemRoot\System32\drivers\$baseName)) {
            "$baseName must be present in the drivers folder" | Write-Host;
            return;
        }
        if (! $DeviceInstanceId) {
            $ret = SetClassFilter $FilterName;
            $displayName = "PCI Bus Filter Driver";
        } else {
            ImportNative;
            $ret = SetDeviceFilter $DeviceInstanceId $FilterName;
            $displayName = "PCI Device Filter Driver";
        }
        if (! $ret) {
            return;
        }
        & sc.exe create $FilterName binPath= System32\Drivers\$baseName DisplayName= $displayName start= boot type= kernel error= normal group= "System Bus Extender" | Write-Host;
        & sc.exe qc $FilterName | Write-Host;
    }
    "Uninstall" {
        if (! $DeviceInstanceId) {
            $ret = UnsetClassFilter $FilterName;
        } else {
            ImportNative;
            $ret = UnsetDeviceFilter $DeviceInstanceId $FilterName;
        }
        if (! $ret) {
            return;
        }
        & sc.exe delete $FilterName | Write-Host;
    }
}
