<#
.SYNOPSIS
    Bootstrap a driver package from CLI, using predefined settings:

    - a comprehensive .vcxproj that does driver signing, static analysis, uses
      clang-tidy. Driver types supported are KMDF, WDM and Export Driver.
    - a minimalistic source file, compliant to C17 standard. The base
      NTDDI_VERSION is set to 0xA00 representing Windows 10. Spectre mitigations
      are on.

    Use a "Developer Powershell for VS 2022" console to launch msbuild.

.PARAMETER Kmdf
    Generate a KMDF source and project, Plug-and-Play.

.PARAMETER Wdm
    Generate a WDM source and project, allows for Control Device Object.

.PARAMETER ControlDeviceObject
    Does not have an AddDevice, creates a DO.

.PARAMETER ExportDriver
    Create a DLL in kernel mode that can be linked by a driver.

.PARAMETER ProjectName
    Name of the target image, for Debug or Release x64 builds.

.PARAMETER CertificatePath
    Either the .sys image or the .cat file will be signed using the
    thumbprint embedded in the .cer file. Use 
        PS > ..\setup\PrepareTestCertificate.ps1 -GenerateSelfSign -CerPath
    to obtain the file.

.NOTES
    Visual Studio 2022 Community is cumbersome. VSCode is familiar, its layout
    allows for unmitigated development. Having a script that gives a driver tree
    bypasses the prolonged startup time of the  dedicated IDE.

    Pitfalls in the .vcxproj IDE interaction require workarounds, now automated:

    1) activating CLang-Tidy for sanitization surfaced a defect, whose source
       is located in
         Project Properties -> C/C++ -> All Options -> AdditionalOptions
       The startup project uses
         <AdditionalOptions>/kernel</AdditionalOptions>
       to remove default
         %(ClCompile.AdditionalOptions) 
  
    2) signing an image requires new timestamp server URL, as previous URL is
       retired. Subject and Thumbprint stored in .cer file are embedded in .vcxproj.
       The file itself cannot be used as an argument in the <TestCertificate>
       setting.

    3) Besides the XML template transformed into .vcxproj, a .vcxproj.user is
       required. Merging both files into one .vcxproj deactivates the settings.
#>

[CmdletBinding(DefaultParameterSetName="Kmdf")]
param(
    [Parameter(ParameterSetName="Kmdf", Position=0)]
    [switch]$Kmdf,
    [Parameter(ParameterSetName="Wdm", Position=0)]
    [switch]$Wdm,
    [Parameter(ParameterSetName="Wdm", Position=1)]
    [Alias("Service")]
    [switch]$ControlDeviceObject,
    [Parameter(ParameterSetName="ExportDriver", Position=0)]
    [switch]$ExportDriver,
    [Parameter(Position=1, Mandatory)]
    [string]$ProjectName,
    [Parameter(Position=2)]
    [string]$CertificatePath,
    [Parameter(ParameterSetName="Kmdf", Position=3)]
    [Parameter(ParameterSetName="Wdm", Position=3)]
    [Parameter(ParameterSetName="Ed", Position=3)]
    [ValidateSet('NTDDI_WIN7', 'NTDDI_WIN8', 'NTDDI_WINBLUE', 'NTDDI_WINTHRESHOLD',
                 'NTDDI_WIN10', 'NTDDI_WIN10_TH2', 'NTDDI_WIN10_RS1', 'NTDDI_WIN10_RS2',
                 'NTDDI_WIN10_RS3', 'NTDDI_WIN10_RS4', 'NTDDI_WIN10_RS5', 'NTDDI_WIN10_19H1',
                 'NTDDI_WIN10_VB', 'NTDDI_WIN10_MN', 'NTDDI_WIN10_FE', 'NTDDI_WIN10_CO',
                 'NTDDI_WIN10_NI', 'NTDDI_WIN10_CU', 'NTDDI_WIN11_ZN', 'NTDDI_WIN11_GA',
                 'NTDDI_WIN11_GE')]
    $NtddiVersion = 'NTDDI_WIN10'
)

. $PSScriptRoot\functions.ps1;

if (! $CertificatePath) {
    Remove-Item -ErrorAction SilentlyContinue "${ProjectName}.vcxproj.user";
}
EvaluateNtddi $NtddiVersion;
switch ($PSCmdlet.ParameterSetName)
{
    "Kmdf" {
        GenerateVcxproj -Kmdf $ProjectName -NtddiVersion:$NtddiVersion;
        GenerateSourceCode -Kmdf $ProjectName;
        if ($CertificatePath) {
            GenerateUserVcxproj $ProjectName $CertificatePath;
        }
    }
    "Wdm" {
        GenerateVcxproj -Wdm $ProjectName -ControlDeviceObject:$ControlDeviceObject -NtddiVersion:$NtddiVersion;
        GenerateSourceCode -Wdm $ProjectName;
        if ($CertificatePath) {
            GenerateUserVcxproj $ProjectName $CertificatePath;
        }
    }
    "ExportDriver" {
        GenerateVcxproj -ExportDriver $ProjectName -NtddiVersion:$NtddiVersion;
        GenerateSourceCode -ExportDriver $ProjectName;
    }
}

SuggestCodeQl;