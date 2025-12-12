$NtddiTable = @{
    NTDDI_WIN7 = 0x06010000;
    NTDDI_WIN8 = 0x06020000;
    NTDDI_WINBLUE = 0x06030000;
    NTDDI_WINTHRESHOLD = 0x0A000000;
    NTDDI_WIN10 = 0x0A000000;
    NTDDI_WIN10_TH2 = 0x0A000001;
    NTDDI_WIN10_RS1 = 0x0A000002;
    NTDDI_WIN10_RS2 = 0x0A000003;
    NTDDI_WIN10_RS3 = 0x0A000004;
    NTDDI_WIN10_RS4 = 0x0A000005;
    NTDDI_WIN10_RS5 = 0x0A000006;
    NTDDI_WIN10_19H1 = 0x0A000007;
    NTDDI_WIN10_VB = 0x0A000008;
    NTDDI_WIN10_MN = 0x0A000009;
    NTDDI_WIN10_FE = 0x0A00000A;
    NTDDI_WIN10_CO = 0x0A00000B;
    NTDDI_WIN10_NI = 0x0A00000C;
    NTDDI_WIN10_CU = 0x0A00000D;
    NTDDI_WIN11_ZN = 0x0A00000E;
    NTDDI_WIN11_GA = 0x0A00000F;
    NTDDI_WIN11_GE = 0x0A000010;
};

function GenerateVcxproj
{
    param(
        [Parameter(ParameterSetName="Kmdf", Position=0)]
        [switch]$Kmdf,
        [Parameter(ParameterSetName="Wdm", Position=0)]
        [switch]$Wdm,
        [Parameter(ParameterSetName="Wdm", Position=1)]
        [switch]$ControlDeviceObject,
        [Parameter(ParameterSetName="Ed", Position=0)]
        [switch]$ExportDriver,
        [Parameter(Position=1, Mandatory)]
        [string]$ProjectName,
        [Parameter(ParameterSetName="Kmdf", Position=2)]
        [Parameter(ParameterSetName="Wdm", Position=2)]
        [Parameter(ParameterSetName="Ed", Position=2)]
        [ValidateSet('NTDDI_WIN7', 'NTDDI_WIN8', 'NTDDI_WINBLUE', 'NTDDI_WINTHRESHOLD',
                     'NTDDI_WIN10', 'NTDDI_WIN10_TH2', 'NTDDI_WIN10_RS1', 'NTDDI_WIN10_RS2',
                     'NTDDI_WIN10_RS3', 'NTDDI_WIN10_RS4', 'NTDDI_WIN10_RS5', 'NTDDI_WIN10_19H1',
                     'NTDDI_WIN10_VB', 'NTDDI_WIN10_MN', 'NTDDI_WIN10_FE', 'NTDDI_WIN10_CO',
                     'NTDDI_WIN10_NI', 'NTDDI_WIN10_CU', 'NTDDI_WIN11_ZN', 'NTDDI_WIN11_GA',
                     'NTDDI_WIN11_GE')]
        $NtddiVersion = 'NTDDI_WIN10'
    )
    $content = Get-Content -Raw $PSScriptRoot\TemplateVcxproj.xml;
    $content = $content.Replace("@ProjectName@", $ProjectName).
                        Replace("@ProjectGuid@", (New-Guid).ToString().ToUpper()).
                        Replace("@SourceFilesGuid@", (New-Guid).ToString().ToUpper()).
                        Replace("@HeaderFilesGuid@", (New-Guid).ToString().ToUpper()).
                        Replace("@ResourceFilesGuid@", (New-Guid).ToString().ToUpper()).
                        Replace("@DriverFilesGuid@", (New-Guid).ToString().ToUpper());
    $content = $content.Replace("@TargetVersion@", "0x{0:X8}" -f $NtddiTable.$NtddiVersion);
    if ($Wdm) {
        $content = $content.Replace("<DriverType>KMDF</DriverType>", "<DriverType>WDM</DriverType>");
        if ($ControlDeviceObject) {
            $content = $content -replace "\s+<PostBuildEvent>`r`n(.+`r`n)+\s+</PostBuildEvent>", "";
            $content = $content -replace "\s+<ItemGroup>`r`n(\s+\<Inf Include=.+`r`n)+\s+</ItemGroup>", "";
        }
    }
    if ($ExportDriver) {
        $content = $content.Replace("<DriverType>KMDF</DriverType>", "<DriverType>ExportDriver</DriverType>");
        $content = $content.Replace("<ConfigurationType>Driver</ConfigurationType>", "<ConfigurationType>DynamicLibrary</ConfigurationType>");
        $content = $content.Replace("@LinkSettingsExportDriver@", @"
    <NoEntryPoint>true</NoEntryPoint>
    <ModuleDefinitionFile>$ProjectName.def</ModuleDefinitionFile>
"@);
        $content = $content -replace "\s+<ItemGroup>`r`n(\s+\<Inf Include=.+`r`n)+\s+</ItemGroup>", "";
    } else {
        $content = $content.Replace("        @LinkSettingsExportDriver@`r`n", "");
    }
    $content | Set-Content "$ProjectName.vcxproj";
}

function GenerateUserVcxproj
{
    param(
        [string]$ProjectName,
        [string]$CertificatePath
    )

    $certObject = Get-PfxCertificate $CertificatePath;
    $certString = $certObject.Subject + " | " + $certObject.Thumbprint;
    $content = Get-Content -Raw $PSScriptRoot\TemplateVcxprojUser.xml;
    $content = $content.Replace("@TestCertificate@", $certString);
    $content | Set-Content "$ProjectName.vcxproj.user";
}

function GenerateSourceCode
{
    param(
        [Parameter(ParameterSetName="Kmdf", Position=0)]
        [switch]$Kmdf,
        [Parameter(ParameterSetName="Wdm", Position=0)]
        [switch]$Wdm,
        [Parameter(ParameterSetName="Ed", Position=0)]
        [switch]$ExportDriver,
        [Parameter(Position=1, Mandatory)]
        [string]$ProjectName
    )

    if (! (Test-Path .\driver.c)) {
        if ($Kmdf) {
            $sourceFile = "$PSScriptRoot\TemplateKmdf.c";
        } elseif ($Wdm) {
            $sourceFile = "$PSScriptRoot\TemplateWdm.c";
        } else {
            $sourceFile = "$PSScriptRoot\TemplateExportDriver.c";
        }
        Copy-Item $sourceFile .\driver.c;
    }
    if ($ExportDriver -and ! (Test-Path $ProjectName.def)) {
        $content = Get-Content -Raw $PSScriptRoot\TemplateExportDriver.def;
        $content = $content.Replace("@ProjectName@", $ProjectName);
        $content | Set-Content ".\$ProjectName.def";
    }
}

function EvaluateNtddi
{
    param($NtddiVersion)

    if ($NtddiVersion -eq 'NTDDI_WIN11_GA') {

        $Vs2022Installed = $false;
        if (Get-Command msbuild -ErrorAction SilentlyContinue) {
            $version = & msbuild --version;
            if ($version[0] -like "MSBuild version 17.*") {
                $Vs2022Installed = $true;
            }
        }
        $warning = @"

If you are using Windows Driver Kit v10.0.26100, then msbuild toolchain does not recognize
NTDDI_WIN11_GA. Use NTDDI_WIN11_GE as alternative for the build error:
    Unknown or unsupported property value '0x0A00000F' for _NT_TARGET_VERSION and Target OS Windows10

Open "C:\Program Files (x86)\Windows Kits\10\build\10.0.26100.0\WindowsDriver.OS.Props"
and follow "Valid_NTTARGETVERSIONS" XML element.

The problem might surface on other WDK versions.
"@;
        if ($Vs2022Installed) {
            $warning | Write-Warning;
        } else {
            $warning | Write-Host;
        }
    }
}

function SuggestCodeQl
{
    $codeQl = (Get-Command codeql.exe -ErrorAction SilentlyContinue).Source;
    if (! $codeQl) {
        $codeQl = (Get-ChildItem -Recurse -Filter codeql.exe -LiteralPath $env:APPDATA -ErrorAction SilentlyContinue |
                  Select-Object -First 1).FullName;
    }
    if (! $codeQl) {
        return;
    }
@"

Use these commands to integrate CodeQL:

    New-Item -Type Directory CodeQlDatabase -ErrorAction SilentlyContinue | Out-Null;
    `$codeQl = "$codeQl";
    & `$codeQl database create CodeQlDatabase --overwrite --language=cpp --command="msbuild -T:Rebuild";
    & `$codeQl database analyze CodeQlDatabase microsoft/windows-drivers:windows-driver-suites/mustfix.qls --format=sarifv2.1.0 --output=DriverAnalysisMustFix.sarif --threads=0;
    & `$codeQl database analyze CodeQlDatabase microsoft/windows-drivers:windows-driver-suites/recommended.qls --format=sarifv2.1.0 --output=DriverAnalysisRecommended.sarif --threads=0;
"@;
    if (! (Get-Command sarif -ErrorAction SilentlyContinue)) {
@"
    & `$codeQl database analyze --format=CSV does not print the headers, use sarif-tools
        - pip install sarif-tools
        - sarif html `$PWD\DriverAnalysisRecommended.sarif -o `$PWD\DriverAnalysisRecommended.html
        - sarif csv `$PWD\DriverAnalysisMustFix.sarif -o `$PWD\DriverAnalysisMustFix.csv
"@;
    }
}
