using namespace System.Runtime.InteropServices;

$SystemClass = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e97d-e325-11ce-bfc1-08002be10318}";

$DIGCF_ALLCLASSES = 4;
$DIGCF_PRESENT = 2;
$SPDRP_LOWERFILTERS = 0x12;
$ERROR_INVALID_DATA = 13;

function ImportNative
{
    $co = [System.CodeDom.Compiler.CompilerParameters]::new();
    $co.CompilerOptions += "/unsafe";

    Add-Type -CompilerOptions $co @"
        using System;
        using System.Runtime.InteropServices;

        [StructLayout(LayoutKind.Sequential)]
        public struct SP_DEVINFO_DATA
        {
            public UInt32 cbSize;
            public Guid ClassGuid;
            public UInt32 DevInst;
            public IntPtr Reserved;
        };

        public static class NativeMethod {
            [DllImport("kernel32.dll")]
            public static extern UInt32
                GetLastError();
            [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
            public static extern IntPtr
                SetupDiGetClassDevs(IntPtr DeviceClasses,
                                    [MarshalAs(UnmanagedType.LPTStr)] string Enumerator,
                                    IntPtr Hwnd,
                                    UInt32 Flags);
            [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
            public static extern bool
                SetupDiEnumDeviceInfo(IntPtr DeviceInfoSet,
                                      UInt32 MemberIndex,
                                      ref SP_DEVINFO_DATA DeviceInfoData);
            [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
            public static extern UInt32
                CM_Get_DevNode_Status(ref UInt32 Status,
                                      ref UInt32 Problem,
                                      IntPtr DevInst,
                                      UInt32 Flags);
            [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
            public static extern UInt32
                CM_Get_Device_ID(IntPtr DevInst,
                                 IntPtr Buffer,
                                 UInt32 Size,
                                 UInt32 Flags);
            [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
            public static extern IntPtr
                SetupDiOpenDevRegKey(IntPtr DeviceInfoSet,
                                     ref SP_DEVINFO_DATA DeviceInfoData,
                                     UInt32 Scope,
                                     UInt32 Profile,
                                     UInt32 Type,
                                     UInt32 Desired);
            [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
            public static extern bool
                SetupDiSetDeviceRegistryProperty(IntPtr DeviceInfoSet,
                                                 ref SP_DEVINFO_DATA DeviceInfoData,
                                                 UInt32 Property,
                                                 IntPtr Buffer,
                                                 UInt32 Size);
            [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
            public static extern bool
                SetupDiGetDeviceRegistryProperty(IntPtr DeviceInfoSet,
                                                 ref SP_DEVINFO_DATA DeviceInfoData,
                                                 UInt32 Property,
                                                 IntPtr OptionalType,
                                                 IntPtr Buffer,
                                                 UInt32 Size,
                                                 ref UInt32 RequiredSize);
            [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
            public static extern bool
                SetupDiDestroyDeviceInfoList(IntPtr Device);
        };
"@;
}

function FromIntPtrToMultiString
{
    param([IntPtr]$Buffer)

    [IntPtr]$current = $Buffer;
    [string[]]$multiString = @();
    while ($true) {
        $singleString = [Marshal]::PtrToStringUni($current);
        if ($singleString) {
            $multiString += $singleString;
        } else {
            break;
        }
        $current = [IntPtr]::Add($current, ($singleString.Length + 1) * 2);
    }

    return $multiString;
}

function FromMultiStringToIntPtr
{
    param([string[]]$MultiString)

    $requestSize = ($MultiString | ForEach-Object { ($PSItem.Length + 1) } | Measure-Object -Sum).Sum;
    $requestSize ++;
    $requestSize *= 2;
    $rawData = [Marshal]::AllocHGlobal($requestSize);
    $offset = 0;
    $MultiString | ForEach-Object {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($PSItem);
        [Marshal]::Copy($bytes, 0, [IntPtr]::Add($rawData, $offset), $bytes.Count);
        $offset += $bytes.Count;
        [Marshal]::WriteInt16($rawData, $offset, 0);
        $offset += 2;
    }
    [Marshal]::WriteInt16($rawData, $offset, 0);
    $offset += 2;

    return @{ Size = $requestSize; Buffer = $rawData };
}

function LocateDevice
{
    param([string]$DeviceInstanceId,
          [IntPtr]$DeviceSet,
          [ref][SP_DEVINFO_DATA]$DeviceData,
          [IntPtr]$Buffer,
          [UInt32]$Size)

    for ($m = 0; [NativeMethod]::SetupDiEnumDeviceInfo($DeviceSet, $m, $DeviceData); $m ++) {
        $c = [NativeMethod]::CM_Get_Device_ID($deviceData.Value.DevInst, $Buffer, $Size, 0);
        if ($c) {
            continue;
        }
        $di = [Marshal]::PtrToStringUni($Buffer);
        if ($di -eq $DeviceInstanceId) {
            return $true;
        }
    }

    return $false;
}

function SetClassFilter
{
    param([string]$Name)

    [string[]]$filters = (Get-ItemProperty $SystemClass -Name LowerFilters -ErrorAction SilentlyContinue).LowerFilters;
    if ($filters -contains $Name) {
        "$Name driver was installed" | Write-Host;
        return $false;
    }
    Set-ItemProperty $SystemClass -Name LowerFilters -Value ($filters + $Name) -Type MultiString;

    return $true;
}

function UnsetClassFilter
{
    param([string]$Name)

    [string[]]$filters = (Get-ItemProperty $SystemClass -Name LowerFilters -ErrorAction SilentlyContinue).LowerFilters;
    if ($filters -contains $Name) {
        $filters = $filters | Where-Object { $PSItem -ne $Name };
        if (! $filters) {
            Remove-ItemProperty $SystemClass -Name LowerFilters;
        } else {
            Set-ItemProperty $SystemClass -Name LowerFilters -Value $filters -Type MultiString;
        }
        return $true;
    }
    "$Name driver was not installed" | Write-Host;

    return $false;
}

function SetDeviceFilter
{
    param([string]$DeviceInstanceId,
          [string]$Name)

    [string[]]$multiFilter = @();
    [SP_DEVINFO_DATA]$deviceData = New-Object SP_DEVINFO_DATA;
    $deviceSet = [NativeMethod]::SetupDiGetClassDevs(0, "PCI", 0, $DIGCF_ALLCLASSES + $DIGCF_PRESENT);
    $deviceData.cbSize = [Marshal]::SizeOf($deviceData);
    [UInt32]$numChars = 512;
    [UInt32]$requestSize = 0;
    $addToFilter = $false;
    $rawData = [Marshal]::AllocHGlobal(2 * $numChars);
    $ret = $false;
    if (! (LocateDevice $DeviceInstanceId $deviceSet ([ref]$deviceData) $rawData $numChars)) {
        "$DeviceInstanceId is not found in the PCI tree" | Write-Host;
        [Marshal]::FreeHGlobal($rawData);
        [NativeMethod]::SetupDiDestroyDeviceInfoList($deviceSet) | Out-Null;
        return $ret;
    }
    $requestSize = 2 * $numChars;
    if (! [NativeMethod]::SetupDiGetDeviceRegistryProperty($deviceSet,
                                                           [ref]$deviceData,
                                                           $SPDRP_LOWERFILTERS,
                                                           [IntPtr]::Zero,
                                                           $rawData,
                                                           $requestSize,
                                                           [ref]$requestSize))
    {
        if ([NativeMethod]::GetLastError() -eq $ERROR_INVALID_DATA) {
            $addToFilter = $true;
        }
    } else {
        $multiFilter = FromIntPtrToMultiString $rawData;
        if ($multiFilter -notcontains $Name) {
            $addToFilter = $true;
        } else {
            "$Name driver was installed on $DeviceInstanceId" | Write-Host;
        }
    }
    if ($addToFilter) {
        $multiFilter += $Name;
        $requestPtr = FromMultiStringToIntPtr $multiFilter;
        [Marshal]::FreeHGlobal($rawData);
        $rawData = $requestPtr.Buffer;
        $requestSize = $requestPtr.Size;
        if (! [NativeMethod]::SetupDiSetDeviceRegistryProperty($deviceSet,
                                                               [ref]$deviceData,
                                                               $SPDRP_LOWERFILTERS,
                                                               $rawData,
                                                               $requestSize)) {
            $gle = [NativeMethod]::GetLastError();
            $em = ([System.ComponentModel.Win32Exception][int]$gle).Message;
            "Failed to set property with code $gle = $em" | Write-Host;
        } else {
            $ret = $true;
        }
    }
    [Marshal]::FreeHGlobal($rawData);
    [NativeMethod]::SetupDiDestroyDeviceInfoList($deviceSet) | Out-Null;

    return $ret;
}

function UnsetDeviceFilter
{
    param([string]$DeviceInstanceId,
          [string]$Name)

    [string[]]$multiFilter = @();
    [SP_DEVINFO_DATA]$deviceData = New-Object SP_DEVINFO_DATA;
    $deviceSet = [NativeMethod]::SetupDiGetClassDevs(0, "PCI", 0, $DIGCF_ALLCLASSES + $DIGCF_PRESENT);
    $deviceData.cbSize = [Marshal]::SizeOf($deviceData);
    [UInt32]$numChars = 512;
    $removeFromFilter = $false;
    $rawData = [Marshal]::AllocHGlobal(2 * $numChars);
    $ret = $false;
    if (! (LocateDevice $DeviceInstanceId $deviceSet ([ref]$deviceData) $rawData $numChars)) {
        "$DeviceInstanceId is not found in the PCI tree" | Write-Host;
        [Marshal]::FreeHGlobal($rawData);
        [NativeMethod]::SetupDiDestroyDeviceInfoList($deviceSet) | Out-Null;
        return $ret;
    }
    [UInt32]$requestSize = 2 * $numChars;
    if (! [NativeMethod]::SetupDiGetDeviceRegistryProperty($deviceSet,
                                                           [ref]$deviceData,
                                                           $SPDRP_LOWERFILTERS,
                                                           [IntPtr]::Zero,
                                                           $rawData,
                                                           $requestSize,
                                                           [ref]$requestSize))
    {
        "$Name driver was not installed on $DeviceInstanceId" | Write-Host;
    } else {
        $multiFilter = FromIntPtrToMultiString $rawData;
        if ($multiFilter -notcontains $Name) {
            "$Name driver was not installed on $DeviceInstanceId" | Write-Host;
        } else {
            $removeFromFilter = $true;
        }
    }
    if ($removeFromFilter) {
        $multiFilter = $multiFilter | Where-Object { $PSItem -ne $Name };
        if ($multiFilter) {
            [Marshal]::FreeHGlobal($rawData);
            $requestPtr = FromMultiStringToIntPtr $multiFilter;
            $rawData = $requestPtr.Buffer;
            $requestSize = $requestPtr.Size;
            $newId = $rawData;
        } else {
            $newId = [IntPtr]::Zero;
            $requestSize = 0;
        }
        if (! [NativeMethod]::SetupDiSetDeviceRegistryProperty($deviceSet,
                                                               [ref]$deviceData,
                                                               $SPDRP_LOWERFILTERS,
                                                               $newId,
                                                               $requestSize)) {
            $gle = [NativeMethod]::GetLastError();
            $em = ([System.ComponentModel.Win32Exception][int]$gle).Message;
            "Failed to set property with code $gle = $em" | Write-Host;
        } else {
            $ret = $true;
        }
    }
    [Marshal]::FreeHGlobal($rawData);
    [NativeMethod]::SetupDiDestroyDeviceInfoList($deviceSet) | Out-Null;

    return $ret;
}
