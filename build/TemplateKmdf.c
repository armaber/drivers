#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EvtDriverDeviceAdd;

#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, EvtDriverDeviceAdd)

NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING Registry)
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    WDF_DRIVER_CONFIG_INIT(&config, EvtDriverDeviceAdd);

    status = WdfDriverCreate(Driver, Registry, NULL, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS EvtDriverDeviceAdd(WDFDRIVER Driver, PWDFDEVICE_INIT Init)
{
    UNREFERENCED_PARAMETER(Driver);
    UNREFERENCED_PARAMETER(Init);

    return STATUS_SUCCESS;
}
