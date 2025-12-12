#include <wdm.h>

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text (INIT, DriverEntry)

/*Linking purposes, not called*/
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING Registry)
{
    UNREFERENCED_PARAMETER(Driver);
    UNREFERENCED_PARAMETER(Registry);

    return STATUS_SUCCESS;
}

NTSTATUS DllInitialize(PUNICODE_STRING Registry)
{
    UNREFERENCED_PARAMETER(Registry);

    return STATUS_SUCCESS;
}

NTSTATUS DllUnload()
{
    return STATUS_SUCCESS;
}
