#include <wdm.h>

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text (INIT, DriverEntry)

NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING Registry)
{
    UNREFERENCED_PARAMETER(Driver);
    UNREFERENCED_PARAMETER(Registry);

    return STATUS_SUCCESS;
}
