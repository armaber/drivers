#include <ntifs.h>
#include <wdm.h>
#include <initguid.h>
#include <ntddstor.h>
#include "shared.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD ReDriverUnload;
/*
    "Re" stands for Review 7B driver.
*/
KBUGCHECK_REASON_CALLBACK_ROUTINE ReTriageCallback;
KBUGCHECK_REASON_CALLBACK_ROUTINE ReDumpCallback;
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, ReDriverUnload)

#define DRIVER_TAG 'DIB7'
/* Allocate a pointer on the NPP to process KbDumpIo reason. */
#define MEMORY_DUMP_SIZE 393216
/* Used when building KBUGCHECK_REASON_CALLBACK_ROUTINE */
#define COMPONENT_NAME "Review7B"
/* Defined in an obscure header file, use it directly here. */
#define EFI_VARIABLE_NON_VOLATILE 0x1
/* Use a NPP buffer to query the ARC name. */
#define ARC_ENUM_SIZE 8192

/* Needed by ZwQueryDirectoryObject. */
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION;

/*
    Global NPP buffer and size, allocated within DriverEntry.
    We want to have everything ready in the KeBugCheck downcall,
    even if INACCESSIBLE_BOOT_DEVICE runs at PASSIVE_LEVEL.
*/
OBJECT_DIRECTORY_INFORMATION *ReArcEnumPtr;
PUCHAR ReMemoryDumpBlock;
ULONG64 ReMemoryDumpSize;
ULONG ReBugCode;
PCHAR ReUefiStorageBlock;
USHORT ReUefiStorageSize;
WCHAR ReLinkSpace[512];
WCHAR ReTargetSpace[512];
KBUGCHECK_REASON_CALLBACK_RECORD ReTriageRecord;
KBUGCHECK_REASON_CALLBACK_RECORD ReDumpRecord;

/* Skip RtlCbPrintfA,W so that \0 is printed, in case the ARC name is corrupt. */
void ReStreamLogW(PWCHAR Message, USHORT Count);
void ReStreamLogA(PCHAR Message, USHORT Count);
void ReStreamLogX4(ULONG Value);
/* 
    Uses an UEFI variable for persistent storage, can be extended to anything. 
    Registry access during KeBugCheck(0x7B) is a nop.
*/
void RePersistentSave(void);

NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING Registry)
{
    BOOLEAN registered;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(Registry);

    ReMemoryDumpSize = 0;
    ReUefiStorageSize = 0;
    Driver->DriverUnload = ReDriverUnload;
    ReBugCode = MAXULONG;
    status = STATUS_INSUFFICIENT_RESOURCES;

    ReMemoryDumpBlock = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, MEMORY_DUMP_SIZE, DRIVER_TAG);
    if (!ReMemoryDumpBlock)
        return status;
    ReUefiStorageBlock = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, UEFI_STORAGE_SIZE, DRIVER_TAG);
    if (!ReUefiStorageBlock)
        goto FreeMemoryDump;
    ReArcEnumPtr = (OBJECT_DIRECTORY_INFORMATION *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                    ARC_ENUM_SIZE, DRIVER_TAG);
    if (!ReArcEnumPtr)
        goto FreeUefiStorage;

    status = STATUS_UNSUCCESSFUL;
    KeInitializeCallbackRecord(&ReTriageRecord);
    registered = KeRegisterBugCheckReasonCallback(&ReTriageRecord,
        &ReTriageCallback, KbCallbackTriageDumpData, (PUCHAR)COMPONENT_NAME);
    if (!registered)
        goto FreeArcTuple;
    KeInitializeCallbackRecord(&ReDumpRecord);
    registered = KeRegisterBugCheckReasonCallback(&ReDumpRecord,
        &ReDumpCallback, KbCallbackDumpIo, (PUCHAR)COMPONENT_NAME);
    if (!registered)
        goto UnregisterTriage;

    return STATUS_SUCCESS;

UnregisterTriage:
    KeDeregisterBugCheckReasonCallback(&ReTriageRecord);
FreeArcTuple:
    ExFreePoolWithTag(ReArcEnumPtr, DRIVER_TAG);
FreeUefiStorage:
    ExFreePoolWithTag(ReUefiStorageBlock, DRIVER_TAG);
FreeMemoryDump:
    ExFreePoolWithTag(ReMemoryDumpBlock, DRIVER_TAG);
    return status;
}

void ReDriverUnload(PDRIVER_OBJECT Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();

    KeDeregisterBugCheckReasonCallback(&ReDumpRecord);
    KeDeregisterBugCheckReasonCallback(&ReTriageRecord);
    ExFreePoolWithTag(ReArcEnumPtr, DRIVER_TAG);
    ExFreePoolWithTag(ReUefiStorageBlock, DRIVER_TAG);
    ExFreePoolWithTag(ReMemoryDumpBlock, DRIVER_TAG);
}

/*
    Print the disk controller DeviceId, for reference. ARC is more relevant.
*/
void ReEnumDisk(void)
{
    NTSTATUS status;
    PZZWSTR linkChain = NULL;
    PWSTR diskIterator;
    USHORT length;

    status = IoGetDeviceInterfaces(&GUID_DEVINTERFACE_DISK, NULL, 0, &linkChain);
    if (!NT_SUCCESS(status) || !linkChain)
        return;

    diskIterator = linkChain;
    while (diskIterator[0]) {
        length = (USHORT)wcslen(diskIterator);
        ReStreamLogW(diskIterator, length);
        diskIterator += length;
        diskIterator ++;
        ReStreamLogA("\n", 1);
    }
    ExFreePool(linkChain);
}

/* Dynamic link to ntoskrnl, deprecated function. */
NTSTATUS NTSYSAPI ZwQueryDirectoryObject(_In_ HANDLE  DirectoryHandle,
                                         _Out_opt_ PVOID Buffer,
                                         _In_ ULONG Length,
                                         _In_ BOOLEAN ReturnSingleEntry,
                                         _In_ BOOLEAN RestartScan,
                                         _Inout_ PULONG Context,
                                         _Out_opt_ PULONG ReturnLength);

/*
    Start from \ArcName root, query each entry to retrieve the target.
*/
void ReEnumArc(void)
{
    NTSTATUS status;
    HANDLE arcRoot;
    HANDLE arcLink;
    UNICODE_STRING arcRootName = RTL_CONSTANT_STRING(L"\\ArcName");
    UNICODE_STRING constLink = RTL_CONSTANT_STRING(L"SymbolicLink");
    UNICODE_STRING arcName;
    UNICODE_STRING arcTarget;
    OBJECT_ATTRIBUTES objAttr;
    OBJECT_DIRECTORY_INFORMATION *iterTuple;
    ULONG context;

    InitializeObjectAttributes(&objAttr, &arcRootName, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenDirectoryObject(&arcRoot, DIRECTORY_TRAVERSE, &objAttr);
    if (!NT_SUCCESS(status))
        return;

    arcName.Buffer = ReLinkSpace;
    RtlCopyMemory(arcName.Buffer, arcRootName.Buffer, arcRootName.Length);
    arcName.Buffer[arcRootName.Length / 2] = L'\\';

    arcTarget.Buffer = ReTargetSpace;
    arcTarget.Length = arcTarget.MaximumLength = sizeof(ReTargetSpace);

    context = 0;
    while (1) {
        status = ZwQueryDirectoryObject(arcRoot, ReArcEnumPtr, ARC_ENUM_SIZE,
                    TRUE, FALSE, &context, NULL);
        if (!NT_SUCCESS(status))
            break;
        for (iterTuple = ReArcEnumPtr;
             iterTuple->Name.Length && iterTuple->TypeName.Length;
             iterTuple ++)
        {
            if (RtlCompareUnicodeString(&iterTuple->TypeName, &constLink, FALSE))
                continue;
            arcName.Length = iterTuple->Name.Length + arcRootName.Length + 2;
            if (arcName.Length > sizeof(ReLinkSpace))
                continue;
            arcName.MaximumLength = arcName.Length;
            RtlCopyMemory(arcName.Buffer + arcRootName.Length / 2 + 1,
                iterTuple->Name.Buffer, iterTuple->Name.Length);

            InitializeObjectAttributes(&objAttr, &arcName, OBJ_KERNEL_HANDLE, NULL, NULL);
            status = ZwOpenSymbolicLinkObject(&arcLink, GENERIC_READ, &objAttr);
            if (!NT_SUCCESS(status))
                continue;

            status = ZwQuerySymbolicLinkObject(arcLink, &arcTarget, NULL);
            ReStreamLogW(arcName.Buffer, arcName.Length / 2);
            if (!NT_SUCCESS(status)) {
                ReStreamLogA(" query error ", sizeof(" query error ") - 1);
                ReStreamLogX4(status);
            }
            else {
                ReStreamLogA(" -> ", sizeof(" -> ") - 1);
                ReStreamLogW(arcTarget.Buffer, arcTarget.Length / 2);
            }
            ReStreamLogA("\n", 1);
            ZwClose(arcLink);
        }
    }
    ZwClose(arcRoot);
}

void ReInterpret7B(UINT_PTR Parameter1,  UINT_PTR Parameter2)
{
    PUNICODE_STRING potential = (PUNICODE_STRING)Parameter1;
    NTSTATUS status = (NTSTATUS)Parameter2;

    /*
        Layout documented at
            https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7b--inaccessible-boot-device#parameters
        In practice, Parameter1 is the ArcBootDeviceName.
    */
    if (potential->Length == 3)
        ReStreamLogA("DeviceObject", sizeof("DeviceObject") - 1);
    else
        ReStreamLogW(potential->Buffer, potential->Length / 2);
    ReStreamLogA(" ", 1);
    ReStreamLogX4(status);
    ReStreamLogA("\n", 1);
}

/*
    Bugcheck code is passed by the OS.
*/
void ReTriageCallback(KBUGCHECK_CALLBACK_REASON Reason,
                      PKBUGCHECK_REASON_CALLBACK_RECORD Record,
                      PVOID Specific,
                      ULONG Length)
{
    PKBUGCHECK_TRIAGE_DUMP_DATA triageData = (PKBUGCHECK_TRIAGE_DUMP_DATA)Specific;
    UNREFERENCED_PARAMETER(Reason);
    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(Length);

    ReBugCode = triageData->BugCheckCode;

    if (ReBugCode == INACCESSIBLE_BOOT_DEVICE) {
        ReInterpret7B(triageData->BugCheckParameter1, triageData->BugCheckParameter2);
        ReEnumDisk();
        ReEnumArc();
        RePersistentSave();
    }
}

void ReDumpCallback(KBUGCHECK_CALLBACK_REASON Reason,
                    PKBUGCHECK_REASON_CALLBACK_RECORD Record,
                    PVOID Specific,
                    ULONG Length)
{
    /*
        Callback depends on crashdmp being loaded:
            BugCheck issued in nt!IopInitializeBootDrivers is a nop
    */
    PKBUGCHECK_DUMP_IO dumpIo = (PKBUGCHECK_DUMP_IO)Specific;
    SIZE_T size;
    UNREFERENCED_PARAMETER(Reason);
    UNREFERENCED_PARAMETER(Record);
    UNREFERENCED_PARAMETER(Length);

    if (dumpIo->Type == KbDumpIoHeader ||
        dumpIo->Type == KbDumpIoBody)
    {
        /*
            KbDumpIoSecondaryData is bypassed. Different strategies can be inferred
            from ReBugCode.
        */
        if (ReMemoryDumpSize < MEMORY_DUMP_SIZE) {
            size = (ReMemoryDumpSize + dumpIo->BufferLength > MEMORY_DUMP_SIZE)?
                MEMORY_DUMP_SIZE - ReMemoryDumpSize: dumpIo->BufferLength;
            RtlCopyMemory(ReMemoryDumpBlock + ReMemoryDumpSize, dumpIo->Buffer, size);
        }
        ReMemoryDumpSize += dumpIo->BufferLength;
    }
}

void _StreamLogW(PCHAR Destination, PUSHORT Size, USHORT Limit, PWCHAR Message, USHORT Count)
{
    USHORT length, i, begin;

    if (Count + *Size > Limit)
        length = Limit - *Size;
    else
        length = Count;
    begin = *Size;
    for (i = 0; i < length; i++) {
        Destination[begin + i] = (CHAR)Message[i];
    }
    *Size += length;
}

void ReStreamLogW(PWCHAR Message, USHORT Count)
{
    _StreamLogW(ReUefiStorageBlock, &ReUefiStorageSize, UEFI_STORAGE_SIZE, Message, Count);
}

void _StreamLogA(PCHAR Destination, PUSHORT Size, USHORT Limit, PCHAR Message, USHORT Count)
{
    USHORT length;

    if (Count + *Size > Limit)
        length = Limit - *Size;
    else
        length = Count;
    RtlCopyMemory(Destination + *Size, Message, length);
    *Size += length;
}

void ReStreamLogA(PCHAR Message, USHORT Count)
{
    _StreamLogA(ReUefiStorageBlock, &ReUefiStorageSize, UEFI_STORAGE_SIZE, Message, Count);
}

void ReStreamLogX4(ULONG Value)
{
    UCHAR hex, i;

    for (i = 0; i < 8; i++) {
        hex = (Value >> ((7 - i) * 4)) & 0xF;
        if (hex >= 0xA)
            hex += 'A' - 0xA;
        else
            hex += '0';
        if (ReUefiStorageSize < UEFI_STORAGE_SIZE)
            ReUefiStorageBlock[ReUefiStorageSize ++] = hex;
    }
}

/*
    At the time of the crash, WindowsTrustedRT driver is loaded. EFI is available.
*/
void RePersistentSave(void)
{
    NTSTATUS status;
    UNICODE_STRING review7B = RTL_CONSTANT_STRING(UEFI_STORAGE_NAME);

    status = ExSetFirmwareEnvironmentVariable(&review7B, (LPGUID)&Review7B_Guid,
        ReUefiStorageBlock, ReUefiStorageSize, EFI_VARIABLE_NON_VOLATILE);
}
