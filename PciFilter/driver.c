#define NT_PROCESSOR_GROUPS
#include <ntstatus.h>
#include <ntstrsafe.h>
#include <ntifs.h>
#include <wdm.h>
#include <acpiioct.h>
#include "definitions.h"

#define DRIVER_TAG 'PBCI'
#define DbgOutput(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, __VA_ARGS__)
#define CUSTOM_FROM_CTL_CODE(x) (!!(x & (1 << 13)))

typedef struct _FILTER_CONTEXT {
    PDEVICE_OBJECT NextLowerDevice;
    PDEVICE_OBJECT PhysicalDevice;
    IO_REMOVE_LOCK RemoveLock;
    PWCHAR TraceLocation;
} FILTER_CONTEXT;

#pragma pack(push, 1)
typedef struct _STACK_HASH_TRACE {
    LIST_ENTRY Pivot;
    ULONG Hash;
} STACK_HASH_TRACE;
#pragma pack(pop)

DRIVER_INITIALIZE DriverEntry;
DRIVER_ADD_DEVICE FiDeviceAdd;
DRIVER_UNLOAD FiDriverUnload;
DRIVER_DISPATCH FiDispatchRoutine;
IO_COMPLETION_ROUTINE StartDeviceCompletion;
IO_COMPLETION_ROUTINE QueryRequirementsCompletion;
IO_COMPLETION_ROUTINE FilterRequirementsCompletion;

KEVENT FiSerialStackOutput;
LIST_ENTRY FiStackHashList;

#pragma alloc_text(PAGE, DriverEntry)
#pragma alloc_text(PAGE, FiDeviceAdd)
#pragma alloc_text(PAGE, FiDriverUnload)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    ULONG i;
    UNREFERENCED_PARAMETER(RegistryPath);

    PAGED_CODE();

    KeInitializeEvent(&FiSerialStackOutput, SynchronizationEvent, TRUE);
    InitializeListHead(&FiStackHashList);
#pragma warning(disable: 28168)
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = &FiDispatchRoutine;
    }
#pragma warning(default: 28168)
    DriverObject->DriverExtension->AddDevice = &FiDeviceAdd;
    DriverObject->DriverUnload = &FiDriverUnload;

    return STATUS_SUCCESS;
}

void FiDriverUnload(PDRIVER_OBJECT DriverObject)
{
    PLIST_ENTRY iter;
    STACK_HASH_TRACE *entryHash;
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();
    while (!IsListEmpty(&FiStackHashList)) {
        iter = RemoveHeadList(&FiStackHashList);
        entryHash = CONTAINING_RECORD(iter, STACK_HASH_TRACE, Pivot);
        ExFreePoolWithTag(entryHash, DRIVER_TAG);
    }
}

DEVICE_TYPE GetDeviceType(PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDEVICE_OBJECT highestDO;
    DEVICE_TYPE type;

    highestDO = IoGetAttachedDeviceReference(PhysicalDeviceObject);
#pragma warning(disable: 28175)
    type = highestDO->Type;
#pragma warning(default: 28175)
    ObDereferenceObject(highestDO);

    return type;
}

NTSTATUS FiDeviceAdd(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject)
{
    NTSTATUS status;
    PDEVICE_OBJECT newDevice;
    ULONG lowerFlags, segment, bus, devfn, size, hidPrefix;
    DEVICE_TYPE highestType;
    FILTER_CONTEXT *filter;

    PAGED_CODE();

    highestType = GetDeviceType(PhysicalDeviceObject);
    status = IoCreateDevice(DriverObject, sizeof(FILTER_CONTEXT), NULL, highestType, FILE_DEVICE_SECURE_OPEN, FALSE, &newDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    filter = (FILTER_CONTEXT *)newDevice->DeviceExtension;
    filter->NextLowerDevice = IoAttachDeviceToDeviceStack(newDevice, PhysicalDeviceObject);
    if (!filter->NextLowerDevice) {
        IoDeleteDevice(newDevice);
        return STATUS_UNSUCCESSFUL;
    }
    status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyBusNumber, sizeof(bus), &bus, &size);
    if (!NT_SUCCESS(status)) {
        bus = 0xFFFFFFFF;
    }
    status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyAddress, sizeof(devfn), &devfn, &size);
    if (!NT_SUCCESS(status)) {
        devfn = 0xFFFFFFFF;
    }
    segment = 0;
    if (bus != 0xFFFFFFFF) {
        segment = (bus >> 8) & 0xFFFF;
    }
    bus &= 0xFF;
    status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyHardwareID, 0, NULL, &size);
    if (status == STATUS_BUFFER_TOO_SMALL) {
        if (segment) {
            hidPrefix = sizeof(HARDWAREID_PREFIX_WITH_SEGMENT);
        }
        else {
            hidPrefix = sizeof(HARDWAREID_PREFIX_WO_SEGMENT);
        }
        size += hidPrefix;
        filter->TraceLocation = (PWCHAR)ExAllocatePoolUninitialized(NonPagedPoolNx, size, DRIVER_TAG);
        if (!filter->TraceLocation) {
            IoDetachDevice(filter->NextLowerDevice);
            IoDeleteDevice(newDevice);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
#pragma warning(disable: 6386)
        if (segment) {
            RtlStringCbPrintfW(filter->TraceLocation, hidPrefix, HARDWAREID_FORMAT_WITH_SEGMENT,
                               PhysicalDeviceObject, segment, bus, (devfn >> 16) & 0x1F, devfn & 0x7);
        }
        else {
            RtlStringCbPrintfW(filter->TraceLocation, hidPrefix, HARDWAREID_FORMAT_WO_SEGMENT,
                               PhysicalDeviceObject, bus, (devfn >> 16) & 0x1F, devfn & 0x7);
        }
#pragma warning(default: 6386)
        hidPrefix -= sizeof(L'\0');
        IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyHardwareID, size - hidPrefix,
            filter->TraceLocation + hidPrefix / 2, &size);
    }
    IoInitializeRemoveLock(&filter->RemoveLock, DRIVER_TAG, 0, 0);
    filter->PhysicalDevice = PhysicalDeviceObject;
    lowerFlags = DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE | DO_POWER_INRUSH;
    newDevice->Flags = filter->NextLowerDevice->Flags & lowerFlags;
    newDevice->DeviceType = filter->NextLowerDevice->DeviceType;
    newDevice->Characteristics = filter->NextLowerDevice->Characteristics;
    newDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    
    return status;
}

void FiPrintCmDesc(PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    USHORT flags;
    PCHAR flagsString;
    UCHAR share;
    PCHAR shareString, prefetchString;

    switch (CmDescriptor->Type)
    {
    case CmResourceTypeMemory:
        share = CmDescriptor->ShareDisposition;
        shareString = (share == CmResourceShareDeviceExclusive)? "exclusive":
            (share == CmResourceShareDriverExclusive)? "driver exclusive":
            "shared";
        flags = CmDescriptor->Flags;
        flagsString = (flags & CM_RESOURCE_MEMORY_READ_ONLY)? "RO":
                      (flags & CM_RESOURCE_MEMORY_WRITE_ONLY)? "WO":
                      "RW";
        prefetchString = (flags & CM_RESOURCE_MEMORY_PREFETCHABLE)? "prefetchable":
                         "non-prefetchable";
        DbgOutput("Memory descriptor %s %s %s 0x%I64X length 0x%08X\n",
                   shareString, flagsString, prefetchString,
                   CmDescriptor->u.Memory.Start.QuadPart, CmDescriptor->u.Memory.Length);
        break;
    case CmResourceTypeInterrupt:
        flags = CmDescriptor->Flags;
        flagsString = (flags == CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE)? "level sensitive":
                      (flags & CM_RESOURCE_INTERRUPT_LATCHED)? "latched":
                      (flags & CM_RESOURCE_INTERRUPT_MESSAGE)? "message":
                      (flags & CM_RESOURCE_INTERRUPT_POLICY_INCLUDED)? "policy":
                      (flags & CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT)? "secondary":
                      "wake hint";
        if (flags & CM_RESOURCE_INTERRUPT_MESSAGE) {
            DbgOutput("Interrupt descriptor %s, Raw [group %u, count %u, vector 0x%X, affinity 0x%zX], "
                       "Translated [level %u, group %u, vector 0x%X, affinity 0x%zX]\n",
                       flagsString, CmDescriptor->u.MessageInterrupt.Raw.Group,
                       CmDescriptor->u.MessageInterrupt.Raw.MessageCount, 
                       CmDescriptor->u.MessageInterrupt.Raw.Vector, 
                       CmDescriptor->u.MessageInterrupt.Raw.Affinity, 
                       CmDescriptor->u.MessageInterrupt.Translated.Level, 
                       CmDescriptor->u.MessageInterrupt.Translated.Group, 
                       CmDescriptor->u.MessageInterrupt.Translated.Vector, 
                       CmDescriptor->u.MessageInterrupt.Translated.Affinity);
        }
        else {
            DbgOutput("Interrupt descriptor %s 0x%X\n", flagsString, CmDescriptor->u.Interrupt.Vector);
        }
        break;
    case CmResourceTypeBusNumber:
        DbgOutput("Bus descriptor start 0x%02X length 0x%02X\n", CmDescriptor->u.BusNumber.Start, CmDescriptor->u.BusNumber.Length);
        break;
    default:
        DbgOutput("%u %08X descriptor\n", CmDescriptor->Type, CmDescriptor->Flags);

    }
}

void FiPrintIoDesc(PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    USHORT flags;
    PCHAR flagsString;
    IRQ_DEVICE_POLICY affinityPolicy;
    PCHAR affinityPolicyString;
    IRQ_PRIORITY priorityPolicy;
    PCHAR priorityPolicyString;
    UCHAR share;
    PCHAR shareString, prefetchString;

    switch (IoDescriptor->Type) {
    case CmResourceTypeMemory:
        share = IoDescriptor->ShareDisposition;
        shareString = (share == CmResourceShareDeviceExclusive)? "exclusive":
                      (share == CmResourceShareDriverExclusive)? "driver exclusive":
                      "shared";
        flags = IoDescriptor->Flags;
        flagsString = (flags & CM_RESOURCE_MEMORY_READ_ONLY)? "RO":
                      (flags & CM_RESOURCE_MEMORY_WRITE_ONLY)? "WO":
                      "RW";
        prefetchString = (flags & CM_RESOURCE_MEMORY_PREFETCHABLE)? "prefetchable":
                         "non-prefetchable";
        DbgOutput("Memory descriptor %s %s %s lower 0x%I64X upper 0x%I64X length 0x%08X alignment 0x%08X\n",
                   shareString, flagsString, prefetchString, IoDescriptor->u.Memory.MinimumAddress.QuadPart,
                   IoDescriptor->u.Memory.MaximumAddress.QuadPart, IoDescriptor->u.Memory.Length,
                   IoDescriptor->u.Memory.Alignment);
        break;
    case CmResourceTypeBusNumber:
        DbgOutput("Bus number lower 0x%02X upper 0x%02X length 0x%02X\n",
                  IoDescriptor->u.BusNumber.MinBusNumber, IoDescriptor->u.BusNumber.MaxBusNumber,
                  IoDescriptor->u.BusNumber.Length);
        break;
    case CmResourceTypeInterrupt:
        flags = IoDescriptor->Flags;
        flagsString = (flags == CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE)? "level sensitive":
                      (flags & CM_RESOURCE_INTERRUPT_LATCHED)? "latched":
                      (flags & CM_RESOURCE_INTERRUPT_MESSAGE)? "message":
                      (flags & CM_RESOURCE_INTERRUPT_POLICY_INCLUDED)? "policy":
                      (flags & CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT)? "secondary":
                      "wake hint";
        affinityPolicy = IoDescriptor->u.Interrupt.AffinityPolicy;
        affinityPolicyString = (affinityPolicy == IrqPolicyMachineDefault)? "machine default":
                               (affinityPolicy == IrqPolicyAllCloseProcessors)? "all close processors":
                               (affinityPolicy == IrqPolicyOneCloseProcessor)? "one close processor":
                               (affinityPolicy == IrqPolicyAllProcessorsInMachine)? "all processors":
                               (affinityPolicy == IrqPolicyAllProcessorsInGroup)? "all processors in group":
                               (affinityPolicy == IrqPolicySpecifiedProcessors)? "specified processors":
                               (affinityPolicy == IrqPolicySpreadMessagesAcrossAllProcessors)? "spread across all processors":
                               (affinityPolicy == IrqPolicyAllProcessorsInMachineWhenSteered)? "all processors when steered":
                               "all processors in group when steered";
        priorityPolicy = IoDescriptor->u.Interrupt.PriorityPolicy;
        priorityPolicyString = (priorityPolicy == IrqPriorityUndefined)? "undefined":
                               (priorityPolicy == IrqPriorityLow)? "low":
                               (priorityPolicy == IrqPriorityNormal)? "normal":
                               "high";
        DbgOutput("Interrupt descriptor %s, policy %s, group %u, priority %s, processors 0x%zX, 0x%X\n",
                   flagsString, affinityPolicyString, IoDescriptor->u.Interrupt.Group, priorityPolicyString,
                   IoDescriptor->u.Interrupt.TargetedProcessors, IoDescriptor->u.Interrupt.MinimumVector);
        break;
    default:
        DbgOutput("%u %08X descriptor\n", IoDescriptor->Type, IoDescriptor->Flags);
    }
}

NTSTATUS StartDeviceCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Arg)
{
    FILTER_CONTEXT *filter = (FILTER_CONTEXT *)Arg;
    
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
#pragma warning(disable: 28182)
    if (filter->NextLowerDevice->Characteristics & FILE_REMOVABLE_MEDIA) {
        DeviceObject->Characteristics |= FILE_REMOVABLE_MEDIA;
    }
    IoReleaseRemoveLock(&filter->RemoveLock, Irp);
#pragma warning(default: 28182)

    return STATUS_SUCCESS;
}

NTSTATUS QueryRequirementsCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Arg)
{
    FILTER_CONTEXT *filter = (FILTER_CONTEXT *)Arg;
    PIO_RESOURCE_REQUIREMENTS_LIST upList;
    PIO_RESOURCE_LIST ioList;
    ULONG listIndex, descIndex;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
    upList = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
    if (upList) {
        DbgOutput("Query requirements UP\n");
        for (listIndex = 0; listIndex < upList->AlternativeLists; listIndex++) {
            ioList = &upList->List[listIndex];
            DbgOutput("IO_RESOURCE_LIST[%u]\n", listIndex);
            for (descIndex = 0; descIndex < ioList->Count; descIndex++) {
                FiPrintIoDesc(&ioList->Descriptors[descIndex]);
            }
        }
    }
    else {
        DbgOutput("No resource requirements UP.\n");
    }
#pragma warning(disable: 28182)
    IoReleaseRemoveLock(&filter->RemoveLock, Irp);
#pragma warning(default: 28182)

    return STATUS_SUCCESS;
}

NTSTATUS FilterRequirementsCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Arg)
{
    FILTER_CONTEXT *filter = (FILTER_CONTEXT *)Arg;
    PIO_RESOURCE_REQUIREMENTS_LIST upList;
    PIO_RESOURCE_LIST ioList;
    ULONG listIndex, descIndex;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
    upList = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
    if (upList) {
        DbgOutput("Filter requirements UP\n");
        for (listIndex = 0; listIndex < upList->AlternativeLists; listIndex++) {
            ioList = &upList->List[listIndex];
            DbgOutput("IO_RESOURCE_LIST[%u]\n", listIndex);
            for (descIndex = 0; descIndex < ioList->Count; descIndex++) {
                FiPrintIoDesc(&ioList->Descriptors[descIndex]);
            }
        }
    }
    else {
        DbgOutput("No resource requirements UP.\n");
    }
#pragma warning(disable: 28182)
    IoReleaseRemoveLock(&filter->RemoveLock, Irp);
#pragma warning(default: 28182)

    return STATUS_SUCCESS;
}

const char* FiConvertMn(UCHAR MajorCode, UCHAR MinorCode)
{

    if (MajorCode != IRP_MJ_PNP && MajorCode != IRP_MJ_POWER) {
        return "NotIdentified";
    }

    switch (MajorCode) {
    case IRP_MJ_PNP:
        switch (MinorCode)
        {
        case IRP_MN_START_DEVICE:
            return "START_DEVICE";
        case IRP_MN_QUERY_REMOVE_DEVICE:
            return "QUERY_REMOVE_DEVICE";
        case IRP_MN_REMOVE_DEVICE:
            return "REMOVE_DEVICE";
        case IRP_MN_CANCEL_REMOVE_DEVICE:
            return "CANCEL_REMOVE_DEVICE";
        case IRP_MN_STOP_DEVICE:
            return "STOP_DEVICE";
        case IRP_MN_QUERY_STOP_DEVICE:
            return "QUERY_STOP_DEVICE";
        case IRP_MN_CANCEL_STOP_DEVICE:
            return "CANCEL_STOP_DEVICE";
        case IRP_MN_QUERY_DEVICE_RELATIONS:
            return "QUERY_DEVICE_RELATIONS";
        case IRP_MN_QUERY_INTERFACE:
            return "QUERY_INTERFACE";
        case IRP_MN_QUERY_CAPABILITIES:
            return "QUERY_CAPABILITIES";
        case IRP_MN_QUERY_RESOURCES:
            return "QUERY_RESOURCES";
        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            return "QUERY_RESOURCE_REQUIREMENTS";
        case IRP_MN_QUERY_DEVICE_TEXT:
            return "QUERY_DEVICE_TEXT";
        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
            return "FILTER_RESOURCE_REQUIREMENTS";
        case IRP_MN_READ_CONFIG:
            return "READ_CONFIG";
        case IRP_MN_WRITE_CONFIG:
            return "WRITE_CONFIG";
        case IRP_MN_EJECT:
            return "EJECT";
        case IRP_MN_SET_LOCK:
            return "SET_LOCK";
        case IRP_MN_QUERY_ID:
            return "QUERY_ID";
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            return "QUERY_PNP_DEVICE_STATE";
        case IRP_MN_QUERY_BUS_INFORMATION:
            return "QUERY_BUS_INFORMATION";
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            return "DEVICE_USAGE_NOTIFICATION";
        case IRP_MN_SURPRISE_REMOVAL:
            return "SURPRISE_REMOVAL";
        case IRP_MN_DEVICE_ENUMERATED:
            return "DEVICE_ENUMERATED";
        }
        break;
    case IRP_MJ_POWER:
        switch (MinorCode)
        {
        case IRP_MN_WAIT_WAKE:
            return "WAIT_WAKE";
        case IRP_MN_POWER_SEQUENCE:
            return "POWER_SEQUENCE";
        case IRP_MN_SET_POWER:
            return "SET_POWER";
        case IRP_MN_QUERY_POWER:
            return "QUERY_POWER";
        }
        break;
    }

    return "NotIdentified";
}

void FiPrintProlog(UCHAR MajorFunction, UCHAR MinorFunction, FILTER_CONTEXT *Filter)
{
    switch (MajorFunction) {
    case IRP_MJ_POWER:
        DbgOutput("Call [MJ_POWER, %s] on %S\n",
                  FiConvertMn(IRP_MJ_POWER, MinorFunction), Filter->TraceLocation);
        break;
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        DbgOutput("Call MJ_INTERNAL_DEVICE_CONTROL on %S\n", Filter->TraceLocation);
        break;
    case IRP_MJ_DEVICE_CONTROL:
        DbgOutput("Call MJ_DEVICE_CONTROL on %S\n", Filter->TraceLocation);
        break;
    case IRP_MJ_PNP:
        if (MinorFunction == IRP_MN_QUERY_RESOURCES ||
            MinorFunction == IRP_MN_QUERY_RESOURCE_REQUIREMENTS ||
            MinorFunction == IRP_MN_FILTER_RESOURCE_REQUIREMENTS ||
            MinorFunction == IRP_MN_START_DEVICE ||
            MinorFunction == IRP_MN_STOP_DEVICE ||
            MinorFunction == IRP_MN_SURPRISE_REMOVAL ||
            MinorFunction == IRP_MN_REMOVE_DEVICE)
        {
            DbgOutput("Call [MJ_PNP, %s] on %S\n",
                      FiConvertMn(IRP_MJ_PNP, MinorFunction), Filter->TraceLocation);
        }
        break;
    }
}

BOOLEAN FiDecodeAcpiMethod(FILTER_CONTEXT *Filter, ULONG Code, PVOID Buffer, ULONG Length)
{
    CHAR shortMethod[5], *plog;
    ULONG expectedLength, methodLength;
    PACPI_EVAL_INPUT_BUFFER acpiInput;
    PACPI_EVAL_INPUT_BUFFER_EX acpiInputEx;
    PACPI_EVAL_INPUT_BUFFER_V2 acpiInputV2;
    PACPI_EVAL_INPUT_BUFFER_V2_EX acpiInputV2Ex;
    BOOLEAN recognized = TRUE;

    switch (Code) {
    case IOCTL_ACPI_EVAL_METHOD:
    case IOCTL_ACPI_ASYNC_EVAL_METHOD:
        expectedLength = sizeof(ACPI_EVAL_INPUT_BUFFER);
        methodLength = FIELD_SIZE(ACPI_EVAL_INPUT_BUFFER, MethodName);
        acpiInput = (PACPI_EVAL_INPUT_BUFFER)Buffer;
        plog = (CHAR *)&acpiInput->MethodName;
        break;
    case IOCTL_ACPI_EVAL_METHOD_EX:
    case IOCTL_ACPI_ASYNC_EVAL_METHOD_EX:
        expectedLength = sizeof(ACPI_EVAL_INPUT_BUFFER_EX);
        methodLength = FIELD_SIZE(ACPI_EVAL_INPUT_BUFFER_EX, MethodName);
        acpiInputEx = (PACPI_EVAL_INPUT_BUFFER_EX)Buffer;
        plog = (CHAR *)&acpiInputEx->MethodName;
        break;
    case IOCTL_ACPI_GET_DEVICE_SPECIFIC_DATA:
        expectedLength = 4;
        methodLength = 0;
        plog = "IOCTL_ACPI_GET_DEVICE_SPECIFIC_DATA";
        break;
    case IOCTL_ACPI_EVAL_METHOD_V2:
    case IOCTL_ACPI_ASYNC_EVAL_METHOD_V2:
        expectedLength = sizeof(ACPI_EVAL_INPUT_BUFFER_V2);
        methodLength = FIELD_SIZE(ACPI_EVAL_INPUT_BUFFER_V2, MethodName);
        acpiInputV2 = (PACPI_EVAL_INPUT_BUFFER_V2)Buffer;
        plog = (CHAR *)&acpiInputV2->MethodName;
        break;
    case IOCTL_ACPI_EVAL_METHOD_V2_EX:
    case IOCTL_ACPI_ASYNC_EVAL_METHOD_V2_EX:
        expectedLength = sizeof(ACPI_EVAL_INPUT_BUFFER_V2_EX);
        methodLength = FIELD_SIZE(ACPI_EVAL_INPUT_BUFFER_V2_EX, MethodName);
        acpiInputV2Ex = (PACPI_EVAL_INPUT_BUFFER_V2_EX)Buffer;
        plog = (CHAR *)&acpiInputV2Ex->MethodName;
        break;
    default:
        recognized = FALSE;
        return recognized;
    }
    if (Length < expectedLength) {
        return recognized;
    }
    if (methodLength == 4) {
        RtlCopyMemory(shortMethod, plog, methodLength);
        shortMethod[4] = '\0';
        plog = shortMethod;
    }
    DbgOutput("ACPI method %s on %S\n", plog, Filter->TraceLocation);
    return recognized;
}

PCHAR IdentifyIoctl(ULONG Code)
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(DetectedIoctl); i ++) {
        if (DetectedIoctl[i].Code == Code) {
            return DetectedIoctl[i].CodeAsString;
        }
    }
    return NULL;
}

void FiPrintCode(FILTER_CONTEXT *Filter, ULONG Code)
{
    PCHAR strCode = IdentifyIoctl(Code);
    PVOID stackFrame[STACK_CAPTURE];
    ULONG computedHash = 0;
    USHORT numFrames;
    PLIST_ENTRY iter;
    STACK_HASH_TRACE *newHash, *entryHash;
    BOOLEAN firstLine = TRUE;

    if (strCode) {
        DbgOutput("Code %s on %S\n", strCode, Filter->TraceLocation);
    }
    else {
        if (CUSTOM_FROM_CTL_CODE(Code)) {
            DbgOutput("Code 0x%X on %S\n", Code, Filter->TraceLocation);
        }
        else {
            KeWaitForSingleObject(&FiSerialStackOutput, Executive, KernelMode, FALSE, NULL);
            DbgOutput("Code 0x%X undocumented on %S\n", Code, Filter->TraceLocation);
            numFrames = RtlCaptureStackBackTrace(2, ARRAYSIZE(stackFrame), stackFrame, &computedHash);
            for (iter = FiStackHashList.Flink; iter != &FiStackHashList; iter = iter->Flink)
            {
                entryHash = CONTAINING_RECORD(iter, STACK_HASH_TRACE, Pivot);
                if (computedHash == entryHash->Hash) {
                    DbgOutput("      Encountered as hash 0x%X\n", computedHash);
                    break;
                }
            }
            if (iter == &FiStackHashList) {
                while (numFrames-- > 0) {
                    if (firstLine) {
                        DbgOutput("Stack 0x%p\n", stackFrame[numFrames]);
                        firstLine = FALSE;
                    } else {
                        DbgOutput("      0x%p\n", stackFrame[numFrames]);
                    }
                }
                newHash = ExAllocatePoolUninitialized(PagedPool | POOL_NX_ALLOCATION, sizeof(*newHash), DRIVER_TAG);
                if (newHash) {
                    InsertHeadList(&FiStackHashList, &newHash->Pivot);
                    DbgOutput("Stack hash 0x%X\n", computedHash);
                    newHash->Hash = computedHash;
                }
            }
            KeSetEvent(&FiSerialStackOutput, 0, FALSE);
        }
    }
}

NTSTATUS FiDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    FILTER_CONTEXT *filter = (FILTER_CONTEXT *)DeviceObject->DeviceExtension;
    PCM_RESOURCE_LIST allocatedRaw, allocatedTranslated;
    PIO_RESOURCE_LIST ioList;
    PCM_PARTIAL_RESOURCE_LIST partialList;
    PIO_RESOURCE_REQUIREMENTS_LIST downList;
    ULONG listIndex, descIndex, internalCode, bufferLength;
    NTSTATUS status;
    BOOLEAN devobjRemoved = FALSE;
    DEVICE_RELATION_TYPE relationType;
    PCHAR relationString;
    PVOID buffer;
    BOOLEAN isAcpi;

    status = IoAcquireRemoveLock(&filter->RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
    FiPrintProlog(ioStack->MajorFunction, ioStack->MinorFunction, filter);
    if (ioStack->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL ||
        ioStack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        internalCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
        buffer = Irp->AssociatedIrp.SystemBuffer;
        bufferLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
        isAcpi = FiDecodeAcpiMethod(filter, internalCode, buffer, bufferLength);
        if (!isAcpi) {
            FiPrintCode(filter, internalCode);
        }
    }
    if (ioStack->MajorFunction == IRP_MJ_PNP) {
        if (ioStack->MinorFunction == IRP_MN_REMOVE_DEVICE ||
            ioStack->MinorFunction == IRP_MN_STOP_DEVICE)
        {
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        if (ioStack->MinorFunction == IRP_MN_REMOVE_DEVICE) {
            devobjRemoved = TRUE;
        }
        if (ioStack->MinorFunction == IRP_MN_START_DEVICE)
        {
            allocatedRaw = ioStack->Parameters.StartDevice.AllocatedResources;
            allocatedTranslated = ioStack->Parameters.StartDevice.AllocatedResourcesTranslated;
            if (allocatedRaw) {
                DbgOutput("CM_RESOURCE_LIST Raw\n");
                partialList = &allocatedRaw->List[0].PartialResourceList;
                for (descIndex = 0; descIndex < partialList->Count; descIndex++) {
                    FiPrintCmDesc(&partialList->PartialDescriptors[descIndex]);
                }
            }
            if (allocatedTranslated) {
                DbgOutput("CM_RESOURCE_LIST Translated\n");
                partialList = &allocatedTranslated->List[0].PartialResourceList;
                for (descIndex = 0; descIndex < partialList->Count; descIndex++) {
                    FiPrintCmDesc(&partialList->PartialDescriptors[descIndex]);
                }
            }
            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, StartDeviceCompletion, filter, TRUE, TRUE, TRUE);
            status = IoCallDriver(filter->NextLowerDevice, Irp);
            return status;
        }
        else if (ioStack->MinorFunction == IRP_MN_QUERY_RESOURCE_REQUIREMENTS) {
            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, QueryRequirementsCompletion, filter, TRUE, TRUE, TRUE);
            status = IoCallDriver(filter->NextLowerDevice, Irp);
            return status;
        }
        else if (ioStack->MinorFunction == IRP_MN_FILTER_RESOURCE_REQUIREMENTS) {
            downList = ioStack->Parameters.FilterResourceRequirements.IoResourceRequirementList;
            if (downList) {
                for (listIndex = 0; listIndex < downList->AlternativeLists; listIndex++) {
                    ioList = &downList->List[listIndex];
                    DbgOutput("IO_RESOURCE_LIST[%u]\n", listIndex);
                    for (descIndex = 0; descIndex < ioList->Count; descIndex++) {
                        FiPrintIoDesc(&ioList->Descriptors[descIndex]);
                    }
                }
            }
            else {
                DbgOutput("No resource requirements DOWN.\n");
            }
            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, FilterRequirementsCompletion, filter, TRUE, TRUE, TRUE);
            status = IoCallDriver(filter->NextLowerDevice, Irp);
            return status;
        }
        else if (ioStack->MinorFunction == IRP_MN_QUERY_DEVICE_RELATIONS) {
            relationType = ioStack->Parameters.QueryDeviceRelations.Type;
            relationString = (relationType == BusRelations)? "BusRelations":
                             (relationType == EjectionRelations)? "EjectionRelations":
                             (relationType == RemovalRelations)? "RemovalRelations":
                             (relationType == TargetDeviceRelation)? "TargetDeviceRelation":
                             (relationType == PowerRelations)? "PowerRelations":
                             "UnknownRelation";
            DbgOutput("Call [MJ_PNP, %s] on %S for %s\n",
                      FiConvertMn(IRP_MJ_PNP, ioStack->MinorFunction), filter->TraceLocation, relationString);
        }
    }
    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(filter->NextLowerDevice, Irp);
    if (devobjRemoved) {
        IoReleaseRemoveLockAndWait(&filter->RemoveLock, Irp);
        ExFreePoolWithTag(filter->TraceLocation, DRIVER_TAG);
        IoDetachDevice(filter->NextLowerDevice);
        IoDeleteDevice(DeviceObject);
    }
    else {
        IoReleaseRemoveLock(&filter->RemoveLock, Irp);
    }

    return status;
}
