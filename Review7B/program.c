#include <windows.h>
#include <stdio.h>
#include <initguid.h>
#include "shared.h"

PWSTR BUGCHECK_EFI_GUID = L"{BA57E015-65B3-4C3C-B274-659192F699E3}";

BOOL SetPrivilege(PWSTR Name)
{
    TOKEN_PRIVILEGES privilege;
    HANDLE token;
    LUID luid;
    BOOL ret = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        printf("OpenProcessToken failed with %u\n", GetLastError());
        return ret;
    }
    if (!LookupPrivilegeValue(NULL, Name, &luid)) {
        printf("LookupPrivilegeValue failed with %u\n", GetLastError());
        goto Close;
    }

    privilege.PrivilegeCount = 1;
    privilege.Privileges[0].Luid = luid;
    privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &privilege, 0, NULL, NULL)) {
        printf("AdjustTokenPrivileges failed with %u\n", GetLastError());
        goto Close;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege.\n");
        goto Close;
    }

    ret = TRUE;

Close:
    CloseHandle(token);
    return ret;
}

void PrintVariable(PWSTR Name, PWSTR Guid, PUCHAR Buffer, DWORD Size)
{
    DWORD length, i, lastErr;

    if (length = GetFirmwareEnvironmentVariable(Name, Guid, Buffer, Size)) {
        printf("%S: ", Name);
        for (i = 0; i < length; i++) {
            printf("%02X ", Buffer[i]);
        }
        printf("\n");
    }
    else {
        lastErr = GetLastError();
        if (lastErr == ERROR_ENVVAR_NOT_FOUND)
            printf("%S is not present\n", Name);
        else
            printf("GetFirmwareEnvironmentVariable %S failed with %u\n", Name, lastErr);
    }
}


int wmain(int argc, wchar_t *argv[])
{
    RPC_WSTR REVIEW7B_EFI_GUID;
    PWSTR variables[] = {
        L"BugCheckProgress",
        L"BugCheckCode",
        L"BugCheckParameter1",
        L"BugCheckParameter2",
        L"BugCheckParameter3",
        L"BugCheckParameter4"
    };
    PUCHAR buffer;
    int rc = -1, i;

    if (RPC_S_OK != UuidToString(&Review7B_Guid, &REVIEW7B_EFI_GUID))
        return -1;

    if (!SetPrivilege(L"SeSystemEnvironmentPrivilege"))
        goto FreeUuid;

    if (argc == 2 && !wcscmp(L"/remove", argv[1])) {
        SetFirmwareEnvironmentVariable(L"Review7B", REVIEW7B_EFI_GUID, NULL, 0);
        goto FreeUuid;
    }

    buffer = (PUCHAR)malloc(UEFI_STORAGE_SIZE);
    if (!buffer)
        goto FreeUuid;

    for (i = 0; i < ARRAYSIZE(variables); i ++)
        PrintVariable(variables[i], BUGCHECK_EFI_GUID, buffer, UEFI_STORAGE_SIZE);

    PrintVariable(L"Review7B", REVIEW7B_EFI_GUID, buffer, UEFI_STORAGE_SIZE);
    rc = 0;

    free(buffer);
FreeUuid:
    RpcStringFree(&REVIEW7B_EFI_GUID);
    return rc;
}
