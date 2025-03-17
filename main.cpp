#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <vector>

using namespace std;

struct MANUAL_MAPPING_DATA
{
    LPVOID pLoadLibraryA;
    LPVOID pGetProcAddress;
    LPVOID pbase;
};

typedef HINSTANCE(*f_LoadLibraryA)(const char* lpLibFilename);
typedef FARPROC(*f_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(void* hDll, DWORD dwReason, void* pReserved);

void __stdcall ShellCode(MANUAL_MAPPING_DATA* pData);

bool ManualMap(HANDLE hProcess, const char* szDllFile)
{
    std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

    if (!File.is_open())
    {
        cout << "No se pudo abrir la DLL" << endl;
        return false;
    }

    std::streampos FileSize = File.tellg();
    BYTE* pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];

    File.seekg(0, std::ios::beg);
    File.read(reinterpret_cast<char*>(pSrcData), FileSize);
    File.close();

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        cout << "Archivo no valido" << endl;
        delete[] pSrcData;
        return false;
    }

    PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pSrcData + pDosHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        cout << "Archivo PE no valido" << endl;
        delete[] pSrcData;
        return false;
    }

    LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, pNTHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase)
    {
        cout << "No se pudo asignar memoria en el proceso objetivo" << endl;
        delete[] pSrcData;
        return false;
    }

    MANUAL_MAPPING_DATA data{ 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
    data.pbase = pTargetBase;

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
                cout << "No se pudo escribir la seccion " << i << endl;
                VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
                delete[] pSrcData;
                return false;
            }
        }
    }

    if (!WriteProcessMemory(hProcess, pTargetBase, pSrcData,
        pNTHeader->OptionalHeader.SizeOfHeaders, nullptr))
    {
        cout << "No se pudieron escribir los PE headers" << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        delete[] pSrcData;
        return false;
    }

    BYTE* pShellcode = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr,
        4096, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!pShellcode)
    {
        cout << "No se pudo asignar memoria para shellcode" << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        delete[] pSrcData;
        return false;
    }

    if (!WriteProcessMemory(hProcess, pShellcode, &data, sizeof(data), nullptr))
    {
        cout << "No se pudieron escribir los datos de mapeo" << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        delete[] pSrcData;
        return false;
    }

    if (!WriteProcessMemory(hProcess, pShellcode + sizeof(data), ShellCode,
        0x1000 - sizeof(data), nullptr))
    {
        cout << "No se pudo escribir el shellcode" << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        delete[] pSrcData;
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode + sizeof(data)),
        pShellcode, 0, nullptr);
    if (!hThread)
    {
        cout << "No se pudo crear el hilo remoto" << endl;
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        delete[] pSrcData;
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    delete[] pSrcData;
    CloseHandle(hThread);

    cout << "DLL mapeada correctamente en dirección: " << pTargetBase << endl;
    return true;
}

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
                WCHAR wideProcessName[MAX_PATH];
                MultiByteToWideChar(CP_ACP, 0, processName, -1, wideProcessName, MAX_PATH);

                if (!wcscmp(processEntry.szExeFile, wideProcessName))
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

void __stdcall ShellCode(MANUAL_MAPPING_DATA* pData)
{
    if (!pData)
        return;

    auto _LoadLibraryA = reinterpret_cast<f_LoadLibraryA>(pData->pLoadLibraryA);
    auto _GetProcAddress = reinterpret_cast<f_GetProcAddress>(pData->pGetProcAddress);
    auto _DllBase = reinterpret_cast<BYTE*>(pData->pbase);

    auto _pOptionalHeader = &reinterpret_cast<PIMAGE_NT_HEADERS>(_DllBase +
        reinterpret_cast<PIMAGE_DOS_HEADER>(_DllBase)->e_lfanew)->OptionalHeader;

    auto _pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(_DllBase +
        _pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (_pImportDescriptor->Name)
    {
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
                        UINT_PTR ordinal = pOriginalThunk->u1.Ordinal & 0xffff;
                        pThunk->u1.Function = reinterpret_cast<UINT_PTR>(_GetProcAddress(hDll,
                            reinterpret_cast<char*>(ordinal)));
                    }
                    else
                    {
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
    }

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

    if (_pOptionalHeader->AddressOfEntryPoint)
    {
        auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(_DllBase + _pOptionalHeader->AddressOfEntryPoint);
        _DllMain(_DllBase, DLL_PROCESS_ATTACH, nullptr);
    }
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        cout << "Uso: ManualMapInjection.exe [target_process] [dll_path]" << endl;
        return 1;
    }

    const char* processName = argv[1];
    const char* dllPath = argv[2];


    DWORD pid = GetProcessId(processName);
    if (!pid)
    {
        cout << "No se pudo encontrar el proceso " << processName << endl;
        return 1;
    }

    cout << "Proceso encontrado. PID: " << pid << endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        cout << "Error: No se pudo abrir el proceso. Código de error: " << GetLastError() << endl;
        return 1;
    }

    if (ManualMap(hProcess, dllPath))
    {
        cout << "Inyeccion completada exitosamente" << endl;
    }
    else
    {
        cout << "La inyección fallo" << endl;
    }

    CloseHandle(hProcess);
    return 0;
}
