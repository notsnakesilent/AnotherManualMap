# Manual Mapping: Inyección de DLLs en detalle

## 1. Estructura de archivos PE y encabezados

Los archivos PE (Portable Executable) son el formato estándar para archivos ejecutables en Windows. Tienen una estructura específica que incluye:

- **Encabezado DOS**: Está al inicio del archivo y contiene la firma "MZ". Es importante porque incluye el campo `e_lfanew` que apunta al encabezado NT.
- **Stub DOS**: Código pequeño que se ejecuta si el archivo se abre en DOS.
- **Encabezado NT**: Contiene la firma "PE\0\0" y tiene dos partes principales:
  - **File Header**: Contiene información sobre la arquitectura y características del archivo.
  - **Optional Header**: A pesar de su nombre, es obligatorio y contiene datos cruciales como ImageBase (dirección base preferida), AddressOfEntryPoint (punto de entrada), SizeOfImage (tamaño total en memoria), y direcciones a tablas de datos importantes.
- **Tabla de secciones**: Define las secciones del archivo (.text, .data, .rdata, etc.).

![image](https://github.com/user-attachments/assets/69388fd9-69ea-434d-a948-33440d094f1f)

En la inyección ManualMap, entendemos esta estructura para poder cargar manualmente el archivo DLL en memoria.

## 2. Lectura del archivo DLL y verificación

```cpp
std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);
// ... 
PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData);
if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
// ...
PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pSrcData + pDosHeader->e_lfanew);
if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
```

En esta sección:
1. Abrimos el archivo DLL en modo binario y leemos todo su contenido en memoria.
2. Verificamos que tenga la firma DOS correcta ("MZ" o 0x5A4D).
3. Usamos el campo `e_lfanew` para encontrar y verificar el encabezado NT con la firma "PE\0\0".

![image](https://github.com/user-attachments/assets/4f8955bf-9fcb-4f2f-88d7-f402bec77f97)

Esta verificación es crucial porque nos asegura que estamos trabajando con un archivo PE válido antes de intentar cargarlo en otro proceso.

## 3. Asignación de memoria en el proceso objetivo

```cpp
LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, pNTHeader->OptionalHeader.SizeOfImage, 
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

En esta fase:
1. Usamos `VirtualAllocEx` para reservar y comprometer memoria en el proceso objetivo.
2. El tamaño que solicitamos es exactamente `SizeOfImage` del encabezado opcional, que representa el tamaño total que ocupará la DLL en memoria.
3. Establecemos permisos `PAGE_EXECUTE_READWRITE` para permitir que el código se ejecute.

A diferencia de `LoadLibrary`, que deja que el sistema operativo decida dónde cargar la DLL, aquí tenemos control total sobre la ubicación en memoria. Esto nos permite evitar detecciones basadas en monitoreo de APIs estándar.

![image](https://github.com/user-attachments/assets/ce90b027-4bd4-4fcf-9d1a-90e15a94d0db)

## 4. Estructura de datos MANUAL_MAPPING_DATA

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

Esta estructura es fundamental para la técnica:
1. Contiene punteros a las funciones `LoadLibraryA` y `GetProcAddress`, que son necesarias para resolver importaciones.
2. Incluye la dirección base donde hemos asignado memoria en el proceso objetivo.

Esta información se pasará al shellcode para que pueda completar el proceso de carga dentro del proceso objetivo.

## 5. Copiado de secciones PE

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
            cout << "Error: No se pudo escribir la sección " << i << endl;
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            delete[] pSrcData;
            return false;
        }
    }
}
```

En esta etapa:
1. Recorremos cada sección del archivo PE (.text, .data, .rdata, etc.).
2. Para cada sección, calculamos su ubicación en el archivo (PointerToRawData) y su destino en memoria (VirtualAddress).
3. Utilizamos `WriteProcessMemory` para copiar los datos de cada sección desde nuestro buffer a la memoria del proceso objetivo.

Las secciones más importantes son:
- `.text`: Contiene el código ejecutable
- `.data`: Datos modificables (variables globales)
- `.rdata`: Datos de solo lectura (constantes, strings)
- `.idata`: Tabla de importaciones

![image](https://github.com/user-attachments/assets/06d7520d-f5f6-436a-a264-f7bca2d4217e)

## 6. Copiado de encabezados PE

```cpp
if (!WriteProcessMemory(hProcess, pTargetBase, pSrcData, 
                       pNTHeader->OptionalHeader.SizeOfHeaders, nullptr))
{
    cout << "Error: No se pudieron escribir los encabezados PE" << endl;
    VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
    delete[] pSrcData;
    return false;
}
```

Aquí:
1. Copiamos todos los encabezados PE (DOS, NT, tabla de secciones) al inicio de la memoria asignada.
2. El tamaño está especificado en `SizeOfHeaders` del encabezado opcional.
3. Estos encabezados son esenciales porque contienen información que el sistema operativo y el propio código de la DLL necesitarán para funcionar correctamente.

## 7. Creación y ejecución del shellcode

```cpp
BYTE* pShellcode = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, 
                                           4096, MEM_COMMIT | MEM_RESERVE, 
                                           PAGE_EXECUTE_READWRITE));
// ... WriteProcessMemory ...
HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode + sizeof(data)), 
                                   pShellcode, 0, nullptr);
```

Este es un paso crítico:
1. Asignamos 4KB de memoria para el shellcode en el proceso objetivo.
2. Escribimos primero la estructura `MANUAL_MAPPING_DATA` y luego el código del shellcode.
3. Creamos un hilo remoto que ejecutará el shellcode.
4. El punto de entrada es la dirección después de los datos de mapeo, y pasamos la dirección del inicio (que incluye los datos) como parámetro.

El shellcode se ejecutará en el contexto del proceso objetivo, lo que le permite realizar operaciones que nosotros no podríamos hacer directamente desde nuestro proceso.

![image](https://github.com/user-attachments/assets/0e4bb1c6-6f4a-4a8c-8894-655d7d836e60)

## 8. Resolución de importaciones dentro del shellcode

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
                // Importación por ordinal
                UINT_PTR ordinal = pOriginalThunk->u1.Ordinal & 0xffff;
                pThunk->u1.Function = reinterpret_cast<UINT_PTR>(_GetProcAddress(hDll, 
                                    reinterpret_cast<char*>(ordinal)));
            }
            else
            {
                // Importación por nombre
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

Dentro del shellcode:
1. Accedemos a la tabla de importaciones de la DLL (`IMAGE_DIRECTORY_ENTRY_IMPORT`).
2. Para cada módulo importado:
   - Obtenemos su nombre y lo cargamos con `LoadLibraryA`.
   - Recorremos todas las funciones importadas de ese módulo.
   - Resolvemos cada función usando `GetProcAddress` y rellenamos la IAT (Import Address Table) con las direcciones correctas.
3. Esto se hace para importaciones por nombre y por ordinal.

Este proceso es similar a lo que hace el cargador de Windows, pero lo hacemos manualmente para tener control total.

## 9. Aplicación de relocaciones de base

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

Las relocaciones son cruciales cuando la DLL se carga en una dirección diferente a su ImageBase preferida:
1. Calculamos el "delta" (diferencia entre la dirección actual y la preferida).
2. Recorremos la tabla de relocaciones (`IMAGE_DIRECTORY_ENTRY_BASERELOC`).
3. Aplicamos el delta a todas las direcciones absolutas dentro del código que necesitan ser ajustadas.

Esto es necesario porque el código compilado puede contener referencias a direcciones fijas que asumen que la DLL se cargará en su ImageBase preferida.

## 10. Llamada a DllMain

```cpp
if (_pOptionalHeader->AddressOfEntryPoint)
{
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(_DllBase + _pOptionalHeader->AddressOfEntryPoint);
    _DllMain(_DllBase, DLL_PROCESS_ATTACH, nullptr);
}
```

Finalmente:
1. Localizamos el punto de entrada de la DLL (`AddressOfEntryPoint`).
2. Llamamos a la función `DllMain` con el parámetro `DLL_PROCESS_ATTACH`.
3. Esto permite que la DLL ejecute su código de inicialización.

La llamada a `DllMain` es la "señal de inicio" para la DLL. Aquí es donde el código de la DLL tiene su primera oportunidad de ejecutarse y realizar cualquier configuración necesaria.

## 11. Búsqueda y conexión con el proceso objetivo

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

Esta función auxiliar:
1. Utiliza `CreateToolhelp32Snapshot` para obtener una "instantánea" de todos los procesos en ejecución.
2. Recorre la lista de procesos con `Process32First`/`Process32Next`.
3. Compara el nombre de cada proceso con el nombre buscado y devuelve el PID si lo encuentra.

Una vez encontrado el PID, usamos `OpenProcess` para obtener un handle con los permisos necesarios (`PROCESS_ALL_ACCESS`).

## 12. Limpieza de recursos y finalización

```cpp
WaitForSingleObject(hThread, INFINITE);
VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
delete[] pSrcData;
CloseHandle(hThread);
```

En esta última fase:
1. Esperamos a que el hilo remoto finalice con `WaitForSingleObject`.
2. Liberamos la memoria del shellcode con `VirtualFreeEx` (ya no es necesaria después de la inyección).
3. Liberamos el buffer local con `delete[]`.
4. Cerramos los handles abiertos con `CloseHandle`.

La DLL queda inyectada y funcionando en el proceso objetivo, sin dejar rastros visibles en la lista de módulos cargados del proceso.
