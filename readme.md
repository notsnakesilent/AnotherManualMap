# AnotherManualMap
Explanation and Proof of Concept of the Manual Map Injection (Windows) technique, commonly used by malware and game hackers to bypass security systems

A complete explanation of the technique is available in
<p align="center">
  <a href="docs/technique_ES.md">Español</a> | <a href="docs/technique_EN.md">English</a>
</p>

## What is Manual Map Injection?

Manual Map Injection is a sophisticated **DLL injection technique** widely used by modern malware and game cheats to:

* Load DLLs into processes without using standard Windows APIs
* Bypass security monitoring of LoadLibrary calls
* Hide injected modules from the loaded module list
* Execute arbitrary code in the context of another process

**In essence**: a DLL is manually loaded into the target process memory, imports are resolved, relocations are applied, and the DLL's entry point is called, all without using the standard Windows loader.

## For Educational Purposes Only

This repository contains:
* **Detailed explanation** of the Manual Map Injection technique (English and Spanish)
* **Complete source code** for a Proof of Concept (PoC)

## How It Works

The technique is divided into several critical steps:

1. **Reading**: The DLL file is read into memory and PE headers are verified
2. **Memory Allocation**: Memory is allocated in the target process
3. **Section Mapping**: DLL sections are mapped into the target memory
4. **Shellcode Creation**: A shellcode is created that will execute in the target process
5. **Import Resolution**: All DLL imports are manually resolved
6. **Base Relocation**: Address relocations are applied if needed
7. **Execution**: DllMain entry point is called to initialize the DLL

## Cybersecurity Applications

* **Malware research**: Understanding how advanced threats operate
* **Game security**: Learning techniques used by cheat developers
* **Penetration testing**: Evaluating defenses against evasion techniques
* **Defense development**: Creating detection systems for this technique

## Repository Structure

```
ManualMapInjection/
├── src/
│   ├── main.cpp           # Source Code
├── docs/                  
│   ├── technique_ES.md    # Detailed explanation in Spanish
│   └── technique_EN.md    # Detailed explanation in English
├── README.md              # README English
└── README_ES.md           # README Spanish
```

## Building and Usage

### Prerequisites
- Visual Studio with C++ development tools
- Windows SDK
- Administrator privileges (for process access)

### Compilation
1. Clone the repository
2. Open the solution in Visual Studio
3. Build the solution in Release mode

### Usage
```
ManualMapInjection.exe [target_process] [dll_path]
```

Example:
```
ManualMapInjection.exe notepad.exe C:\path\to\your.dll
```

## Disclaimer

This code is provided for educational purposes only. Using this technique to inject code into processes you don't own may violate:

- Computer fraud laws
- Software license agreements
- Game terms of service

The authors are not responsible for any misuse of this information or code.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
