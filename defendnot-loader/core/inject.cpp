#include "core/core.hpp"

#include "shared/defer.hpp"
#include <print>
#include <stdexcept>

#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

#define HASH_ANSI(API) (HashStringDjb2A(reinterpret_cast<PBYTE>(API)))

// String hashing
#define H_MOD_KERNEL32 0x7AF0CEAE
#define H_FUN_CREATEPROCESSA 0x55FE21B2
#define H_FUN_VIRTUALALLOCEX 0x9AB74E4D
#define H_FUN_VIRTUALFREEEX 0xF97CC084
#define H_FUN_WRITEPROCESSMEMORY 0xB27E00E1
#define H_FUN_CREATEREMOTETHREAD 0xED8B8F76

namespace loader {

    // Function prototypes
    typedef BOOL(WINAPI* fnCreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
    typedef LPVOID(WINAPI* fnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    typedef BOOL(WINAPI* fnVirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
    typedef HANDLE(WINAPI* fnCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

    // API Hashing using Djb2 for ANSI
    DWORD HashStringDjb2A(PBYTE String) {
        ULONG Hash = 0xDEADC0DE;
        INT c;
        while (c = *String++)
            Hash = ((Hash << 0x5) + Hash) + c;
        return Hash;
    }

    // retrieve module handle by hash
    HMODULE GetModuleHandleByHash(DWORD hash) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        HANDLE hProcess = GetCurrentProcess();

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleFileNameA(hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                    // Get the base name (strip path)
                    const char* pBaseName = strrchr(szModName, '\\');
                    pBaseName = pBaseName ? pBaseName + 1 : szModName;
                    if (HashStringDjb2A((PBYTE)pBaseName) == hash) {
                        return hMods[i];
                    }
                }
            }
        }
        return nullptr;
    }

    // GetProcAddress replacement
    FARPROC NotGetProcAddress(IN HMODULE hModule, IN DWORD dwApiNameHash) {
        if (!hModule || dwApiNameHash == NULL) 
            return NULL;

        PBYTE pBase = (PBYTE)hModule;

        PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
        if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
        if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
        PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
        PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
        PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

        // Looping through all the exported functions
        for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
            CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
            WORD ordinal = FunctionOrdinalArray[i];
            PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[ordinal]);

            if (dwApiNameHash == HASH_ANSI(pFunctionName)) {
                return reinterpret_cast<FARPROC>(pFunctionAddress);
            }
        }

        return NULL;
    }

    // Main function for DLL injection
    HANDLE inject(std::string_view dll_path, std::string_view proc_name) {
        STARTUPINFOA si = {
            .cb = sizeof(si),
        };
        PROCESS_INFORMATION pi = {
            0,
        };
        SECURITY_ATTRIBUTES sa = {
            .nLength = sizeof(sa),
            .bInheritHandle = TRUE,
        };

        fnCreateProcessA pCreateProcessA = nullptr;
        pCreateProcessA = reinterpret_cast<fnCreateProcessA>(NotGetProcAddress(GetModuleHandleByHash(H_MOD_KERNEL32), H_FUN_CREATEPROCESSA));
        std::println("[*] Executing: {}", proc_name);
        if (!pCreateProcessA(nullptr, const_cast<char*>(proc_name.data()), &sa, &sa, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            throw std::runtime_error(std::format("[!] Error when spawning new process: {}", GetLastError()));
        }

        defer->void {
            CloseHandle(pi.hThread);
            // Not closing hProcess because we return it
        };

        fnVirtualAllocEx pVirtualAllocEx = nullptr;
        pVirtualAllocEx = reinterpret_cast<fnVirtualAllocEx>(NotGetProcAddress(GetModuleHandleByHash(H_MOD_KERNEL32), H_FUN_VIRTUALALLOCEX));
        LPVOID mem = pVirtualAllocEx(pi.hProcess, nullptr, dll_path.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem == nullptr) {
            throw std::runtime_error(std::format("[!] Error when allocating memory: {}", GetLastError()));
        }

        fnVirtualFreeEx pVirtualFreeEx = nullptr;
        pVirtualFreeEx = reinterpret_cast<fnVirtualFreeEx>(NotGetProcAddress(GetModuleHandleByHash(H_MOD_KERNEL32), H_FUN_VIRTUALFREEEX));
        defer->void {
            pVirtualFreeEx(pi.hProcess, mem, 0, MEM_RELEASE);
        };

        fnWriteProcessMemory pWriteProcessMemory = nullptr;
        pWriteProcessMemory = reinterpret_cast<fnWriteProcessMemory>(NotGetProcAddress(GetModuleHandleByHash(H_MOD_KERNEL32), H_FUN_WRITEPROCESSMEMORY));
        if (!pWriteProcessMemory(pi.hProcess, mem, dll_path.data(), dll_path.size() + 1, nullptr)) {
            throw std::runtime_error(std::format("[!] Error when writing memory: {}", GetLastError()));
        }

        fnCreateRemoteThread pCreateRemoteThread = nullptr;
        pCreateRemoteThread = reinterpret_cast<fnCreateRemoteThread>(NotGetProcAddress(GetModuleHandleByHash(H_MOD_KERNEL32), H_FUN_CREATEREMOTETHREAD));
        HANDLE thread = pCreateRemoteThread(pi.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), mem, 0, nullptr);
        if (thread == NULL) {
            throw std::runtime_error(std::format("[!] Error when creating thread: {}", GetLastError()));
        }

        defer->void {
            CloseHandle(thread);
        };

        // Wait for DllMain to complete
        WaitForSingleObject(thread, INFINITE);
        return pi.hProcess;
    }
} // namespace loader
