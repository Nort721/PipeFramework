#pragma once

#include <windows.h>
#include <bcrypt.h> // Windows Cryptography API: Next Generation (CNG)
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <memory> // For unique_ptr

#pragma comment(lib, "Bcrypt.lib") // Link against Bcrypt.lib

// Custom unique_ptr deleters for BCRYPT handles
struct AlgProviderDeleter {
    void operator()(BCRYPT_ALG_HANDLE h) const { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
struct HashHandleDeleter {
    void operator()(BCRYPT_HASH_HANDLE h) const { if (h) BCryptDestroyHash(h); }
};

using unique_alg_provider_handle = std::unique_ptr<void, AlgProviderDeleter>;
using unique_hash_handle = std::unique_ptr<void, HashHandleDeleter>;


// Helper to convert byte vector to hex string
inline std::string BytesToHex(const std::vector<BYTE>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (BYTE b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Helper to convert hex string to byte vector
inline std::vector<BYTE> HexToBytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of characters");
    }
    std::vector<BYTE> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        BYTE byte = static_cast<BYTE>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}


// Computes SHA-256 hash of data combined with a salt (nonce)
inline std::vector<BYTE> ComputeSHA256(const std::string& data, const std::vector<BYTE>& salt) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to open SHA256 algorithm provider");
    unique_alg_provider_handle hAlg_ptr(hAlg); // RAII

    DWORD cbHashObject = 0, cbResult = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to get hash object size");

    std::vector<BYTE> hashObject(cbHashObject);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to create hash object");
    unique_hash_handle hHash_ptr(hHash); // RAII

    // Combine data and salt
    std::vector<BYTE> combinedData;
    combinedData.insert(combinedData.end(), data.begin(), data.end());
    combinedData.insert(combinedData.end(), salt.begin(), salt.end());


    status = BCryptHashData(hHash, combinedData.data(), static_cast<ULONG>(combinedData.size()), 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to hash data");

    DWORD cbHash = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to get hash length");

    std::vector<BYTE> hashValue(cbHash);
    status = BCryptFinishHash(hHash, hashValue.data(), cbHash, 0);
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Failed to finish hash computation");

    return hashValue;
}

// Generates a random nonce (salt) of specified size in bytes
inline std::vector<BYTE> GenerateNonce(size_t size = 16) {
    std::vector<BYTE> nonce(size);
    NTSTATUS status = BCryptGenRandom(NULL, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to generate random nonce");
    }
    return nonce;
}