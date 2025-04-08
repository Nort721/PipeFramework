#pragma once

#include <windows.h>
#include <sddl.h>   // For ConvertStringSecurityDescriptorToSecurityDescriptor
#include <stdexcept>
#include <memory>   // For std::unique_ptr

// RAII wrapper for LocalFree
struct LocalFreeDeleter {
    void operator()(HLOCAL h) const { if (h) LocalFree(h); }
};
using unique_local_ptr = std::unique_ptr<void, LocalFreeDeleter>;

//------------------------------------------------------------------------------
// Creates SECURITY_ATTRIBUTES that grant access only to the current user.
// Returns a unique_ptr to manage the SECURITY_DESCRIPTOR lifetime.
// The SECURITY_ATTRIBUTES structure itself needs to be managed separately,
// but its lpSecurityDescriptor field will point to the memory managed by the unique_ptr.
//------------------------------------------------------------------------------
inline std::unique_ptr<SECURITY_DESCRIPTOR, decltype(&::LocalFree)> CreateCurrentUserSecurityAttributes(
    SECURITY_ATTRIBUTES& sa)
{
    const wchar_t* sddl = L"D:(A;OICI;GA;;;OW)"; // Grant full access to Owner

    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        &psd,
        nullptr))
    {
        throw PipeException("Failed to convert string security descriptor");
    }

    // Use unique_ptr with LocalFree as deleter
    std::unique_ptr<SECURITY_DESCRIPTOR, decltype(&::LocalFree)> psd_ptr(
        static_cast<SECURITY_DESCRIPTOR*>(psd),
        &::LocalFree
    );

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = psd_ptr.get();
    sa.bInheritHandle = FALSE;

    return psd_ptr;
}

// Simpler function to just return the pointer, assuming lifetime is managed elsewhere
// (e.g., within the NamedPipeServer class)
inline unique_local_ptr CreateCurrentUserSecurityDescriptor() {
    const wchar_t* sddl = L"D:(A;OICI;GA;;;OW)"; // Grant full access to Owner
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        &psd,
        nullptr))
    {
        throw PipeException("Failed to convert string security descriptor");
    }
    return unique_local_ptr(psd);
}