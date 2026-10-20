#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <psapi.h>

#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#include "sdk.hpp"

namespace {

bool GrantPackageReadExecute(const wchar_t* filePath) {
    uint8_t sidBuf[SECURITY_MAX_SID_SIZE];
    PSID pSid = sidBuf;
    DWORD sidSize = sizeof(sidBuf);

    if (!CreateWellKnownSid(WELL_KNOWN_SID_TYPE::WinBuiltinAnyPackageSid, nullptr, pSid, &sidSize)) {
        return false;
    }

    PACL pOldDacl = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (GetNamedSecurityInfoW(filePath, SE_OBJECT_TYPE::SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, &pOldDacl, nullptr, &pSD) != ERROR_SUCCESS) {
        return false;
    }

    EXPLICIT_ACCESS_W ea{};
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
    ea.grfAccessMode = ACCESS_MODE::SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.pMultipleTrustee = nullptr;
    ea.Trustee.MultipleTrusteeOperation = MULTIPLE_TRUSTEE_OPERATION::NO_MULTIPLE_TRUSTEE;
    ea.Trustee.TrusteeForm = TRUSTEE_FORM::TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_TYPE::TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWCH>(pSid);

    PACL pNewDacl = nullptr;
    if (SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl) != ERROR_SUCCESS) {
        LocalFree(pSD);
        return false;
    }

    DWORD status = SetNamedSecurityInfoW(const_cast<LPWSTR>(filePath), SE_OBJECT_TYPE::SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
    LocalFree(pNewDacl);
    LocalFree(pSD);
    return status == ERROR_SUCCESS;
}

HMODULE LookupRemoteModule(DWORD pid, const wchar_t* fullPath) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    HMODULE hMod = nullptr;
    if (Module32FirstW(hSnap, &me)) {
        do {
            if (_wcsicmp(me.szExePath, fullPath) == 0) {
                hMod = me.hModule;
                break;
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return hMod;
}

bool InjectDll(DWORD pid, const wchar_t* dllPath) {
    wchar_t fullSrc[MAX_PATH] = {0};
    wchar_t* fileName = nullptr;
    DWORD pathLen = GetFullPathNameW(dllPath, MAX_PATH, fullSrc, &fileName);
    if (pathLen == 0 || pathLen >= MAX_PATH || !fileName) {
        printf("[-] GetFullPathNameW failed for %ls\n", dllPath);
        return false;
    }

    std::wstring dir(fullSrc, fileName - fullSrc);
    std::wstring stagedPath = dir + L"injected_" + std::wstring(fileName);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[-] OpenProcess(%lu) failed (err=%lu)\n", pid, GetLastError());
        return false;
    }

    if (HMODULE prev = LookupRemoteModule(pid, stagedPath.c_str())) {
        auto fnFree = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "FreeLibrary"));
        if (HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, fnFree, prev, 0, nullptr)) {
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
        }
    }

    if (!CopyFileW(fullSrc, stagedPath.c_str(), FALSE)) {
        printf("[-] CopyFileW failed (err=%lu)\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    if (!GrantPackageReadExecute(stagedPath.c_str())) {
        printf("[-] Failed to apply WinBuiltinAnyPackageSid DACL\n");
        CloseHandle(hProc);
        return false;
    }

    SIZE_T allocBytes = (stagedPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteBuf = VirtualAllocEx(hProc, nullptr, allocBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        printf("[-] VirtualAllocEx failed (err=%lu)\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteBuf, stagedPath.c_str(), allocBytes, &written) || written != allocBytes) {
        printf("[-] WriteProcessMemory failed (err=%lu)\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    auto fnLoad = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "LoadLibraryW"));
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, fnLoad, remoteBuf, 0, nullptr);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed (err=%lu)\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);

    printf("[+] Injected %ls into PID %lu\n", stagedPath.c_str(), pid);
    return true;
}

bool IsHeapPtr(uintptr_t p) {
    return p >= 0x10000000000ULL && p <= 0x7FFFFFFFFFFFULL && (p & 3) == 0;
}

template <typename T>
T ReadRemote(HANDLE hProc, uintptr_t addr, T def = T{}) {
    T val{};
    SIZE_T read = 0;
    if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), &val, sizeof(T), &read) && read == sizeof(T)) {
        return val;
    }
    return def;
}

template <typename T>
bool WriteRemote(HANDLE hProc, uintptr_t addr, T val) {
    SIZE_T written = 0;
    return WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(addr), &val, sizeof(T), &written) && written == sizeof(T);
}

struct TargetProcess {
    DWORD pid = 0;
    uintptr_t base = 0;
    size_t size = 0;
    std::wstring name;
};

bool AttachTarget(TargetProcess* out) {
    constexpr const wchar_t* kNames[] = {
        L"Boston-WinGDK-Shipping.exe",
        L"Boston-Win64-Shipping.exe"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    std::wstring matched;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            for (const wchar_t* t : kNames) {
                if (_wcsicmp(pe.szExeFile, t) == 0) {
                    pid = pe.th32ProcessID;
                    matched = pe.szExeFile;
                    break;
                }
            }
            if (pid) break;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (!pid) return false;

    HANDLE hMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hMod == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool ok = false;
    if (Module32FirstW(hMod, &me)) {
        out->pid = pid;
        out->base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
        out->size = me.modBaseSize;
        out->name = matched;
        ok = true;
    }
    CloseHandle(hMod);
    return ok;
}

uintptr_t ResolveRemoteWorld(HANDLE hProc, uintptr_t base, size_t size, uintptr_t* outGI, uintptr_t* outPC) {
    auto verify = [&](uintptr_t w) -> bool {
        if (!IsHeapPtr(w)) return false;
        uintptr_t gi = ReadRemote<uintptr_t>(hProc, w + sdk::offsets::UWorld_OwningGameInstance);
        if (!IsHeapPtr(gi)) return false;
        uintptr_t lpData = ReadRemote<uintptr_t>(hProc, gi + sdk::offsets::UGameInstance_LocalPlayers);
        int32_t lpCount  = ReadRemote<int32_t>(hProc, gi + sdk::offsets::UGameInstance_LocalPlayers + 0x08);
        if (!IsHeapPtr(lpData) || lpCount < 1 || lpCount > 4) return false;
        uintptr_t lp0 = ReadRemote<uintptr_t>(hProc, lpData);
        if (!IsHeapPtr(lp0)) return false;
        uintptr_t pc = ReadRemote<uintptr_t>(hProc, lp0 + sdk::offsets::ULocalPlayer_PlayerController);
        if (!IsHeapPtr(pc)) return false;
        if (outGI) *outGI = gi;
        if (outPC) *outPC = pc;
        return true;
    };

    for (uintptr_t rva : {sdk::rva::GWorld_WinGDK, sdk::rva::GWorld_Win64}) {
        if (rva + 8 <= size) {
            uintptr_t cand = ReadRemote<uintptr_t>(hProc, base + rva);
            if (verify(cand)) return cand;
        }
    }

    constexpr size_t kChunk = 0x100000;
    std::vector<uint8_t> buf(kChunk);
    size_t start = (size > 0x5000000) ? 0x5000000 : 0;
    for (size_t off = start; off < size; off += kChunk) {
        size_t len = (off + kChunk <= size) ? kChunk : (size - off);
        SIZE_T nRead = 0;
        if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(base + off), buf.data(), len, &nRead)) continue;
        for (size_t i = 0; i + 8 <= nRead; i += 8) {
            uintptr_t cand = *reinterpret_cast<const uintptr_t*>(&buf[i]);
            if (verify(cand)) return cand;
        }
    }
    return 0;
}

void PatchRemoteProgression(const TargetProcess& proc, float shiftPoints, float multiplier) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, proc.pid);
    if (!hProc) {
        printf("[-] OpenProcess failed (err=%lu)\n", GetLastError());
        return;
    }

    uintptr_t gi = 0, pc = 0;
    uintptr_t uworld = ResolveRemoteWorld(hProc, proc.base, proc.size, &gi, &pc);
    if (!uworld) {
        printf("[!] UWorld not initialized yet.\n");
        CloseHandle(hProc);
        return;
    }

    uintptr_t gs = ReadRemote<uintptr_t>(hProc, uworld + sdk::offsets::UWorld_GameState);
    if (!IsHeapPtr(gs)) gs = ReadRemote<uintptr_t>(hProc, pc + sdk::offsets::APsPC_GameState_WinGDK);
    if (!IsHeapPtr(gs)) gs = ReadRemote<uintptr_t>(hProc, pc + sdk::offsets::APsPC_GameState_Win64);

    uintptr_t ps   = ReadRemote<uintptr_t>(hProc, pc + sdk::offsets::AController_PlayerState);
    uintptr_t pawn = ReadRemote<uintptr_t>(hProc, pc + sdk::offsets::APlayerController_Pawn);

    printf("[+] UWorld=0x%llX  GI=0x%llX  PC=0x%llX\n",
           static_cast<unsigned long long>(uworld),
           static_cast<unsigned long long>(gi),
           static_cast<unsigned long long>(pc));

    if (IsHeapPtr(gs)) {
        uintptr_t sb = ReadRemote<uintptr_t>(hProc, gs + sdk::offsets::APsGS_ShiftBalancing);
        if (IsHeapPtr(sb)) {
            WriteRemote<float>(hProc, sb + sdk::offsets::UShiftBal_StartConductPoints, 9999.0f);
            WriteRemote<float>(hProc, sb + sdk::offsets::UShiftBal_MinConductPoints, -9999.0f);
            WriteRemote<float>(hProc, sb + sdk::offsets::UShiftBal_ScoreBonusMultiplier, multiplier);
            WriteRemote<int32_t>(hProc, sb + sdk::offsets::UShiftBal_MaxShiftsPerWeek, 99);
            WriteRemote<int32_t>(hProc, sb + sdk::offsets::UShiftBal_MaxSkippedDays, 99);
            WriteRemote<int32_t>(hProc, sb + sdk::offsets::UShiftBal_MaxAvailableShifts, 99);
            printf("[+] UShiftBalancingData: Multiplier=%.0fx, ConductPoints=9999\n", multiplier);
        }

        uintptr_t fuc = ReadRemote<uintptr_t>(hProc, gs + sdk::offsets::APsGS_FeatureUnlockingComponent);
        if (IsHeapPtr(fuc)) {
            uintptr_t states = ReadRemote<uintptr_t>(hProc, fuc + sdk::offsets::UFUC_UnlockableStates);
            int32_t count    = ReadRemote<int32_t>(hProc, fuc + sdk::offsets::UFUC_UnlockableStates + 0x08);
            if (IsHeapPtr(states) && count > 0 && count < 500) {
                for (int32_t i = 0; i < count; ++i) {
                    WriteRemote<uint8_t>(hProc, states + static_cast<size_t>(i) * sizeof(sdk::FUnlockableStateReplicationHelper) + 0x08, 1);
                }
                printf("[+] UFeatureUnlockingComponent: %d states unlocked\n", count);
            }
        }
    }

    if (IsHeapPtr(gi)) {
        uintptr_t mapData = ReadRemote<uintptr_t>(hProc, gi + sdk::offsets::UGameInstance_SubsystemMap);
        int32_t mapCount  = ReadRemote<int32_t>(hProc, gi + sdk::offsets::UGameInstance_SubsystemMap + 0x08);
        if (IsHeapPtr(mapData) && mapCount > 0 && mapCount < 64) {
            for (int32_t i = 0; i < mapCount; ++i) {
                uintptr_t sub = ReadRemote<uintptr_t>(hProc, mapData + static_cast<size_t>(i) * 0x18 + 0x08);
                if (!IsHeapPtr(sub)) continue;
                int32_t nImpl = ReadRemote<int32_t>(hProc, sub + sdk::offsets::UFUS_UnlockableImplementations + 0x08);
                int32_t nCfg  = ReadRemote<int32_t>(hProc, sub + sdk::offsets::UFUS_UnlockableConfigs + 0x08);
                if (nImpl >= 100 && nImpl <= 500 && nImpl == nCfg) {
                    uintptr_t implData = ReadRemote<uintptr_t>(hProc, sub + sdk::offsets::UFUS_UnlockableImplementations);
                    for (int32_t j = 0; j < nImpl; ++j) {
                        uintptr_t obj = ReadRemote<uintptr_t>(hProc, implData + static_cast<size_t>(j) * 0x18 + 0x08);
                        if (IsHeapPtr(obj)) WriteRemote<uint8_t>(hProc, obj + 0x30, 1);
                    }
                    uintptr_t cfgData = ReadRemote<uintptr_t>(hProc, sub + sdk::offsets::UFUS_UnlockableConfigs);
                    for (int32_t j = 0; j < nCfg; ++j) {
                        uintptr_t obj = ReadRemote<uintptr_t>(hProc, cfgData + static_cast<size_t>(j) * 0x18 + 0x08);
                        if (IsHeapPtr(obj)) WriteRemote<uint8_t>(hProc, obj + 0xB8, 1);
                    }
                    printf("[+] UFeatureUnlockingSubsystem: %d implementations & configs unlocked\n", nImpl);
                    break;
                }
            }
        }
    }

    if (IsHeapPtr(ps)) {
        WriteRemote<float>(hProc, ps + sdk::offsets::APsPS_ConductPoints, 100.0f);
        WriteRemote<float>(hProc, ps + sdk::offsets::APsPS_ShiftPoints, shiftPoints);

        uintptr_t nbData = ReadRemote<uintptr_t>(hProc, ps + sdk::offsets::APsPS_ShiftPointsPerNbhd);
        int32_t nbCount  = ReadRemote<int32_t>(hProc, ps + sdk::offsets::APsPS_ShiftPointsPerNbhd + 0x08);
        if (IsHeapPtr(nbData) && nbCount > 0 && nbCount < 64) {
            for (int32_t i = 0; i < nbCount; ++i) {
                WriteRemote<float>(hProc, nbData + static_cast<size_t>(i) * 0x10 + 0x04, shiftPoints);
            }
        }

        uintptr_t dpData = ReadRemote<uintptr_t>(hProc, ps + sdk::offsets::APsPS_DistrictsProgress);
        int32_t dpCount  = ReadRemote<int32_t>(hProc, ps + sdk::offsets::APsPS_DistrictsProgress + 0x08);
        if (IsHeapPtr(dpData) && dpCount > 0 && dpCount <= 32) {
            for (int32_t i = 0; i < dpCount; ++i) {
                uintptr_t entry = dpData + static_cast<size_t>(i) * 0x20;
                WriteRemote<uint8_t>(hProc, entry + 0x01, 1);
                WriteRemote<float>(hProc, entry + 0x04, 99999.0f);
                WriteRemote<int32_t>(hProc, entry + 0x08, 10);
            }
        }

        WriteRemote<float>(hProc, ps + sdk::offsets::APsPS_PendingDistrictXp, 99999.0f);
        WriteRemote<int32_t>(hProc, ps + sdk::offsets::APsPS_PendingDutyStars, 10);

        sdk::FFreeRoamProgress fr{};
        fr.bIsEarlyFreeRoamUnlocked = 1;
        fr.bIsUnlocked = 1;
        fr.Xp = 99999.0f;
        fr.BadgeLevel = 50;
        WriteRemote<sdk::FFreeRoamProgress>(hProc, ps + sdk::offsets::APsPS_FreeRoamProgress, fr);
        WriteRemote<float>(hProc, ps + sdk::offsets::APsPS_PendingFreeRoamXp, 99999.0f);
        WriteRemote<int32_t>(hProc, ps + sdk::offsets::APsPS_PendingBadgeLevel, 50);

        printf("[+] APsPlayerState: ShiftPoints=%.0f, Districts=%d (10 Stars / 99,999 XP), BadgeLevel=50\n",
               shiftPoints, dpCount);
    }

    if (IsHeapPtr(pawn)) {
        uintptr_t tools = ReadRemote<uintptr_t>(hProc, pawn + sdk::offsets::APsChar_ToolBalancingData);
        if (IsHeapPtr(tools)) {
            for (uintptr_t off : sdk::offsets::kToolOffsets) {
                WriteRemote<float>(hProc, tools + off, 999.0f);
            }
            printf("[+] APsPlayerCharacter: Equipment & Ammo set to 999\n");
        }
    }

    CloseHandle(hProc);
}

std::wstring LocatePayloadDll() {
    wchar_t self[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    wchar_t* slash = wcsrchr(self, L'\\');
    std::wstring dir = slash ? std::wstring(self, slash - self + 1) : L"";

    const std::wstring paths[] = {
        dir + L"library.dll",
        dir + L"Release\\library.dll",
        L"library.dll"
    };

    for (const auto& p : paths) {
        DWORD attr = GetFileAttributesW(p.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            return p;
        }
    }
    return dir + L"library.dll";
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleTitleW(L"PoliceSimUnlocker");
    printf("PoliceSimUnlocker (WinGDK / Win64)\n");
    printf("----------------------------------\n");

    if (argc == 3) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        DWORD pid = 0;
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, argv[1]) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
        if (!pid) {
            printf("[-] Process %ls not found.\n", argv[1]);
            return 1;
        }
        return InjectDll(pid, argv[2]) ? 0 : 1;
    }

    TargetProcess target{};
    if (!AttachTarget(&target)) {
        printf("[*] Waiting for Boston-WinGDK-Shipping.exe / Boston-Win64-Shipping.exe...\n");
        while (!AttachTarget(&target)) {
            Sleep(1000);
        }
    }

    printf("[+] Target: %ls (PID=%lu, Base=0x%llX, Size=0x%llX)\n",
           target.name.c_str(),
           target.pid,
           static_cast<unsigned long long>(target.base),
           static_cast<unsigned long long>(target.size));

    std::wstring dll = LocatePayloadDll();
    InjectDll(target.pid, dll.c_str());
    PatchRemoteProgression(target, 100000.0f, 1000.0f);

    if (argc == 2 && _wcsicmp(argv[1], L"--auto") == 0) {
        return 0;
    }

    for (;;) {
        printf("\nHotkeys (in-game): [F1] Unlock All + 100k SP  [F2] Refill Tools  [F3] Speed/Jump\n");
        printf("[1] Re-apply Unlock All + 100,000 SP\n");
        printf("[2] Set custom Shift Points & Multiplier\n");
        printf("[3] Re-inject DLL\n");
        printf("[4] Quit\n> ");

        char buf[64] = {0};
        if (!fgets(buf, sizeof(buf), stdin)) break;

        int cmd = atoi(buf);
        if (cmd == 4) break;

        if (!AttachTarget(&target)) {
            printf("[-] Target process not running.\n");
            continue;
        }

        if (cmd == 1) {
            InjectDll(target.pid, dll.c_str());
            PatchRemoteProgression(target, 100000.0f, 1000.0f);
        } else if (cmd == 2) {
            printf("Shift Points (default 100000): ");
            if (!fgets(buf, sizeof(buf), stdin)) break;
            float sp = static_cast<float>(atof(buf));
            if (sp <= 0.0f) sp = 100000.0f;

            printf("Score Bonus Multiplier (default 1000): ");
            if (!fgets(buf, sizeof(buf), stdin)) break;
            float mult = static_cast<float>(atof(buf));
            if (mult <= 0.0f) mult = 1000.0f;

            PatchRemoteProgression(target, sp, mult);
        } else if (cmd == 3) {
            InjectDll(target.pid, dll.c_str());
        }
    }

    return 0;
}
