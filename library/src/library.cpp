#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>

#include "../../src/sdk.hpp"

namespace {

void WriteLog(const char* fmt, ...) {
    char tmp[MAX_PATH] = {0};
    if (!GetTempPathA(MAX_PATH, tmp)) return;

    char path[MAX_PATH] = {0};
    wsprintfA(path, "%sPoliceSimUnlocker.log", tmp);

    FILE* fp = nullptr;
    if (fopen_s(&fp, path, "a") == 0 && fp) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        va_end(ap);
        fputc('\n', fp);
        fclose(fp);
    }
}

bool IsHeapPtr(uintptr_t p) {
    return p >= 0x10000000000ULL && p <= 0x7FFFFFFFFFFFULL && (p & 3) == 0;
}

bool IsReadable(uintptr_t p) {
    if (p < 0x10000ULL || p > 0x7FFFFFFFFFFFULL) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) return false;
    constexpr DWORD kMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & kMask) != 0;
}

template <typename T>
T Read(uintptr_t addr, T def = T{}) {
    if (!IsReadable(addr)) return def;
    __try {
        return *reinterpret_cast<const T*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return def;
    }
}

template <typename T>
bool Write(uintptr_t addr, T val) {
    if (!IsReadable(addr)) return false;
    __try {
        *reinterpret_cast<T*>(addr) = val;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool CheckPrologue(uintptr_t addr, const uint8_t* sig, size_t len) {
    if (!IsReadable(addr)) return false;
    __try {
        const auto* bytes = reinterpret_cast<const uint8_t*>(addr);
        for (size_t i = 0; i < len; ++i) {
            if (bytes[i] != sig[i]) return false;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ProbeWorldChain(uintptr_t uworld, uintptr_t* outGI, uintptr_t* outPC) {
    if (!IsHeapPtr(uworld)) return false;
    uintptr_t gi = Read<uintptr_t>(uworld + sdk::offsets::UWorld_OwningGameInstance);
    if (!IsHeapPtr(gi)) return false;

    uintptr_t lpData = Read<uintptr_t>(gi + sdk::offsets::UGameInstance_LocalPlayers);
    int32_t lpCount  = Read<int32_t>(gi + sdk::offsets::UGameInstance_LocalPlayers + 0x08);
    if (!IsHeapPtr(lpData) || lpCount < 1 || lpCount > 4) return false;

    uintptr_t lp0 = Read<uintptr_t>(lpData);
    if (!IsHeapPtr(lp0)) return false;

    uintptr_t pc = Read<uintptr_t>(lp0 + sdk::offsets::ULocalPlayer_PlayerController);
    if (!IsHeapPtr(pc)) return false;

    if (outGI) *outGI = gi;
    if (outPC) *outPC = pc;
    return true;
}

uintptr_t LocateUWorld(uintptr_t base, size_t imgSize, uintptr_t* outGI, uintptr_t* outPC) {
    const uintptr_t rvas[] = {sdk::rva::GWorld_WinGDK, sdk::rva::GWorld_Win64};
    for (uintptr_t rva : rvas) {
        if (rva + 8 <= imgSize) {
            uintptr_t w = Read<uintptr_t>(base + rva);
            if (ProbeWorldChain(w, outGI, outPC)) return w;
        }
    }

    size_t start = (imgSize > 0x4800000) ? 0x4800000 : 0;
    for (size_t off = start; off + 8 <= imgSize; off += 8) {
        uintptr_t w = Read<uintptr_t>(base + off);
        if (ProbeWorldChain(w, outGI, outPC)) return w;
    }
    return 0;
}

void RunEngineUnlocks(uintptr_t base, uintptr_t gi, uintptr_t gs, uintptr_t ps) {
    __try {
        uintptr_t fus = 0;
        uintptr_t mapData = Read<uintptr_t>(gi + sdk::offsets::UGameInstance_SubsystemMap);
        int32_t mapCount  = Read<int32_t>(gi + sdk::offsets::UGameInstance_SubsystemMap + 0x08);

        if (IsHeapPtr(mapData) && mapCount > 0 && mapCount < 64) {
            for (int32_t i = 0; i < mapCount; ++i) {
                uintptr_t sub = Read<uintptr_t>(mapData + static_cast<size_t>(i) * 0x18 + 0x08);
                if (!IsHeapPtr(sub)) continue;
                int32_t nImpl = Read<int32_t>(sub + sdk::offsets::UFUS_UnlockableImplementations + 0x08);
                int32_t nCfg  = Read<int32_t>(sub + sdk::offsets::UFUS_UnlockableConfigs + 0x08);
                if (nImpl >= 100 && nImpl <= 500 && nImpl == nCfg) {
                    fus = sub;
                    break;
                }
            }
        }

        constexpr uint8_t kSigUnlockTag[8] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74};
        uintptr_t fnUnlockAddr = base + sdk::rva::UnlockFeatureByTag;
        bool canCallUnlock = CheckPrologue(fnUnlockAddr, kSigUnlockTag, sizeof(kSigUnlockTag));

        uintptr_t fuc = IsHeapPtr(gs) ? Read<uintptr_t>(gs + sdk::offsets::APsGS_FeatureUnlockingComponent) : 0;
        if (IsHeapPtr(fuc)) {
            uintptr_t states = Read<uintptr_t>(fuc + sdk::offsets::UFUC_UnlockableStates);
            int32_t count    = Read<int32_t>(fuc + sdk::offsets::UFUC_UnlockableStates + 0x08);
            if (IsHeapPtr(states) && count > 0 && count < 500) {
                auto fnUnlock = reinterpret_cast<sdk::FnUnlockFeatureByTag>(fnUnlockAddr);
                for (int32_t i = 0; i < count; ++i) {
                    uintptr_t elem = states + static_cast<size_t>(i) * sizeof(sdk::FUnlockableStateReplicationHelper);
                    if (fus && canCallUnlock && Read<uint8_t>(elem + 0x08) == 0) {
                        sdk::FName tag = Read<sdk::FName>(elem);
                        fnUnlock(fus + sdk::offsets::UFUS_ServiceInterface, &tag);
                    }
                    Write<uint8_t>(elem + 0x08, 1);
                }
            }
        }

        if (fus) {
            uintptr_t implData = Read<uintptr_t>(fus + sdk::offsets::UFUS_UnlockableImplementations);
            int32_t implCount  = Read<int32_t>(fus + sdk::offsets::UFUS_UnlockableImplementations + 0x08);
            if (IsHeapPtr(implData) && implCount > 0 && implCount < 500) {
                for (int32_t i = 0; i < implCount; ++i) {
                    uintptr_t obj = Read<uintptr_t>(implData + static_cast<size_t>(i) * 0x18 + 0x08);
                    if (IsHeapPtr(obj)) Write<uint8_t>(obj + 0x30, 1);
                }
            }

            uintptr_t cfgData = Read<uintptr_t>(fus + sdk::offsets::UFUS_UnlockableConfigs);
            int32_t cfgCount  = Read<int32_t>(fus + sdk::offsets::UFUS_UnlockableConfigs + 0x08);
            if (IsHeapPtr(cfgData) && cfgCount > 0 && cfgCount < 500) {
                for (int32_t i = 0; i < cfgCount; ++i) {
                    uintptr_t obj = Read<uintptr_t>(cfgData + static_cast<size_t>(i) * 0x18 + 0x08);
                    if (IsHeapPtr(obj)) Write<uint8_t>(obj + 0xB8, 1);
                }
            }
        }

        constexpr uint8_t kSigUnlockDist[8] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74};
        uintptr_t fnDistAddr = base + sdk::rva::UnlockDistrict;
        if (IsHeapPtr(ps) && CheckPrologue(fnDistAddr, kSigUnlockDist, sizeof(kSigUnlockDist))) {
            auto fnDist = reinterpret_cast<sdk::FnUnlockDistrict>(fnDistAddr);
            for (uint8_t d = 1; d <= 23; ++d) {
                fnDist(ps, d, false);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteLog("SEH: exception in RunEngineUnlocks");
    }
}

void SyncProgression(bool invokeNative, bool superSpeed) {
    HMODULE hMod = GetModuleHandleW(nullptr);
    if (!hMod) return;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) return;

    const auto base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
    const auto size = static_cast<size_t>(mi.SizeOfImage);

    uintptr_t gi = 0, pc = 0;
    uintptr_t uworld = LocateUWorld(base, size, &gi, &pc);
    if (!uworld || !gi || !pc) return;

    uintptr_t gs = Read<uintptr_t>(uworld + sdk::offsets::UWorld_GameState);
    if (!IsHeapPtr(gs)) gs = Read<uintptr_t>(pc + sdk::offsets::APsPC_GameState_WinGDK);
    if (!IsHeapPtr(gs)) gs = Read<uintptr_t>(pc + sdk::offsets::APsPC_GameState_Win64);

    uintptr_t ps   = Read<uintptr_t>(pc + sdk::offsets::AController_PlayerState);
    uintptr_t pawn = Read<uintptr_t>(pc + sdk::offsets::APlayerController_Pawn);

    if (invokeNative) {
        RunEngineUnlocks(base, gi, gs, ps);
    }

    if (IsHeapPtr(gs)) {
        uintptr_t sb = Read<uintptr_t>(gs + sdk::offsets::APsGS_ShiftBalancing);
        if (IsHeapPtr(sb)) {
            Write<float>(sb + sdk::offsets::UShiftBal_StartConductPoints, 9999.0f);
            Write<float>(sb + sdk::offsets::UShiftBal_MinConductPoints, -9999.0f);
            Write<float>(sb + sdk::offsets::UShiftBal_ScoreBonusMultiplier, 1000.0f);
            Write<int32_t>(sb + sdk::offsets::UShiftBal_MaxShiftsPerWeek, 99);
            Write<int32_t>(sb + sdk::offsets::UShiftBal_MaxSkippedDays, 99);
            Write<int32_t>(sb + sdk::offsets::UShiftBal_MaxAvailableShifts, 99);
        }
    }

    if (IsHeapPtr(ps)) {
        Write<float>(ps + sdk::offsets::APsPS_ConductPoints, 100.0f);
        if (Read<float>(ps + sdk::offsets::APsPS_ShiftPoints) < 100000.0f) {
            Write<float>(ps + sdk::offsets::APsPS_ShiftPoints, 100000.0f);
        }

        uintptr_t nbMap = Read<uintptr_t>(ps + sdk::offsets::APsPS_ShiftPointsPerNbhd);
        int32_t nbCount = Read<int32_t>(ps + sdk::offsets::APsPS_ShiftPointsPerNbhd + 0x08);
        if (IsHeapPtr(nbMap) && nbCount > 0 && nbCount < 64) {
            for (int32_t i = 0; i < nbCount; ++i) {
                uintptr_t entry = nbMap + static_cast<size_t>(i) * 0x10;
                if (Read<float>(entry + 0x04) < 100000.0f) {
                    Write<float>(entry + 0x04, 100000.0f);
                }
            }
        }

        uintptr_t dpData = Read<uintptr_t>(ps + sdk::offsets::APsPS_DistrictsProgress);
        int32_t dpCount  = Read<int32_t>(ps + sdk::offsets::APsPS_DistrictsProgress + 0x08);
        if (IsHeapPtr(dpData) && dpCount > 0 && dpCount <= 32) {
            constexpr uint8_t kSigSetXp[8] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74};
            uintptr_t fnXpAddr = base + sdk::rva::SetDistrictXp;
            bool canSetXp = invokeNative && CheckPrologue(fnXpAddr, kSigSetXp, sizeof(kSigSetXp));
            auto fnSetXp = reinterpret_cast<sdk::FnSetDistrictXp>(fnXpAddr);

            for (int32_t i = 0; i < dpCount; ++i) {
                uintptr_t entry = dpData + static_cast<size_t>(i) * 0x20;
                uint8_t dist = Read<uint8_t>(entry);
                Write<uint8_t>(entry + 0x01, 1);
                Write<float>(entry + 0x04, 99999.0f);
                Write<int32_t>(entry + 0x08, 10);
                if (canSetXp && dist >= 1 && dist <= 23) {
                    __try {
                        fnSetXp(ps, dist, 99999.0f, true);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
        }

        Write<float>(ps + sdk::offsets::APsPS_PendingDistrictXp, 99999.0f);
        Write<int32_t>(ps + sdk::offsets::APsPS_PendingDutyStars, 10);

        sdk::FFreeRoamProgress fr{};
        fr.bIsEarlyFreeRoamUnlocked = 1;
        fr.bIsUnlocked = 1;
        fr.Xp = 99999.0f;
        fr.BadgeLevel = 50;
        Write<sdk::FFreeRoamProgress>(ps + sdk::offsets::APsPS_FreeRoamProgress, fr);
        Write<float>(ps + sdk::offsets::APsPS_PendingFreeRoamXp, 99999.0f);
        Write<int32_t>(ps + sdk::offsets::APsPS_PendingBadgeLevel, 50);
    }

    if (IsHeapPtr(pawn)) {
        uintptr_t tools = Read<uintptr_t>(pawn + sdk::offsets::APsChar_ToolBalancingData);
        if (IsHeapPtr(tools)) {
            for (uintptr_t off : sdk::offsets::kToolOffsets) {
                Write<float>(tools + off, 999.0f);
            }
        }
        Write<uint8_t>(pawn + sdk::offsets::APsChar_FlashlightEnabled, 1);

        if (superSpeed) {
            Write<int32_t>(pawn + sdk::offsets::ACharacter_JumpMaxCount, 99);
            Write<int32_t>(pawn + sdk::offsets::ACharacter_JumpCurrentCount, 0);
            uintptr_t cm = Read<uintptr_t>(pawn + sdk::offsets::ACharacter_CharacterMovement);
            if (IsHeapPtr(cm)) {
                Write<float>(cm + sdk::offsets::UCharMove_JumpZVelocity, 750.0f);
                Write<float>(cm + sdk::offsets::UCharMove_MaxAcceleration, 9999.0f);
                Write<float>(cm + sdk::offsets::UCharMove_MaxAirControl, 9999.0f);
            }
            const uintptr_t physList[] = {
                Read<uintptr_t>(pc + sdk::offsets::APsPC_BalancingData_WinGDK),
                Read<uintptr_t>(pc + sdk::offsets::APsPC_BalancingData_Win64),
                Read<uintptr_t>(pawn + sdk::offsets::APsChar_BalancingData)
            };
            for (uintptr_t phys : physList) {
                if (IsHeapPtr(phys)) {
                    Write<float>(phys + 0x34, 800.0f);
                    Write<float>(phys + 0x38, 1600.0f);
                    Write<float>(phys + 0x3C, 5000.0f);
                }
            }
        }
    }
}

DWORD WINAPI PayloadThread(LPVOID) {
    WriteLog("Attached to PID %lu", GetCurrentProcessId());
    SyncProgression(true, false);
    Beep(880, 160);
    Beep(1175, 200);

    bool speedEnabled = false;
    DWORD lastTick = GetTickCount();

    for (;;) {
        if (GetAsyncKeyState(VK_F1) & 1) {
            SyncProgression(true, speedEnabled);
            Beep(1046, 140);
            Beep(1318, 180);
        }
        if (GetAsyncKeyState(VK_F2) & 1) {
            SyncProgression(false, speedEnabled);
            Beep(987, 140);
        }
        if (GetAsyncKeyState(VK_F3) & 1) {
            speedEnabled = !speedEnabled;
            SyncProgression(false, speedEnabled);
            Beep(speedEnabled ? 1200 : 600, 140);
        }

        DWORD now = GetTickCount();
        if (now - lastTick >= 3000) {
            lastTick = now;
            SyncProgression(false, speedEnabled);
        }
        Sleep(50);
    }
}

} // namespace

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        if (HANDLE h = CreateThread(nullptr, 0, PayloadThread, nullptr, 0, nullptr)) {
            CloseHandle(h);
        }
    }
    return TRUE;
}
