#pragma once

#include <cstdint>

namespace sdk {

namespace rva {
    // GWorld pointers
    constexpr uintptr_t GWorld_WinGDK = 0x62562D8;
    constexpr uintptr_t GWorld_Win64  = 0x63FDA28;

    // FNamePool (WinGDK 22.3.3.0)
    constexpr uintptr_t FNamePool_WinGDK = 0x60AD540;

    // Native engine methods (WinGDK 22.3.3.0)
    constexpr uintptr_t UnlockFeatureByTag = 0x1A60580; // IFeatureUnlockingService::vt30[7]
    constexpr uintptr_t UnlockDistrict     = 0x1A604E0; // UPsPlayerState::UnlockDistrict
    constexpr uintptr_t SetDistrictXp      = 0x1A5E180; // UPsPlayerState::SetDistrictXp
}

namespace offsets {
    // UWorld
    constexpr uintptr_t UWorld_GameState          = 0x120;
    constexpr uintptr_t UWorld_OwningGameInstance = 0x180;

    // UGameInstance
    constexpr uintptr_t UGameInstance_LocalPlayers  = 0x038;
    constexpr uintptr_t UGameInstance_SubsystemMap  = 0x0F0;

    // ULocalPlayer
    constexpr uintptr_t ULocalPlayer_PlayerController = 0x030;

    // APlayerController / APsPlayerController
    constexpr uintptr_t AController_PlayerState     = 0x228;
    constexpr uintptr_t APlayerController_Pawn      = 0x2A0;
    constexpr uintptr_t APsPC_BalancingData_Win64   = 0x728;
    constexpr uintptr_t APsPC_BalancingData_WinGDK  = 0x760;
    constexpr uintptr_t APsPC_GameState_Win64       = 0x790;
    constexpr uintptr_t APsPC_GameState_WinGDK      = 0x7D8;

    // APsGameStateBase
    constexpr uintptr_t APsGS_ShiftBalancing            = 0x3C0;
    constexpr uintptr_t APsGS_IngameTimeComponent       = 0x3F0;
    constexpr uintptr_t APsGS_FeatureUnlockingComponent = 0x440;

    // UShiftBalancingData
    constexpr uintptr_t UShiftBal_StartConductPoints   = 0x030;
    constexpr uintptr_t UShiftBal_MinConductPoints     = 0x034;
    constexpr uintptr_t UShiftBal_ScoreBonusMultiplier = 0x038;
    constexpr uintptr_t UShiftBal_IngameShiftDuration  = 0x04C;
    constexpr uintptr_t UShiftBal_MaxShiftsPerWeek     = 0x074;
    constexpr uintptr_t UShiftBal_MaxSkippedDays       = 0x078;
    constexpr uintptr_t UShiftBal_MaxAvailableShifts   = 0x0D0;

    // UFeatureUnlockingComponent
    constexpr uintptr_t UFUC_UnlockableStates = 0x0B0; // TArray<FUnlockableStateReplicationHelper>, stride 0xC

    // UFeatureUnlockingSubsystem
    constexpr uintptr_t UFUS_ServiceInterface          = 0x030;
    constexpr uintptr_t UFUS_UnlockableImplementations = 0x050; // TMap<FName, UObject*>, stride 0x18
    constexpr uintptr_t UFUS_UnlockableConfigs         = 0x0A0; // TMap<FName, UObject*>, stride 0x18

    // APsPlayerState
    constexpr uintptr_t APsPS_ConductPoints            = 0x698;
    constexpr uintptr_t APsPS_ShiftPoints              = 0x69C;
    constexpr uintptr_t APsPS_ShiftPointsPerNbhd       = 0x6A8; // TMap<ENeighborhood, float>, stride 0x10
    constexpr uintptr_t APsPS_DistrictsProgress        = 0x750; // TArray<FDistrictProgress>, stride 0x20
    constexpr uintptr_t APsPS_PendingDistrict          = 0x760;
    constexpr uintptr_t APsPS_PendingDistrictXp        = 0x764;
    constexpr uintptr_t APsPS_PendingDutyStars         = 0x768;
    constexpr uintptr_t APsPS_FreeRoamProgress         = 0x780; // FFreeRoamProgress (0xC bytes)
    constexpr uintptr_t APsPS_PendingFreeRoamXp        = 0x790;
    constexpr uintptr_t APsPS_PendingBadgeLevel        = 0x794;

    // APsPlayerCharacter (Pawn)
    constexpr uintptr_t ACharacter_CharacterMovement   = 0x288;
    constexpr uintptr_t ACharacter_JumpMaxCount        = 0x344;
    constexpr uintptr_t ACharacter_JumpCurrentCount    = 0x348;
    constexpr uintptr_t APsChar_BalancingData          = 0x890;
    constexpr uintptr_t APsChar_ToolBalancingData      = 0x898;
    constexpr uintptr_t APsChar_FlashlightEnabled      = 0xB30;

    // UCharacterMovementComponent
    constexpr uintptr_t UCharMove_JumpZVelocity        = 0x158;
    constexpr uintptr_t UCharMove_MaxAcceleration      = 0x1A0;
    constexpr uintptr_t UCharMove_MaxAirControl        = 0x1C4;

    // ToolBalancingData offsets
    constexpr uintptr_t kToolOffsets[] = {
        0x048, // Handcuffs
        0x088, // Taser Ammo
        0x0B8, // Road Flares
        0x0D8, // Evidence Markers
        0x0F8, // Traffic Cones
        0x118, // Traffic Barriers
        0x138, // Spike Strips
        0x148, // Gun Ammo
        0x1A8, // Secure Poles
        0x1D8  // Fire Extinguisher
    };
}

struct FName {
    uint32_t ComparisonIndex;
    uint32_t Number;
};

#pragma pack(push, 1)
struct FUnlockableStateReplicationHelper {
    FName    UnlockableName; // +0x00
    uint8_t  bIsUnlocked;    // +0x08
    uint8_t  Pad[3];         // +0x09
};
static_assert(sizeof(FUnlockableStateReplicationHelper) == 0x0C);

struct FFreeRoamProgress {
    uint8_t  bIsEarlyFreeRoamUnlocked; // +0x00
    uint8_t  bIsUnlocked;              // +0x01
    uint8_t  Pad[2];                   // +0x02
    float    Xp;                       // +0x04
    int32_t  BadgeLevel;               // +0x08
};
static_assert(sizeof(FFreeRoamProgress) == 0x0C);
#pragma pack(pop)

using FnUnlockFeatureByTag = void(__fastcall*)(uintptr_t serviceInterface, const FName* name);
using FnUnlockDistrict     = void(__fastcall*)(uintptr_t playerState, uint8_t district, bool bSilent);
using FnSetDistrictXp      = void(__fastcall*)(uintptr_t playerState, uint8_t district, float xp, bool bForce);

} // namespace sdk
