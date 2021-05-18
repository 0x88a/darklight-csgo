#pragma once
#include "common.h"
#include "sdk/datatypes/vector.h"
#include "sdk/datatypes/qangle.h"
#include "sdk/datatypes/usercmd.h"
#include "sdk/entity.h"

namespace G
{
	inline HMODULE				hDll = nullptr;
	inline CBaseEntity*			pLocal = nullptr;
	inline CBaseCombatWeapon*	pWeapon = nullptr;
	inline CCSWeaponData*		pWeaponData = nullptr;
	inline CUserCmd*			pCmd = nullptr;
	inline bool					bSendPacket = true;
	inline QAngle				angRealView = { };
	inline QAngle				angStep = { };
	inline Vector				vecCamera = { };
	inline std::string			szUsername = { };
	inline bool					bTakingInput = false;
	inline CUserCmd				cmd;
	inline Vector2D				vecDisplaySize = {};
	inline int					iDPIScale = 0;
}
