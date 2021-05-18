#pragma once
#include "../common.h"
#include "../sdk/datatypes/usercmd.h"
#include "../sdk/entity.h"
#include "../utilities.h"
#include <optional>

class CTriggerBot
{
public:
	void Run(CUserCmd* pCmd, CBaseEntity* pLocal);
	float AcceptedInaccuracy(CBaseCombatWeapon* pWeapon);
	bool Hitchance(CBaseEntity* pEntity, CBaseCombatWeapon* pWeapon, float flMinimum);

private:
	std::optional<Vector> IntersectionPoint(Vector&, Vector&, Vector&, Vector&, float);
	std::optional<int> TargetRecord(CBaseEntity*, CBaseCombatWeapon*, Vector&, Vector&);

	CTimer timer = {};
};

extern CTriggerBot g_Triggerbot;
