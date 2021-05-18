#pragma once

#include "../common.h"
#include "../sdk/datatypes/usercmd.h"
#include "../sdk/entity.h"
#include "prediction.h"
#include "aimbot.h"

class CRagebot
{
public:
	void Run(CUserCmd* pCmd, CBaseEntity* pLocal, bool& bSendPacket);
	Vector GetBestHitbox(CBaseEntity* pEntity);
	AimbotTarget_t GetBestPlayer();
	void ClearRagebot();
	void WeaponSettings();
	void MoveViewAngles(AimbotTarget_t target);

	std::deque<Vector> MultipointHitboxes(CBaseEntity* pEntity, int iHitbox, float flHead, float flBody);
	bool Hitchance(CBaseEntity* pEntity, CBaseCombatWeapon* pWeapon, float flMinimum);

private:
	bool m_bEnable;
	bool m_bSilentAim;
	float m_flFOV;
	bool m_bMinimumDamage;
	float m_flMinimumDamage;
	float m_flHeadScale;
	float m_flBodyScale;
	float m_flHitchance;
	std::deque<bool> m_vecHitboxes;

	int m_iBestHitbox;
	float m_flBestDamage;

	CUserCmd* m_pCmd;
	CBaseEntity* m_pLocal;
	CBaseCombatWeapon* m_pLocalWeapon;
	CCSWeaponData* m_pWeaponData;
	Vector m_vLocalPosition;
	QAngle m_vEyeAngles;
	float m_flSimTime;
	std::vector<AimbotTarget_t> m_vTargets;
};

extern CRagebot g_Ragebot;