#pragma once

#include "../common.h"

#include "../sdk/datatypes/usercmd.h"
#include "../sdk/interfaces/igameeventmanager.h"
#include "../sdk/entity.h"
#include "prediction.h"

struct AimbotTarget_t
{
	CBaseEntity* pEntity = nullptr;
	float flFOV = 0.0f;
	QAngle angAngleTo = QAngle();
	Vector vHitboxPos = Vector();
};

class CAimbot
{
public:
	void Run(CUserCmd* pCmd, CBaseEntity* pLocal, bool& bSendPacket);

private:
	AimbotTarget_t GetBestPlayer();
	int GetNearestHitbox(CBaseEntity* pEntity);
	Vector GetBestHitbox(CBaseEntity* pEntity);
	void MoveViewAngles(AimbotTarget_t target);
	void RCS();
	void ClearAimbot();
	void WeaponSettings();

	float GetFOV();
	bool IsNotSilent(float);
	bool IsRCS();

	bool m_bEnable;
	bool m_bSilentAim;
	float m_flFOV;
	float m_flSilentFOV;
	int m_iHitboxSelection;
	float m_flRCS;
	float m_flSmoothing;
	
	CUserCmd* m_pCmd;
	CBaseEntity* m_pLocal;
	CBaseCombatWeapon* m_pLocalWeapon;
	CCSWeaponData* m_pWeaponData;
	Vector m_vLocalPosition;
	QAngle m_vEyeAngles;
	float m_flSimTime;

	std::vector<AimbotTarget_t> m_vTargets;
};

extern CAimbot g_Aimbot;