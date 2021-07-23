#include "aimbot.h"
#include "../utilities/math.h"
#include "../core/variables.h"
#include "../core/interfaces.h"
#include "../core/gui/gui.h"
#include "../utilities.h"
#include "backtrack.h"
#include "misc.h"

CAimbot g_Aimbot;

QAngle angOldAng;

void CAimbot::Run(CUserCmd* pCmd, CBaseEntity* pLocal, bool& bSendPacket)
{
	ClearAimbot();

	static bool bToggled = false;

	m_pCmd = pCmd;
	if (!m_pCmd)
		return;

	m_pLocal = pLocal;
	if (!m_pLocal || !m_pLocal->IsAlive())
		return;

	m_pLocalWeapon = m_pLocal->GetWeapon();
	if (!m_pLocalWeapon)
		return;

	if (!(m_pCmd->iButtons & IN_ATTACK))
		angOldAng.x = angOldAng.y = angOldAng.z = 0;

	short nDefinitionIndex = *m_pLocalWeapon->GetItemDefinitionIndex();
	m_pWeaponData = I::WeaponSystem->GetWeaponData(nDefinitionIndex);
	if (!m_pWeaponData || !m_pWeaponData->IsGun())
		return;

	WeaponSettings();

	if (!m_bEnable ||
		!GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iAimbotKey), C::Get<int>(Vars.iAimbotKeyMethod), &bToggled))
		return;

	m_vLocalPosition = m_pLocal->GetEyePosition();

	if (!m_pLocal->CanShoot((CWeaponCSBase*)m_pLocalWeapon))
		return;

	if (m_flRCS > 0)
		RCS();

	AimbotTarget_t target = GetBestPlayer();
	if (target.pEntity)
		MoveViewAngles(target);
}

float CAimbot::GetFOV()
{
	return !m_bSilentAim ? m_flFOV : m_flSilentFOV > m_flFOV ? m_flSilentFOV : m_flFOV;
}

bool CAimbot::IsRCS()
{
	return m_pLocal->GetShotsFired() > 1;
}

bool CAimbot::IsNotSilent(float flFOV)
{
	return (IsRCS() && (m_flRCS) || !m_bSilentAim || (m_bSilentAim && flFOV > m_flSilentFOV));
}

AimbotTarget_t CAimbot::GetBestPlayer()
{
	for (int i = 1; i < I::Globals->nMaxClients; i++)
	{
		CBaseEntity* pEntity = I::ClientEntityList->Get<CBaseEntity>(i);
		if (!pEntity || !pEntity->IsAlive() || pEntity->IsDormant())
			continue;

		if (!m_pLocal->IsEnemy(pEntity) || !pEntity->IsPlayer() || pEntity->HasImmunity())
			continue;

		Vector vHitbox = GetBestHitbox(pEntity);
		if (vHitbox.IsZero())
			continue;

		static auto pWeaponRecoilScale = I::ConVar->FindVar(_("weapon_recoil_scale"));

		QAngle angCalc = M::CalcAngle(m_vLocalPosition, vHitbox);
		float flFOV = M::GetFOV(m_pCmd->angViewPoint + m_pLocal->GetPunch() * pWeaponRecoilScale->GetFloat(), angCalc);
		
		m_vTargets.push_back({ pEntity, flFOV, angCalc, vHitbox });
	}

	if (m_vTargets.empty())
		return { };

	std::sort(m_vTargets.begin(), m_vTargets.end(), [](const AimbotTarget_t& a, const AimbotTarget_t& b) -> bool {
		return a.flFOV < b.flFOV;
	});

	for (auto& i : m_vTargets)
	{
		if (i.pEntity && !i.angAngleTo.IsZero())
		{
			if (i.flFOV < GetFOV())
				return i;
		}
	}

	return { };
}

int CAimbot::GetNearestHitbox(CBaseEntity* pEntity)
{
	int iBestHitbox = -1;
	auto flBestFOV = 180.0f;

	for (auto i = 0; i < HITBOX_MAX; i++)
	{
		Vector vHitbox = pEntity->GetHitboxPosition(i);
		if (vHitbox.IsZero())
			continue;

		QAngle angCalc = M::CalcAngle(m_vLocalPosition, vHitbox);
		float flFOV = M::GetFOV(m_pCmd->angViewPoint + m_pLocal->GetPunch() * 2.0f, angCalc);
		if (flFOV < flBestFOV)
		{
			flBestFOV = flFOV;
			iBestHitbox = i;
		}
	}

	return iBestHitbox;
}

Vector CAimbot::GetBestHitbox(CBaseEntity* pEntity)
{
	Vector vecReturn;
	int iBestHitbox = -1;
	float flBestFOV = 180.0f;
	float flBestSimTime = -1;

	switch (m_iHitboxSelection)
	{
	case 0:
		iBestHitbox = HITBOX_HEAD;
		break;
	case 1:
		iBestHitbox = HITBOX_CHEST;
		break;
	case 2:
		iBestHitbox = HITBOX_PELVIS;
		break;
	case 3:
		iBestHitbox = this->GetNearestHitbox(pEntity);
		break;
	default:
		break;
	}

	vecReturn = pEntity->GetHitboxPosition(iBestHitbox);

	//if (!g_Backtrack.vRecords[pEntity->GetIndex()].empty() &&
	//	C::Get<bool>(Vars.bBacktrack))
	//{
	//	auto vecBacktrack = g_Backtrack.vRecords[pEntity->GetIndex()];

	//	int iTicks = 0;
	//	for (auto i = 0; i < vecBacktrack.size() && iTicks < C::Get<int>(Vars.iBacktrackMax); i++) {
	//		iTicks++;

	//		Vector vecBacktrackHitbox = pEntity->GetBacktrackHitboxPosition(iBestHitbox, i);
	//		if (vecBacktrackHitbox.IsZero())
	//			continue;

	//		QAngle angCalc = M::CalcAngle(m_vLocalPosition, vecBacktrackHitbox);
	//		float flFOV = M::GetFOV(m_pCmd->angViewPoint + m_pLocal->GetPunch() * 2.0f, angCalc);

	//		if (flFOV < flBestFOV && vecBacktrack.at(i).bIsValid) {
	//			flBestFOV = flFOV;
	//			flBestSimTime = vecBacktrack.at(i).flSimTime;
	//			vecReturn = vecBacktrackHitbox;
	//		}
	//	}

	//	m_flSimTime = flBestSimTime;
	//}

	return m_pLocal->IsVisible(pEntity, vecReturn) ? vecReturn : Vector();
}


void CAimbot::MoveViewAngles(AimbotTarget_t target)
{
	QAngle angDest = target.angAngleTo;
	QAngle angSrc = m_pCmd->angViewPoint;

	if (m_flRCS > 0 && IsNotSilent(target.flFOV))
		angDest -= m_pLocal->GetPunch() * m_flRCS / 50.0f;

	QAngle angDelta = angSrc - angDest;
	angDelta.Clamp();

	if (!angDelta.IsZero())
	{
		if (IsNotSilent(target.flFOV))
			angDest = angSrc - angDelta / m_flSmoothing;
	}

	angDest.Clamp();

	m_pCmd->angViewPoint = angDest;

	if (IsNotSilent(target.flFOV))
		I::Engine->SetViewAngles(m_pCmd->angViewPoint);

	//if (m_pCmd->iButtons & IN_ATTACK && m_flSimTime != -1 &&
	//	C::Get<bool>(Vars.bBacktrack)) {
	//	/*m_pCmd->iTickCount = M_TIME_TO_TICKS(m_flSimTime);*/
	//}
}

void CAimbot::RCS()
{
	static auto pWeaponRecoilScale = I::ConVar->FindVar(_("weapon_recoil_scale"));

	if (m_pCmd->iButtons & IN_ATTACK) 
	{
		QAngle angPunch = m_pLocal->GetPunch() * pWeaponRecoilScale->GetFloat();

		m_pCmd->angViewPoint += (angOldAng - angPunch);

		angOldAng = angPunch;
	}
}

void CAimbot::ClearAimbot()
{
	if (!m_vTargets.empty())
		m_vTargets.clear();

	m_pCmd = nullptr;
	m_pLocal = nullptr;
	m_pLocalWeapon = nullptr;
	m_pWeaponData = nullptr;
	m_vLocalPosition = Vector();
	m_vEyeAngles = QAngle();
}

void CAimbot::WeaponSettings()
{
	const auto iWeaponIndex = *m_pLocalWeapon->GetItemDefinitionIndex();
	const auto iWeaponType = m_pWeaponData->nWeaponType;
	auto iElement = -1;

	if (iWeaponType == WEAPONTYPE_PISTOL &&
		iWeaponIndex != WEAPON_DEAGLE && iWeaponIndex != WEAPON_REVOLVER &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(1))
		iElement = 1;
	else if (iWeaponType == WEAPONTYPE_PISTOL &&
		(iWeaponIndex == WEAPON_DEAGLE || iWeaponIndex == WEAPON_REVOLVER) &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(2))
		iElement = 2;
	else if (iWeaponType == WEAPONTYPE_RIFLE &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(3))
		iElement = 3;
	else if (iWeaponType == WEAPONTYPE_SHOTGUN &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(4))
		iElement = 4;
	else if (iWeaponType == WEAPONTYPE_SUBMACHINEGUN &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(5))
		iElement = 5;
	else if (iWeaponType == WEAPONTYPE_MACHINEGUN &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(6))
		iElement = 6;
	else if (iWeaponIndex == WEAPON_SCAR20 || iWeaponIndex == WEAPON_G3SG1 &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(7))
		iElement = 7;
	else if (iWeaponIndex == WEAPON_SSG08 &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(8))
		iElement = 8;
	else if (iWeaponIndex == WEAPON_AWP &&
		C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(9))
		iElement = 9;
	else if (C::Get<std::deque<bool>>(Vars.vecWeaponEnabled).at(0))
		iElement = 0;

	if (iElement != -1 )
	{
		m_bEnable = C::Get<std::deque<bool>>(Vars.vecEnable).at(iElement);
		m_bSilentAim = C::Get<std::deque<bool>>(Vars.vecSilentEnable).at(iElement);
		m_flFOV = C::Get<std::deque<float>>(Vars.vecRegularFOV).at(iElement);
		m_flSilentFOV = C::Get<std::deque<float>>(Vars.vecSilentFOV).at(iElement);
		m_iHitboxSelection = C::Get<std::deque<int>>(Vars.vecHitboxSelection).at(iElement);
		m_flRCS = C::Get<std::deque<float>>(Vars.vecRCS).at(iElement);
		m_flSmoothing = C::Get<std::deque<float>>(Vars.vecSmoothing).at(iElement);
	}
}