#include "ragebot.h"
#include "../utilities/math.h"
#include "../core/variables.h"
#include "../core/interfaces.h"
#include "../core/gui/gui.h"
#include "../utilities.h"
#include "backtrack.h"
#include "misc.h"
#include "entity_cache.h"
#include "autowall.h"

CRagebot g_Ragebot;

void CRagebot::Run(CUserCmd* pCmd, CBaseEntity* pLocal, bool& bSendPacket)
{
	ClearRagebot();

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

	short nDefinitionIndex = *m_pLocalWeapon->GetItemDefinitionIndex();
	m_pWeaponData = I::WeaponSystem->GetWeaponData(nDefinitionIndex);
	if (!m_pWeaponData || !m_pWeaponData->IsGun())
		return;

	WeaponSettings();

	if (!m_bEnable ||
		!GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iRagebotKey), C::Get<int>(Vars.iRagebotKeyMethod), &bToggled))
		return;

	m_vLocalPosition = m_pLocal->GetEyePosition();

	if (!m_pLocal->CanShoot((CWeaponCSBase*)m_pLocalWeapon))
		return;

	AimbotTarget_t target = GetBestPlayer();
	if (target.pEntity)
		MoveViewAngles(target);
}

bool CRagebot::Hitchance(CBaseEntity* pEntity, CBaseCombatWeapon* pWeapon, float flMinimum)
{
	static float flTraceAmount = 256.0f;
	const int iMinimumHits = (int)(256.0f * (flMinimum / 100.0f));
	const Vector vecStart = G::pLocal->GetEyePosition();
	int iCurrentHits = 0;

	QAngle qViewangles;
	I::Engine->GetViewAngles(qViewangles);

	const float flInaccuracy = pWeapon->GetInaccuracy(), flSpread = pWeapon->GetSpread();

	Vector vecEnd, vecForward;
	QAngle qShotAng;
	Trace_t trace;

	for (int i = 0; i < (int)flTraceAmount; i++)
	{
		M::RandomSeed(i);

		float multiplier1 = M::RandomFloat(0.f, 1.f);
		float angle1 = M::RandomFloat(0.f, M_2PI);

		float multiplier2 = M::RandomFloat(0.f, 1.f);
		float angle2 = M::RandomFloat(0.f, M_2PI);

		float spreadOffsetX = cos(angle1) * (multiplier1 * flInaccuracy) + cos(angle2) * (multiplier2 * flSpread);
		float spreadOffsetY = sin(angle1) * (multiplier1 * flInaccuracy) + sin(angle2) * (multiplier2 * flSpread);

		qShotAng = qViewangles + QAngle(spreadOffsetX, spreadOffsetY, 0);

		M::AngleVectors(qShotAng, &vecForward);

		vecEnd = vecStart + vecForward * m_pWeaponData->flRange;

		I::EngineTrace->ClipRayToEntity(Ray_t(vecStart, vecEnd), MASK_SHOT, pEntity, &trace);

		if (trace.pHitEntity == pEntity)
			iCurrentHits++;

		if (iMinimumHits >= iCurrentHits)
			return true;

		if (((int)flTraceAmount - i + iCurrentHits) < iMinimumHits)
			return false;
	}

	return false;
}

AimbotTarget_t CRagebot::GetBestPlayer()
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

		const QAngle angCalc = M::CalcAngle(m_vLocalPosition, vHitbox);
		const float flFOV = M::GetFOV(m_pCmd->angViewPoint, angCalc);
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
			if (i.flFOV < m_flFOV)
				return i;
	}

	return { };
}

Vector CRagebot::GetBestHitbox(CBaseEntity* pEntity)
{
	std::vector<int> vecHitboxes;
	Vector vecFinalPoint;

	float flDamage = m_flMinimumDamage;
	if (flDamage > 100)
		flDamage = pEntity->GetHealth() + (flDamage - 100);

	if (m_vecHitboxes[0])
		vecHitboxes.push_back(HITBOX_HEAD);

	if (m_vecHitboxes[1])
	{
		vecHitboxes.push_back(HITBOX_CHEST);
		vecHitboxes.push_back(HITBOX_UPPER_CHEST);
		vecHitboxes.push_back(HITBOX_THORAX);
	}

	if (m_vecHitboxes[2])
		vecHitboxes.push_back(HITBOX_STOMACH);

	if (m_vecHitboxes[3])
	{
		vecHitboxes.push_back(HITBOX_LEFT_UPPER_ARM);
		vecHitboxes.push_back(HITBOX_RIGHT_UPPER_ARM);
	}

	if (m_vecHitboxes[4])
		vecHitboxes.push_back(HITBOX_PELVIS);

	if (m_vecHitboxes[5])
	{
		vecHitboxes.push_back(HITBOX_LEFT_CALF);
		vecHitboxes.push_back(HITBOX_RIGHT_CALF);
	}

	if (m_vecHitboxes[6])
	{
		vecHitboxes.push_back(HITBOX_LEFT_FOOT);
		vecHitboxes.push_back(HITBOX_RIGHT_FOOT);
	}

	for (const int iHitbox : vecHitboxes)
	{
		for (const Vector vecPoint : MultipointHitboxes(pEntity, iHitbox, m_flHeadScale, m_flBodyScale))
		{
			float flCurDamage = g_AutoWall.GetDamage(G::pLocal, vecPoint);
			if (flCurDamage > flDamage)
			{
				m_iBestHitbox = iHitbox;
				m_flBestDamage = flCurDamage;
				vecFinalPoint = vecPoint;

				if (m_flBestDamage >= pEntity->GetHealth())
					return vecFinalPoint;
			}
		}
	}

	return vecFinalPoint;
}

std::deque<Vector> CRagebot::MultipointHitboxes(CBaseEntity* pEntity, int iHitbox, float flHeadScale, float flBodyScale)
{
	if (!pEntity->GetModel())
		return { };

	studiohdr_t* pStudioModel = I::ModelInfo->GetStudioModel(pEntity->GetModel());
	if (!pStudioModel)
		return { };

	mstudiohitboxset_t* pHitboxSet = pStudioModel->GetHitboxSet(0);
	if (!pHitboxSet)
		return { };

	mstudiobbox_t* pHitbox = pHitboxSet->GetHitbox(iHitbox);
	if (!pHitbox)
		return {};

	std::deque<Vector> vecArray;

	Vector vecMin, vecMax;

	vecMax = M::VectorTransform(pHitbox->vecBBMax, pEntity->GetBoneMatrix(pHitbox->iBone));
	vecMin = M::VectorTransform(pHitbox->vecBBMin, pEntity->GetBoneMatrix(pHitbox->iBone));

	const Vector vecCenter = (vecMin + vecMax) * 0.5f;

	const QAngle vecAngle = M::CalcAngle(vecCenter, G::pLocal->GetEyePosition());
	Vector vecForward;

	M::AngleVectors(vecAngle, &vecForward);

	const Vector vecTop = Vector(0, 0, 1);
	const Vector vecRight = vecForward.CrossProduct(Vector(0, 0, 1));
	const Vector vecLeft = Vector(-vecRight.x, -vecRight.y, vecRight.z);

	switch (iHitbox) {
	case HITBOX_HEAD:
		for (auto i = 0; i < 4; i++)
			vecArray.push_back(vecCenter);

		vecArray[0] += vecTop * (pHitbox->flRadius * flHeadScale / 100.f);
		vecArray[1] += vecRight * (pHitbox->flRadius * flHeadScale / 100.f);
		vecArray[2] += vecLeft * (pHitbox->flRadius * flHeadScale / 100.f);
		break;

	default:
		for (auto i = 0; i < 4; i++)
			vecArray.push_back(vecCenter);

		vecArray[0] += vecTop * (pHitbox->flRadius * flBodyScale / 100.f);
		vecArray[1] += vecRight * (pHitbox->flRadius * flBodyScale / 100.f);
		vecArray[2] += vecLeft * (pHitbox->flRadius * flBodyScale / 100.f);
		break;
	}

	return vecArray;
}

void CRagebot::ClearRagebot()
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

void CRagebot::WeaponSettings()
{
	const auto iWeaponIndex = *m_pLocalWeapon->GetItemDefinitionIndex();
	const auto iWeaponType = m_pWeaponData->nWeaponType;
	auto iElement = -1;

	if (iWeaponType == WEAPONTYPE_PISTOL &&
		iWeaponIndex != WEAPON_DEAGLE && iWeaponIndex != WEAPON_REVOLVER &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(1))
		iElement = 1;
	else if (iWeaponType == WEAPONTYPE_PISTOL &&
		(iWeaponIndex == WEAPON_DEAGLE || iWeaponIndex == WEAPON_REVOLVER) &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(2))
		iElement = 2;
	else if (iWeaponType == WEAPONTYPE_RIFLE &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(3))
		iElement = 3;
	else if (iWeaponType == WEAPONTYPE_SHOTGUN &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(4))
		iElement = 4;
	else if (iWeaponType == WEAPONTYPE_SUBMACHINEGUN &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(5))
		iElement = 5;
	else if (iWeaponType == WEAPONTYPE_MACHINEGUN &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(6))
		iElement = 6;
	else if (iWeaponIndex == WEAPON_SCAR20 || iWeaponIndex == WEAPON_G3SG1 &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(7))
		iElement = 7;
	else if (iWeaponIndex == WEAPON_SSG08 &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(8))
		iElement = 8;
	else if (iWeaponIndex == WEAPON_AWP &&
		C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(9))
		iElement = 9;
	else if (C::Get<std::deque<bool>>(Vars.vecRagebotWeaponEnabled).at(0))
		iElement = 0;

	if (iElement != -1)
	{
		m_bEnable = C::Get<bool>(Vars.bRagebotEnabled);
		m_bSilentAim = C::Get<std::deque<bool>>(Vars.vecRagebotSilentEnable).at(iElement);
		m_flFOV = C::Get<std::deque<float>>(Vars.vecRagebotRegularFOV).at(iElement);
		m_bMinimumDamage = C::Get<std::deque<bool>>(Vars.vecRagebotMindamage).at(iElement);
		m_flMinimumDamage = C::Get<std::deque<float>>(Vars.vecRagebotMindamageValue).at(iElement);
		m_flHeadScale = C::Get<std::deque<float>>(Vars.vecRagebotMultipointHead).at(iElement);
		m_flBodyScale = C::Get<std::deque<float>>(Vars.vecRagebotMultipointBody).at(iElement);
		m_flHitchance = C::Get<std::deque<float>>(Vars.vecRagebotHitchance).at(iElement);
		m_vecHitboxes = Vars.vecRagebotHitboxes[iElement];
	}
}

void CRagebot::MoveViewAngles(AimbotTarget_t target)
{
	QAngle angDest = target.angAngleTo;

	static auto pWeaponRecoilScale = I::ConVar->FindVar(_("weapon_recoil_scale"));
	if (Hitchance(target.pEntity, m_pLocalWeapon, m_flHitchance))
	{
		angDest -= m_pLocal->GetPunch() * pWeaponRecoilScale->GetFloat();
		angDest.Clamp();

		m_pCmd->angViewPoint = angDest;

		if (!m_bSilentAim)
			I::Engine->SetViewAngles(m_pCmd->angViewPoint);

		m_pCmd->iButtons |= IN_ATTACK;
	}
}