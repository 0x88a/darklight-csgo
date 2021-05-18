#include "backtrack.h"
#include "../utilities/math.h"
#include "../core/variables.h"
#include "../core/interfaces.h"
#include "../utilities.h"
#include "misc.h"

CBacktrack g_Backtrack;

void CBacktrack::Run(CUserCmd* pCmd, CBaseEntity* pLocal, bool& bSendPacket) {
	if (!C::Get<bool>(Vars.bBacktrack) ||
		!C::Get<int>(Vars.iBacktrackMax))
		return;

	QAngle angEyeAngles;
	I::Engine->GetViewAngles(angEyeAngles);

	auto flBestFOV = 180.0f;
	auto iBestIndex = -1;

	for (int i = 1; i < I::ClientEntityList->GetMaxEntities(); i++) {
		CBaseEntity* pEntity = I::ClientEntityList->Get<CBaseEntity>(i);
		if (!pEntity || !pEntity->IsPlayer() || pEntity->HasImmunity() ||
			pEntity->GetClientClass()->nClassID != EClassIndex::CCSPlayer)
			continue;
		
		if (pEntity->IsDormant() || !pEntity->IsAlive() || pEntity->HasImmunity() ||
			!pLocal->IsEnemy(pEntity))
			vRecords[i].clear();

		vRecords[i].insert(vRecords[i].begin(), { pEntity->GetHitboxPosition(HITBOX_HEAD), pEntity->GetHitboxPosition(HITBOX_CHEST), pEntity->GetSimulationTime() });
		vRecords[i].front().bIsValid = pEntity->SetupBones(vRecords[i].front().matrix, 128, 0x7FF00, I::Globals->flCurrentTime);

		if (vRecords[i].size() > 12)
			vRecords[i].pop_back();

		QAngle angCalc = M::CalcAngle(pLocal->GetEyePosition(), pEntity->GetHitboxPosition(HITBOX_HEAD));
		float flFOV = M::GetFOV(angEyeAngles, angCalc);
		if (flFOV < flBestFOV) 
		{
			flBestFOV = flFOV;
			iBestIndex = i;
		}
	}

	if (iBestIndex != -1 && pCmd->iButtons & IN_ATTACK) {
		if (vRecords[iBestIndex].empty()) { return; }

		float flBestSimTime = -1;
		float flBestNewFOV = 180.0f;

		auto backtrack = vRecords[iBestIndex];

		int iTicks = 0;
		for (auto i = 0; i < backtrack.size() && iTicks < C::Get<int>(Vars.iBacktrackMax); i++) {
			iTicks++; 

			QAngle angCalc = M::CalcAngle(pLocal->GetEyePosition(), backtrack.at(i).vHead);
			float flFOV = M::GetFOV(angEyeAngles, angCalc);
			if (flFOV < flBestNewFOV &&
				backtrack.at(i).bIsValid) {
				flBestNewFOV = flFOV;
				flBestSimTime = backtrack.at(i).flSimTime;
			}
		}

		if (flBestSimTime != -1) {
			pCmd->iTickCount = M_TIME_TO_TICKS(flBestSimTime);
		}
	}
}

bool CBacktrack::ValidTick(float flTime) {
	auto* netChannelInfo = I::Engine->GetNetChannelInfo();
	if (netChannelInfo == nullptr)
		return false;

	float correct = 0;

	correct += netChannelInfo->GetLatency(FLOW_OUTGOING);
	correct += netChannelInfo->GetLatency(FLOW_INCOMING);

	std::clamp(correct, 0.f, I::ConVar->FindVar(_("sv_maxunlag"))->GetFloat());

	auto const deltaTime = correct - (I::Globals->flCurrentTime - flTime);
	auto const timeLimit = std::clamp(M_TICKS_TO_TIME(C::Get<int>(Vars.iBacktrackMax)), 0.f, 0.2f);

	return fabsf(deltaTime) <= timeLimit;
}

float CBacktrack::LerpTime() {
	auto ratio = std::clamp(
		I::ConVar->FindVar(_("cl_interp_ratio"))->GetFloat(),
		I::ConVar->FindVar(_("sv_client_min_interp_ratio"))->GetFloat(),
		I::ConVar->FindVar(_("sv_client_max_interp_ratio"))->GetFloat());

	return M_MAX(
		I::ConVar->FindVar(_("cl_interp"))->GetFloat(),
		(ratio / ((I::ConVar->FindVar(_("sv_maxupdaterate"))) ?
			I::ConVar->FindVar(_("sv_maxupdaterate"))->GetFloat() :
			I::ConVar->FindVar(_("cl_updaterate"))->GetFloat())));
}