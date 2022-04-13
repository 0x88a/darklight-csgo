#include <random>
#include <algorithm>

#include "misc.h"
#include "../global.h"
#include "../core/variables.h"
#include "../core/interfaces.h"
#include "../utilities/math.h"
#include "../utilities.h"
#include "../core/gui/gui.h"
#include "prediction.h"

CMiscellaneous g_Misc;

void CMiscellaneous::Run(CUserCmd* pCmd, CBaseEntity* pLocal, bool& bSendPacket)
{
	MouseDelta(pCmd, pLocal);
	ClantagChanger(pCmd, pLocal);
	RankReveal(pCmd, pLocal);

	if (pLocal->IsAlive())
	{
		Bunnyhop(pCmd, pLocal);
		InfiniteDuck(pCmd, pLocal);
		AutoPistol(pCmd, pLocal);
	}
}

void CMiscellaneous::InfiniteDuck(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	if (!C::Get<bool>(Vars.bFastDuck))
		return;

	pCmd->iButtons |= IN_BULLRUSH;
}

void CMiscellaneous::MovementRecorder(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	bool is_playback_active = playback.IsPlaybackActive();
	bool is_recording_active = recorder.IsRecordingActive();

	FrameContainer& recording = recorder.GetActiveRecording();

	bool is_rerecording_active = recorder.IsRerecordingActive();
	FrameContainer& rerecording = recorder.GetActiveRerecording();

	if (is_recording_active)
		recording.push_back({ pCmd });
	else if (is_rerecording_active)
		rerecording.push_back({ pCmd });

	if (is_playback_active) {
		Vector vecCurrentPosition = G::pLocal->GetOrigin();
		QAngle angCurrentAngle = G::pCmd->angViewPoint;

		if (!g_Misc.m_bPreparedOrigin || !g_Misc.m_bPreparedViewAngs)
		{
			const float flDist = vecCurrentPosition.DistTo(recorder.vecStartingPosition);
			if (flDist >= 1.0f) {
				g_Misc.m_bMoveViewAngs = false;

				QAngle angWish;
				M::VectorAngles((recorder.vecStartingPosition - vecCurrentPosition), angWish);

				G::pCmd->angViewPoint = angWish;
				I::Engine->SetViewAngles(pCmd->angViewPoint);

				G::cmd.flForwardMove = flDist;
			}
			else if (flDist < 1.0f)
			{
				g_Misc.m_bPreparedOrigin = true;
				g_Misc.m_bPreparedViewAngs = true;
			}

			if (g_Misc.m_bMoveViewAngs)
			{
				QAngle angDelta = (angCurrentAngle - recorder.angStartingAngle);
				angDelta.Clamp();

				QAngle angWish = angCurrentAngle - angDelta / 16.0f;
				angWish.Clamp();

				Vector vecDelta;
				M::AngleVectors(angDelta, &vecDelta);

				Vector vecStartingAng;
				M::AngleVectors(recorder.angStartingAngle, &vecStartingAng);

				Vector vecWish;
				M::AngleVectors(angWish, &vecWish);

				const float flAngDist = vecDelta.DistTo(vecWish);

				if (flAngDist > 0.75f)
				{
					g_Misc.m_bPreparedViewAngs = false;

					G::pCmd->angViewPoint = angWish;
					I::Engine->SetViewAngles(pCmd->angViewPoint);
				}
				else if (flAngDist < 0.75f)
				{
					g_Misc.m_bPreparedViewAngs = true;
					g_Misc.m_bMoveViewAngs = false;
				}
			}
		}
		
		if (g_Misc.m_bPreparedOrigin && g_Misc.m_bPreparedViewAngs)
		{
			const size_t current_playback_frame = playback.GetCurrentFrame();

			if (pCmd->iButtons != 0) {
				recorder.StartRerecording(current_playback_frame);
				playback.StopPlayback();
				g_Misc.m_bPreparedOrigin = false;
				g_Misc.m_bPreparedViewAngs = false;
				g_Misc.m_bMoveViewAngs = false;
				return;
			}

			try {
				recording.at(current_playback_frame).Replay(pCmd);
				I::Engine->SetViewAngles(pCmd->angViewPoint);

				if (current_playback_frame + 1 == recording.size())
				{
					playback.StopPlayback();
					g_Misc.m_bPreparedOrigin = false;
					g_Misc.m_bPreparedViewAngs = false;
					g_Misc.m_bMoveViewAngs = false;
				}
				else
					playback.SetCurrentFrame(current_playback_frame + 1);
			}
			catch (std::out_of_range) {
				playback.StopPlayback();
			}
		}
	}
}

void CMiscellaneous::AutoPistol(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	if (!C::Get<bool>(Vars.bAutoShoot))
		return;

	const auto pWeapon = pLocal->GetWeapon();
	if (!pWeapon)
		return;

	const auto pWeaponData = I::WeaponSystem->GetWeaponData(*pWeapon->GetItemDefinitionIndex());
	if (!pWeaponData)
		return;

	if (pWeaponData->nWeaponType != WEAPONTYPE_PISTOL ||
		*pWeapon->GetItemDefinitionIndex() == WEAPON_REVOLVER)
		return;

	if ((pWeapon->GetNextPrimaryAttack() -
		(pLocal->GetTickBase() * I::Globals->flIntervalPerTick) > 0))
		pCmd->iButtons &= ~IN_ATTACK;
}

void CMiscellaneous::RankReveal(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	if (!(C::Get<std::deque<bool>>(Vars.vecMatchmaking).at(3) && pCmd->iButtons & IN_SCORE))
		return;

	I::Client->DispatchUserMessage(CS_UM_ServerRankRevealAll, 0U, 0, nullptr);
}

void CMiscellaneous::JumpBug(CUserCmd* pCmd, CBaseEntity* pLocal, int iFlags)
{
	m_bJumpbugging = false;

	static bool bToggled = false;
	if (!C::Get<bool>(Vars.bJumpBug) ||
		!GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iJumpBugKey), C::Get<int>(Vars.iJumpBugKeyMethod), &bToggled))
		return;

	m_bJumpbugging = true;
	if (pLocal->GetFlags() & FL_ONGROUND)
	{
		pCmd->iButtons &= ~IN_JUMP;
		if (!(iFlags & FL_ONGROUND))
			pCmd->iButtons |= IN_DUCK;
	}
}

void CMiscellaneous::EdgeBug(CUserCmd* pCmd, CBaseEntity* pLocal, int iFlags)
{
	static bool bToggled = false;
	if (!C::Get<bool>(Vars.bEdgeBug) ||
		!GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iEdgeBugKey), C::Get<int>(Vars.iEdgeBugKeyMethod), &bToggled))
		return;

	if ((pLocal->GetFlags() & FL_ONGROUND) &&
		!(iFlags & FL_ONGROUND))
		pCmd->iButtons |= IN_DUCK;
}

void CMiscellaneous::EdgeJump(CUserCmd* pCmd, CBaseEntity* pLocal, int iFlags)
{
	static bool bToggled = false;
	if (!C::Get<bool>(Vars.bEdgeJump) ||
		!GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iEdgeJumpKey), C::Get<int>(Vars.iEdgeJumpKeyMethod), &bToggled))
		return;

	if (!(pLocal->GetFlags() & FL_ONGROUND) &&
		(iFlags & FL_ONGROUND))
		pCmd->iButtons |= IN_JUMP;
}

void CMiscellaneous::Bunnyhop(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	static CConVar* sv_autobunnyhopping = I::ConVar->FindVar(_("sv_autobunnyhopping"));
	if (sv_autobunnyhopping->GetBool() || !C::Get<int>(Vars.iBunnyHop) || m_bJumpbugging)
		return;

	if (pLocal->GetMoveType() == MOVETYPE_LADDER || pLocal->GetMoveType() == MOVETYPE_NOCLIP || pLocal->GetMoveType() == MOVETYPE_OBSERVER)
		return;

	static float flHitchance, flMax = 0;
	if (C::Get<int>(Vars.iBunnyHop) == 2)
	{
		flHitchance = C::Get<float>(Vars.flBunnyhopHitchance);
		flMax = 0;
	}
	else
		flHitchance = 100, flMax = 0;

	static int hops_hit = 0;
	if (!(pCmd->iButtons & IN_JUMP) ||
		flHitchance <= 0)
		return;

	if (!(pLocal->GetFlags() & FL_ONGROUND))
		pCmd->iButtons &= ~IN_JUMP;
	else if (
		(rand() % 100 > flHitchance) ||
		(flMax > 0 && hops_hit > flMax))
	{
		pCmd->iButtons &= ~IN_JUMP;
		hops_hit = 0;
	}
	else
		hops_hit++;
}

void CMiscellaneous::NullStrafe(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	if (!C::Get<bool>(Vars.bNullStrafe) || !pLocal ||
		pLocal->GetFlags() & FL_ONGROUND)
		return;

	if (pCmd->sMouseDeltaX > 0 && pCmd->iButtons & IN_MOVERIGHT && pCmd->iButtons & IN_MOVELEFT)
		G::cmd.flSideMove = -450.f;
	else if (pCmd->sMouseDeltaX < 0 && pCmd->iButtons & IN_MOVELEFT && pCmd->iButtons & IN_MOVERIGHT)
		G::cmd.flSideMove = 450.f;
}

void CMiscellaneous::Blockbot(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	static bool bToggled = false;
	if (!C::Get<int>(Vars.iBlockbot) ||
		!GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iBlockbotKey), C::Get<int>(Vars.iBlockbotKeyMethod), &bToggled))
		return;

	float flBestDistance = 250.0f;
	int iBestIndex = -1;
	for (auto i = 1; i < I::Globals->nMaxClients; i++) {
		CBaseEntity* pEntity = I::ClientEntityList->Get<CBaseEntity>(i);
		if (!pEntity || pEntity->IsDormant() || !pEntity->IsAlive() ||
			pEntity == G::pLocal)
			continue;

		float flDistance = pLocal->GetOrigin().DistTo(pEntity->GetOrigin());
		if (flDistance < flBestDistance)
		{
			flBestDistance = flDistance;
			iBestIndex = i;
		}
	}

	CBaseEntity* pEntity = I::ClientEntityList->Get<CBaseEntity>(iBestIndex);
	if (!pEntity)
		return;

	float flBestSpeed = C::Get<int>(Vars.iBlockbot) == 1 ? pEntity->GetVelocity().Length() : 450.0f;

	QAngle angLocal;
	I::Engine->GetViewAngles(angLocal);

	Vector vecForward = pEntity->GetOrigin() - pLocal->GetOrigin();
	if (pEntity->GetHitboxPosition(6).z < pLocal->GetOrigin().z && pLocal->GetOrigin().DistTo(pEntity->GetOrigin()) < 100.0f)
	{
		G::cmd.flForwardMove = ((sin(DEG2RAD(angLocal.y)) * vecForward.y) + (cos(DEG2RAD(angLocal.y)) * vecForward.x)) * flBestSpeed;
		G::cmd.flSideMove = ((cos(DEG2RAD(angLocal.y)) * -vecForward.y) + (sin(DEG2RAD(angLocal.y)) * vecForward.x)) * flBestSpeed;
	}
	else
	{
		auto yaw_delta = (atan2(vecForward.y, vecForward.x) * 180.0f / M_PI) - angLocal.y;
		if (yaw_delta > 180) { yaw_delta -= 360; }
		else if (yaw_delta < -180) { yaw_delta += 360; }
		if (yaw_delta > 0.25) { G::cmd.flSideMove = -flBestSpeed; }
		else if (yaw_delta < -0.25) { G::cmd.flSideMove = flBestSpeed; }
	}
}
void CMiscellaneous::StrafeOptimizer(CUserCmd* cmd, CBaseEntity* pLocal)
{
	static bool bToggled = false;
	if (!C::Get<bool>(Vars.bStrafeOptimizer_Enabeld) ||
		!GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iStrafeOptimizer_Key), C::Get<int>(Vars.iStrafeOptimizer_Key_Method), &bToggled))
		return;

	static auto m_yaw = I::ConVar->FindVar(_("m_yaw"));

	static auto sensitivity = I::ConVar->FindVar(_("sensitivity"));

	static float Previous_View_Angles_Y = cmd->angViewPoint.y;

	{
		if (cmd->flForwardMove == 0 && cmd->iButtons & IN_JUMP) if (auto Velocity = pLocal->GetVelocity(); Velocity.Length2D() > C::Get<int>(Vars.iStrafeOptimizer_Min_Speed))
		{
			I::Prediction->Update(I::ClientState->iDeltaTick,
				I::ClientState->iDeltaTick > 0, I::ClientState->nLastCommandAck,
				I::ClientState->nLastOutgoingCommand + I::ClientState->iChokedCommands);

			float Mouse_Yaw_Factor = m_yaw->GetFloat();

			float Mouse_Sensitivity = sensitivity->GetFloat();

			float Mouse_Yaw_Step = Mouse_Sensitivity * Mouse_Yaw_Factor;

			if (cmd->flSideMove < 0)
			{
				if (Previous_View_Angles_Y - cmd->angViewPoint[1] < 0)
				{
					float Strafe_Angle = remainderf(cmd->angViewPoint[1] - atan2f(Velocity[1], Velocity[0]) * 180 / M_PI, 360) * C::Get<int>(Vars.iStrafeOptimizer_Desired_Gain) / 100;

					if (Strafe_Angle < -Mouse_Yaw_Step)
					{
						if (Strafe_Angle < -180)
						{
							Strafe_Angle = -180;
						}

						cmd->angViewPoint[1] = remainderf(cmd->angViewPoint[1] - Mouse_Yaw_Step * roundf(Strafe_Angle / Mouse_Yaw_Step), 360);

						cmd->sMouseDeltaX = (__int16)(Mouse_Sensitivity * ceilf(remainderf(Previous_View_Angles_Y - cmd->angViewPoint[1], 360) / sqrtf(Mouse_Yaw_Step)));

						I::Engine->SetViewAngles(cmd->angViewPoint);
					}
				}
			}
			else
			{
				if (cmd->flSideMove > 0)
				{
					if (Previous_View_Angles_Y - cmd->angViewPoint[1] > 0)
					{
						float Strafe_Angle = remainderf(cmd->angViewPoint[1] - atan2f(Velocity[1], Velocity[0]) * 180 / M_PI, 360) * C::Get<int>(Vars.iStrafeOptimizer_Desired_Gain)/ 100;

						if (Strafe_Angle > Mouse_Yaw_Step)
						{
							if (Strafe_Angle > 180)
							{
								Strafe_Angle = 180;
							}

							cmd->angViewPoint[1] = remainderf(cmd->angViewPoint[1] - Mouse_Yaw_Step * roundf(Strafe_Angle / Mouse_Yaw_Step), 360);

							cmd->sMouseDeltaX = (__int16)(Mouse_Sensitivity * ceilf(remainderf(Previous_View_Angles_Y - cmd->angViewPoint[1], 360) / sqrtf(Mouse_Yaw_Step)));

							I::Engine->SetViewAngles(cmd->angViewPoint);
						}
					}
				}
			}
		}

		Previous_View_Angles_Y = cmd->angViewPoint[1];
	}
}
void CMiscellaneous::MiniJump(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	static bool bToggled = false;
	if (!C::Get<bool>(Vars.bMiniJump) ||
		!GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iMiniJump_Key), C::Get<int>(Vars.iMiniJump_Key_Method), &bToggled))
		return;
	if (!pLocal || !pLocal->IsAlive())
		return;
	if (const auto mt = pLocal->GetMoveType(); mt == MOVETYPE_LADDER|| mt == MOVETYPE_NOCLIP)
		return;
	static int minijump_tick = 0;
	static bool minijumpbool = false;
	if ((pLocal->GetFlags() & 1) && !(pLocal->GetFlags() & 1))
	{
		pCmd->iButtons |= IN_JUMP;
		minijumpbool = true;
		minijump_tick = pCmd->iTickCount + 1;
	}
	if (minijumpbool)
	{
		if (pCmd->iTickCount < minijump_tick)
		{
			pCmd->iButtons |= IN_DUCK;
			I::Engine->ClientCmd_Unrestricted(_("-forward"));
			pCmd->iButtons &= ~IN_BACK;
		}
	}
}
void CMiscellaneous::MouseDelta(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	static QAngle angDeltaAngles;
	QAngle angDelta = pCmd->angViewPoint - angDeltaAngles;
	angDelta.Clamp();

	static auto pSensitivity = I::ConVar->FindVar(_("sensitivity"));
	if (!pSensitivity)
		return;

	if (angDelta.x != 0.f) {
		static auto pPitch = I::ConVar->FindVar(_("m_pitch"));
		if (!pPitch)
			return;

		int iFinalDeltaY = (int)((angDelta.x / pPitch->GetFloat()) / pSensitivity->GetFloat());
		if (iFinalDeltaY <= 32767) {
			if (iFinalDeltaY >= -32768) {
				if (iFinalDeltaY >= 1 || iFinalDeltaY < 0) {
					if (iFinalDeltaY <= -1 || iFinalDeltaY > 0)
						iFinalDeltaY = iFinalDeltaY;
					else
						iFinalDeltaY = -1;
				}
				else
					iFinalDeltaY = 1;
			}
			else
				iFinalDeltaY = 32768;
		}
		else
			iFinalDeltaY = 32767;

		pCmd->sMouseDeltaY = (short)iFinalDeltaY;
	}

	if (angDelta.y != 0.f) {
		static auto pYaw = I::ConVar->FindVar(_("m_yaw"));
		if (!pYaw)
			return;

		int iFinalDeltaX = (int)((angDelta.y / pYaw->GetFloat()) / pSensitivity->GetFloat());
		if (iFinalDeltaX <= 32767) {
			if (iFinalDeltaX >= -32768) {
				if (iFinalDeltaX >= 1 || iFinalDeltaX < 0) {
					if (iFinalDeltaX <= -1 || iFinalDeltaX > 0)
						iFinalDeltaX = iFinalDeltaX;
					else
						iFinalDeltaX = -1;
				}
				else
					iFinalDeltaX = 1;
			}
			else
				iFinalDeltaX = 32768;
		}
		else
			iFinalDeltaX = 32767;

		pCmd->sMouseDeltaX = (short)iFinalDeltaX;
	}

	angDeltaAngles = pCmd->angViewPoint;
}

void CMiscellaneous::CorrectMovement(CBaseEntity* pLocal, CUserCmd* pCmd, QAngle& angOldViewPoint)
{
	pCmd->angViewPoint.Normalize();
	pCmd->angViewPoint.Clamp();

	Vector vecForward, vecRight, vecUp, vecForwardOld, vecRightOld, vecUpOld;
	M::AngleVectors(G::cmd.angViewPoint, &vecForward, &vecRight, &vecUp);
	M::AngleVectors(angOldViewPoint, &vecForwardOld, &vecRightOld, &vecUpOld);

	Vector vecMoveData = { G::cmd.flForwardMove, G::cmd.flSideMove, G::cmd.flUpMove };
	if (!(pLocal->GetFlags() & FL_ONGROUND) && angOldViewPoint.z != 0.0f)
		vecMoveData.y = 0.0f;

	const float flFwdLenght = vecForward.Length2D();
	const float flRightLenght = vecRight.Length2D();
	const float flUpLenght = std::sqrtf(vecUp.z * vecUp.z);

	const Vector vecNormFwd = Vector(1.f / flFwdLenght * vecForward.x, 1.f / flFwdLenght * vecForward.y, 0.f);
	const Vector vecNormRight = Vector(1.f / flRightLenght * vecRight.x, 1.f / flRightLenght * vecRight.y, 0.f);
	const Vector vecNormUp = Vector(0.f, 0.f, 1.f / flUpLenght * vecUp.z);

	const float flFwdOldLenght = vecForwardOld.Length2D();
	const float flRightOldLenght = vecRightOld.Length2D();
	const float flUpOldLenght = std::sqrtf(vecUpOld.z * vecUpOld.z);

	const Vector vecNormFwdOld(1.f / flFwdOldLenght * vecForwardOld.x, 1.f / flFwdOldLenght * vecForwardOld.y, 0.f);
	const Vector vecNormRightOld(1.f / flRightOldLenght * vecRightOld.x, 1.f / flRightOldLenght * vecRightOld.y, 0.f);
	const Vector vecNormUpOld(0.f, 0.f, 1.f / flUpOldLenght * vecUpOld.z);

	const auto
		v22 = vecNormFwd.x * vecMoveData.x,
		v26 = vecNormFwd.y * vecMoveData.x,
		v28 = vecNormFwd.z * vecMoveData.x,
		v24 = vecNormRight.x * vecMoveData.y,
		v23 = vecNormRight.y * vecMoveData.y,
		v25 = vecNormRight.z * vecMoveData.y,
		v30 = vecNormUp.x * vecMoveData.z,
		v27 = vecNormUp.z * vecMoveData.z,
		v29 = vecNormUp.y * vecMoveData.z;

	const float x = vecNormFwdOld.x * v24 + vecNormFwdOld.y * v23 + vecNormFwdOld.z * v25
		+ (vecNormFwdOld.x * v22 + vecNormFwdOld.y * v26 + vecNormFwdOld.z * v28)
		+ (vecNormFwdOld.y * v30 + vecNormFwdOld.x * v29 + vecNormFwdOld.z * v27);

	const float y = vecNormRightOld.x * v24 + vecNormRightOld.y * v23 + vecNormRightOld.z * v25
		+ (vecNormRightOld.x * v22 + vecNormRightOld.y * v26 + vecNormRightOld.z * v28)
		+ (vecNormRightOld.x * v29 + vecNormRightOld.y * v30 + vecNormRightOld.z * v27);

	const float z = vecNormUpOld.x * v23 + vecNormUpOld.y * v24 + vecNormUpOld.z * v25
		+ (vecNormUpOld.x * v26 + vecNormUpOld.y * v22 + vecNormUpOld.z * v28)
		+ (vecNormUpOld.x * v30 + vecNormUpOld.y * v29 + vecNormUpOld.z * v27);

	pCmd->flForwardMove = std::clamp(x, -450.f, 450.f);
	pCmd->flSideMove = std::clamp(y, -450.f, 450.f);
	pCmd->flUpMove = std::clamp(z, -450.f, 450.f);
}

void CMiscellaneous::ClantagChanger(CUserCmd* pCmd, CBaseEntity* pLocal)
{
	static float flPrevtime = 0;

	static bool bHasTag = false;

	if (!I::Engine->IsConnected())
		flPrevtime = 0;

	if (bHasTag && !C::Get<bool>(Vars.bClantagChanger)) {
		U::SendClanTag(_(""), _(""));
		bHasTag = false;
	}

	if (C::Get<bool>(Vars.bClantagChanger))
	{
		static std::string starter = _("[$] darklight ");
		static std::string current(starter.size(), ' ');
		static int position = 0, string_size = starter.size();
		bHasTag = true;
		if (I::Globals->flCurrentTime - flPrevtime > 0.2f)
		{
			if (position < string_size)
			{
				if (position < string_size - 1)
					current[position] = '>';

				if (position)
					current[position - 1] = starter[position - 1];
			}
			else if (position >= string_size)
			{
				int cur = string_size - (position - string_size + 1);
				if (cur > string_size / 2 - 1)
					current[cur] = '<';
				else
					current[cur] = '>';
			}

			position++;

			if (position == string_size * 2)
				position = 0;

			U::SendClanTag(current.c_str(), _("$$$"));

			flPrevtime = I::Globals->flCurrentTime;
		}
	}
}