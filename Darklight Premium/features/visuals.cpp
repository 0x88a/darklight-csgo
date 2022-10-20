#include <mutex>

#include "visuals.h"
#include "../global.h"
#include "../sdk/datatypes/keyvalues.h"
#include "../core/variables.h"
#include "../core/gui/gui.h"
#include "../core/hooks.h"
#include "../utilities/draw.h"
#include "../utilities/math.h"
#include "../utilities.h"
#include "backtrack.h"
#include "misc.h"
#include "../global.h"
#include "autowall.h"

CVisuals g_Visuals;

void CVisuals::RunEventLogs()
{
	for (auto i = 0; i < vecEventVector.size(); i++) {
		auto log = vecEventVector[i];
		auto time_delta = fabs(I::Globals->flCurrentTime - log.flTime);

		if (time_delta > flTextTime) {
			vecEventVector.erase(vecEventVector.begin() + i);
			continue;
		}

		auto height = flIdealHeight + (14 * i),
			 width = flIdealWidth;

		if (time_delta < flTextFadeInTime) {
			log.flAlpha = ((time_delta / flTextFadeInTime) * 255.f);
			width = (time_delta / flTextFadeInTime) * (float)(flSlideInDistance) + (flIdealWidth - flSlideInDistance);
		}

		if (time_delta > flTextTime - flTextFadeOutTime) {
			log.flAlpha = (255 - (((time_delta - (flTextTime - flTextFadeOutTime)) / flTextFadeOutTime) * 255.f));
			width = flIdealWidth + (((time_delta - (flTextTime - flTextFadeOutTime)) / flTextFadeOutTime) * (float)(flSlideOutDistance));
		}

		D::String(width, height, D::uVerdana[G::iDPIScale], log.szText, false, Color(255, 255, 255, log.flAlpha));
	}
}

std::string hitgroup_to_name(int hitgroup) {
	switch (hitgroup) {
	case HITGROUP_HEAD:
		return _("head");
	case HITGROUP_LEFTLEG:
		return _("left leg");
	case HITGROUP_RIGHTLEG:
		return _("right leg");
	case HITGROUP_STOMACH:
		return _("stomach");
	case HITGROUP_LEFTARM:
		return _("left arm");
	case HITGROUP_RIGHTARM:
		return _("right arm");
	default:
		return _("body");
	}
}

void CVisuals::Event(IGameEvent* pEvent, const FNV1A_t uNameHash)
{
	if (!pEvent || !G::pLocal)
		return;

	switch (uNameHash)
	{
		case FNV1A::HashConst(("player_hurt")):
		{
			const auto pAttacker = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("attacker"))));
			if (!pAttacker)
				return;

			const auto pVictim = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
			if (!pVictim)
				return;

			if (pAttacker == G::pLocal && pVictim != G::pLocal)
			{
				if (C::Get<bool>(Vars.bHitmarker))
				{
					m_flHitmarkerTime = 1.0f;
					I::Surface->PlaySoundSurface(_("buttons\\arena_switch_press_02.wav"));
				}

				if (C::Get<std::deque<bool>>(Vars.vecEventLogs).at(0))
				{
					PlayerInfo_t player_info;
					if (!I::Engine->GetPlayerInfo(pVictim->GetIndex(), &player_info))
						return;

					char buffer[256];
					sprintf_s(buffer, _("Hurt %s in the %s for %i. (%i health remaining)\n"), player_info.szName, hitgroup_to_name(pEvent->GetInt(_("hitgroup"))).c_str(), pEvent->GetInt(_("dmg_health")), pEvent->GetInt(_("health")));

					vecEventVector.push_back(EventLogging_t{ buffer });
					I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
					I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
					I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
					I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
				}
			}
			else if (pVictim == G::pLocal)
			{
				if (C::Get<std::deque<bool>>(Vars.vecEventLogs).at(1))
				{
					PlayerInfo_t player_info;
					if (!I::Engine->GetPlayerInfo(pAttacker->GetIndex(), &player_info))
						return;

					char buffer[256];
					sprintf_s(buffer, _("%s hurt you in the %s for %i. (%i health remaining)\n"), player_info.szName, hitgroup_to_name(pEvent->GetInt(_("hitgroup"))).c_str(), pEvent->GetInt(_("dmg_health")), pEvent->GetInt(_("health")));

					vecEventVector.push_back(EventLogging_t{ buffer });
					I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
					I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
					I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
					I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
				}
			}
		} break;
		case FNV1A::HashConst(("item_purchase")):
		{
			const auto pPurchaser = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
			if (!pPurchaser || !C::Get<std::deque<bool>>(Vars.vecEventLogs).at(2))
				return;

			if (pEvent->GetInt(_("team")) == G::pLocal->GetTeam())
				return;

			PlayerInfo_t player_info;
			if (!I::Engine->GetPlayerInfo(pPurchaser->GetIndex(), &player_info))
				return;

			const auto szWeapon = pEvent->GetString(_("weapon"));
			if (szWeapon == _("weapon_unknown"))
				return;

			char buffer[256];
			sprintf_s(buffer, _("%s bought %s.\n"), player_info.szName, szWeapon);

			vecEventVector.push_back(EventLogging_t{ buffer });
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
			I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
		} break;
		case FNV1A::HashConst(("player_given_c4")):
		{
			const auto pEntity = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
			if (!pEntity || !C::Get<std::deque<bool>>(Vars.vecEventLogs).at(3))
				return;

			PlayerInfo_t player_info;
			if (!I::Engine->GetPlayerInfo(pEntity->GetIndex(), &player_info))
				return;

			char buffer[256];
			sprintf_s(buffer, _("%s picked up the bomb.\n"), player_info.szName);

			vecEventVector.push_back(EventLogging_t{ buffer });
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
			I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
		} break;
		case FNV1A::HashConst(("bomb_beginplant")):
		{
			const auto pEntity = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
			if (!pEntity || !C::Get<std::deque<bool>>(Vars.vecEventLogs).at(3))
				return;

			PlayerInfo_t player_info;
			if (!I::Engine->GetPlayerInfo(pEntity->GetIndex(), &player_info))
				return;

			char buffer[256];
			sprintf_s(buffer, _("%s started planting the bomb.\n"), player_info.szName);

			vecEventVector.push_back(EventLogging_t{ buffer });
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
			I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
		} break;
		case FNV1A::HashConst(("bomb_abortplant")):
		{
			const auto pEntity = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
			if (!pEntity || !C::Get<std::deque<bool>>(Vars.vecEventLogs).at(3))
				return;

			PlayerInfo_t player_info;
			if (!I::Engine->GetPlayerInfo(pEntity->GetIndex(), &player_info))
				return;

			char buffer[256];
			sprintf_s(buffer, _("%s stopped planting the bomb.\n"), player_info.szName);

			vecEventVector.push_back(EventLogging_t{ buffer });
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
			I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
		} break;
		case FNV1A::HashConst(("bomb_planted")):
		{
			const auto pEntity = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
			if (!pEntity || !C::Get<std::deque<bool>>(Vars.vecEventLogs).at(3))
				return;

			PlayerInfo_t player_info;
			if (!I::Engine->GetPlayerInfo(pEntity->GetIndex(), &player_info))
				return;

			char buffer[256];
			sprintf_s(buffer, _("%s planted the bomb.\n"), player_info.szName);

			vecEventVector.push_back(EventLogging_t{ buffer });
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
			I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
		} break;
		case FNV1A::HashConst(("bomb_begindefuse")):
		{
			const auto pEntity = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
			if (!pEntity || !C::Get<std::deque<bool>>(Vars.vecEventLogs).at(3))
				return;

			PlayerInfo_t player_info;
			if (!I::Engine->GetPlayerInfo(pEntity->GetIndex(), &player_info))
				return;

			char buffer[256];
			sprintf_s(buffer, _("%s started defusing the bomb %s.\n"), player_info.szName, pEvent->GetInt(_("haskit")) ? _("with a kit") : _("without a kit"));

			vecEventVector.push_back(EventLogging_t{ buffer });
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
			I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
		} break;
		case FNV1A::HashConst(("bomb_abortdefuse")):
		{
			const auto pEntity = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
			if (!pEntity || !C::Get<std::deque<bool>>(Vars.vecEventLogs).at(3))
				return;

			PlayerInfo_t player_info;
			if (!I::Engine->GetPlayerInfo(pEntity->GetIndex(), &player_info))
				return;

			char buffer[256];
			sprintf_s(buffer, _("%s stopped defusing the bomb.\n"), player_info.szName);

			vecEventVector.push_back(EventLogging_t{ buffer });
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
			I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
			I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _(" %s"), buffer);
		} break;
		default: break;
	}
}

void CVisuals::Hitmarker()
{
	if (!G::pLocal || !G::pLocal->IsAlive())
		return;

	const Vector2D vecCenter(G::vecDisplaySize.x / 2, G::vecDisplaySize.y / 2);

	if (m_flHitmarkerTime > 0.0f) {
		D::Line(vecCenter.x - 10, vecCenter.y + 10, vecCenter.x - 4, vecCenter.y + 4, Color(255, 255, 255, m_flHitmarkerTime * 255));
		D::Line(vecCenter.x + 10, vecCenter.y + 10, vecCenter.x + 4, vecCenter.y + 4, Color(255, 255, 255, m_flHitmarkerTime * 255));
		D::Line(vecCenter.x - 10, vecCenter.y - 10, vecCenter.x - 4, vecCenter.y - 4, Color(255, 255, 255, m_flHitmarkerTime * 255));
		D::Line(vecCenter.x + 10, vecCenter.y - 10, vecCenter.x + 4, vecCenter.y - 4, Color(255, 255, 255, m_flHitmarkerTime * 255));

		m_flHitmarkerTime -= 1.0f / 0.5f * I::Globals->flFrameTime;
	}
}

void CVisuals::Run()
{
	SpectatorFrame();

	m_pLocal = LocalPlayerOrSpectatedPlayer();
	if (!m_pLocal)
		return;

	if (m_iTotalSpectators > 0)
		m_iTotalSpectators = 0;

	CollectEntities();
	Paint();
	Hitmarker();
	RunEventLogs();
	Crosshair();
	Watermark();
	PaintMovementData();
}

void CVisuals::CollectEntities()
{
	if (!m_pLocal)
		return;

	for (int i = 1; i < I::ClientEntityList->GetHighestEntityIndex(); i++)
	{
		CBaseEntity* pEntity = I::ClientEntityList->Get<CBaseEntity>(i);
		if (!pEntity)
			continue;

		if (!pEntity->IsAlive())
			SpectatorList(pEntity);

		if (pEntity->IsPlayer())
		{
			if (!pEntity->IsAlive() || !m_pLocal->IsEnemy(pEntity))
				continue;

			if (pEntity->IsDormant() && m_flEntityAlpha[i] > 0)
			{
				if (!m_bTimeSet[i])
				{
					m_flTimeSinceDormant[i] = I::Globals->flCurrentTime;
					m_bTimeSet[i] = true;
				}

				float flFade = C::Get<float>(Vars.flDormancy);
				if (flFade <= 0.0f)
					flFade = 0.01f;

				m_flEntityAlpha[i] = 150.0f - ((I::Globals->flCurrentTime - m_flTimeSinceDormant[i]) * (150.0f / flFade));
				if (m_flEntityAlpha[i] < 0.0f)
					m_flEntityAlpha[i] = 0.0f;
			}

			if (!pEntity->IsDormant())
			{
				m_flEntityAlpha[i] = 255.0f;
				m_flTimeSinceDormant[i] = 0.0f;
				m_bTimeSet[i] = false;

				if (C::Get<bool>(Vars.bRadarHack))
					*pEntity->IsSpotted() = true;
			}

			PaintPlayers(pEntity);
		}

		if (!pEntity->IsDormant() && !pEntity->IsPlayer())
		{
			if (G::pLocal->IsAlive() &&
				pEntity->GetClientClass()->nClassID != EClassIndex::CC4 &&
				pEntity->GetClientClass()->nClassID != EClassIndex::CPlantedC4)
			{
				const auto flDist = G::pLocal->GetOrigin().DistTo(pEntity->GetOrigin());
				m_flEntityAlpha[i] = 255.f;

				const auto flAlphaDist = std::clamp(flDist - 300.f, 0.f, 510.f);
				m_flEntityAlpha[i] = 255.f - flAlphaDist / 2;
			}
			else
				m_flEntityAlpha[i] = 255.f;

			if (m_flEntityAlpha[i] < 0.0f) {
				m_flEntityAlpha[i] = 0.0f;
				continue;
			}

			PaintWeapons(pEntity);
			PaintGrenades(pEntity);

			if (pEntity->GetClientClass()->nClassID == EClassIndex::CPlantedC4)
				PaintC4(pEntity);
		}
	}
}

void CVisuals::SpectatorList(CBaseEntity* pEntity)
{
	PlayerInfo_t playerInfo;
	if (!I::Engine->GetPlayerInfo(pEntity->GetIndex(), &playerInfo))
		return;

	CBaseHandle hOBSTarget = pEntity->GetObserverTargetHandle();
	if (!hOBSTarget)
		return;

	CBaseEntity* pObserved = I::ClientEntityList->Get<CBaseEntity>(hOBSTarget);
	if (!pObserved)
		return;

	std::string szName = playerInfo.szName;

	if (pObserved == G::pLocal && G::pLocal->IsAlive() && C::Get<bool>(Vars.bSpectatorList))
		D::String(m_vecPos.x + 10, m_vecPos.y + 30 + (m_iTotalSpectators++ * 11), D::uMenuFont[G::iDPIScale], szName, false, Color(150, 150, 150));
}

void CVisuals::SpectatorFrame()
{
	if (!C::Get<bool>(Vars.bSpectatorList))
		return;

	m_vecSize = { 152, float(42 + m_iTotalSpectators * 11) };

	auto vecPos = m_vecPos = Vector2D((float)C::Get<int>(Vars.iSpectatorX), (float)C::Get<int>(Vars.iSpectatorY));

	static bool bDrag = false;
	static Vector2D vecLastMousePos;
	static Vector2D vecLastMenuPos;

	if (GUI::UTILS::KeyDown(VK_LBUTTON) && GUI::m_bOpened && !GUI::m_bGrabbingCheatGUI)
	{
		if (!bDrag && GUI::UTILS::MouseInRegion(m_vecPos.x, m_vecPos.y, m_vecSize.x, m_vecSize.y) &&
			!GUI::UTILS::MouseInRegion(m_vecPos.x, m_vecPos.y + 20, m_vecSize.x, m_vecSize.y - 20))
		{
			bDrag = true;
			vecLastMousePos = GUI::UTILS::m_vMousePos;
			vecLastMenuPos = m_vecPos;
		}

		if (bDrag)
		{
			C::Get<int>(Vars.iSpectatorX) = vecLastMenuPos.x + (GUI::UTILS::m_vMousePos.x - vecLastMousePos.x);
			C::Get<int>(Vars.iSpectatorY) = vecLastMenuPos.y + (GUI::UTILS::m_vMousePos.y - vecLastMousePos.y);
		}
	}
	else
		bDrag = false;

	m_bGrabbingSpectatorList = bDrag;

	if (C::Get<int>(Vars.iSpectatorX) < 0)
		C::Get<int>(Vars.iSpectatorX) = 0;

	if (C::Get<int>(Vars.iSpectatorY) < 0)
		C::Get<int>(Vars.iSpectatorY) = 0;

	if ((C::Get<int>(Vars.iSpectatorX) + m_vecSize.x) > G::vecDisplaySize.x)
		C::Get<int>(Vars.iSpectatorX) = G::vecDisplaySize.x - m_vecSize.x;

	if ((C::Get<int>(Vars.iSpectatorY) + m_vecSize.y) > G::vecDisplaySize.y)
		C::Get<int>(Vars.iSpectatorY) = G::vecDisplaySize.y - m_vecSize.y;

	std::string szName = _("Spectators  (") + std::to_string(m_iTotalSpectators) + _(")");

	D::Rect(m_vecPos.x, m_vecPos.y, m_vecSize.x, m_vecSize.y, Color(20, 20, 20));
	D::Rect(m_vecPos.x, m_vecPos.y + 23, m_vecSize.x, 1, Color(GUI::CONTROLS::m_cDefaultMenuCol));
	D::OutlinedRect(m_vecPos.x + 1, m_vecPos.y + 1, m_vecSize.x - 2, m_vecSize.y - 2, Color(50, 50, 50));
	D::OutlinedRect(m_vecPos.x, m_vecPos.y, m_vecSize.x, m_vecSize.y, Color(0, 0, 0));
	D::String(m_vecPos.x + 6, m_vecPos.y + 6, D::uMenuFont[G::iDPIScale], szName.c_str(), false, Color(147, 147, 155));
}

void CVisuals::Watermark() {
	if (C::Get<bool>(Vars.bWatermark)) {
		std::string watermarkname = _("darklight v2");
		m_vecSize = { 70, float(21) };
		auto vecPos = m_vecPos = Vector2D( float(1830), float(5) );
		D::Rect(m_vecPos.x, m_vecPos.y, m_vecSize.x, m_vecSize.y, Color(20, 20, 20, 69));
		D::Rect(m_vecPos.x, m_vecPos.y + 21, m_vecSize.x, 1, Color(GUI::CONTROLS::m_cDefaultMenuCol));
		D::String(m_vecPos.x + 4, m_vecPos.y + 5, D::uVerdana[G::iDPIScale], watermarkname, false, Color(147, 147, 155));
	}
}
 
void CVisuals::PaintPlayers(CBaseEntity* pEntity)
{
	if (!m_pLocal)
		return;

	BBox_t bbox;
	if (!CreateBBox(pEntity, bbox))
		return;

	if (C::Get<bool>(Vars.bBox))
	{
		D::OutlinedRect(bbox.flX, bbox.flY, bbox.flW, bbox.flH, pEntity->IsDormant() ? Color(110, 110, 110, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]) : Color(C::Get<Color>(Vars.colBox), (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));
		D::OutlinedRect(bbox.flX - 1, bbox.flY - 1, bbox.flW + 2, bbox.flH + 2, Color(0, 0, 0, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));
		D::OutlinedRect(bbox.flX + 1, bbox.flY + 1, bbox.flW - 2, bbox.flH - 2, Color(0, 0, 0, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));
	}

	if (C::Get<bool>(Vars.bName))
	{
		PlayerInfo_t playerInfo;
		I::Engine->GetPlayerInfo(pEntity->GetIndex(), &playerInfo);

		std::string player_name;
		if (playerInfo.bFakePlayer)
			player_name += _("BOT ");

		player_name += playerInfo.szName;

		auto name_text_size = D::GetTextSize(D::uVerdana[G::iDPIScale], player_name.c_str());
		D::String(bbox.flX + (bbox.flW / 2) - (name_text_size.right / 2), bbox.flY - 14, D::uVerdana[G::iDPIScale], player_name.c_str(), false, Color(C::Get<Color>(Vars.colName), (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));
	}

	if (C::Get<bool>(Vars.bHealth))
	{
		auto health = std::clamp(pEntity->GetHealth(), 0, 100);

		auto green = health * 2.55;
		auto red = 255 - green;

		auto bar = (bbox.flH / 100.0f) * health;
		auto delta = bbox.flH - bar;

		D::Rect(bbox.flX - 6, bbox.flY - 1, 2, bbox.flH + 2, pEntity->IsDormant() ? Color(80, 80, 80, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]) : Color(80, 80, 80, 125));
		D::Rect(bbox.flX - 6, bbox.flY + delta - 1, 2, bar + 2, Color(red, green, 0, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));
		D::OutlinedRect(bbox.flX - 7, bbox.flY - 1, 4, bbox.flH + 2, Color(0, 0, 0, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));

		if (health < 100.0f) {
			D::String(bbox.flX - 6, bbox.flY + delta - 4, D::uSmallFonts[G::iDPIScale], std::to_string(health).c_str(), true, Color(255, 255, 255, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));
		}
	}

	CBaseCombatWeapon* pWeapon = pEntity->GetWeapon();
	if (pWeapon)
	{
		CCSWeaponData* pData = I::WeaponSystem->GetWeaponData(*pWeapon->GetItemDefinitionIndex());
		if (pData)
		{
			if (C::Get<bool>(Vars.bWeapon))
				D::String(bbox.flX + (bbox.flW / 2), C::Get<bool>(Vars.bAmmo) && !(pData->nWeaponType == WEAPONTYPE_C4 || pData->nWeaponType == WEAPONTYPE_GRENADE || pData->nWeaponType == WEAPONTYPE_KNIFE) ? (bbox.flY + bbox.flH) + 10 : (bbox.flY + bbox.flH) + 4, D::uSmallFonts[G::iDPIScale], pWeapon->GetWeaponName(), true, Color(C::Get<Color>(Vars.colWeapon), (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));

			if (C::Get<bool>(Vars.bAmmo))
			{
				if (pData->nWeaponType == WEAPONTYPE_C4 ||
					pData->nWeaponType == WEAPONTYPE_GRENADE ||
					pData->nWeaponType == WEAPONTYPE_KNIFE) {
					return;
				}

				float bar_width = pWeapon->GetAmmo() * bbox.flW / pData->iMaxClip1;

				auto animlayer = pEntity->GetAnimationOverlays()[1];
				if (animlayer.pOwner) {
					auto activity = pEntity->GetSequenceActivity(animlayer.nSequence);
					if ((activity == 967 && animlayer.flWeight != 0.0f) &&
						animlayer.flCycle < 0.99) {
						bar_width = (animlayer.flCycle * bbox.flW) / 1.f;
					}
				}

				D::Rect(bbox.flX, bbox.flY + bbox.flH + 3, bbox.flW + 1, 2, pEntity->IsDormant() ? Color(80, 80, 80, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]) : Color(80, 80, 80, 125));
				D::OutlinedRect(bbox.flX - 1, bbox.flY + bbox.flH + 2, bbox.flW + 2, 4, Color(0, 0, 0, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));
				D::Rect(bbox.flX, bbox.flY + bbox.flH + 3, bar_width, 2, Color(C::Get<Color>(Vars.colAmmo), (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));

				if (pWeapon->GetAmmo() < pData->iMaxClip1 && pEntity->GetSequenceActivity(animlayer.nSequence) != 967) {
					D::String(bbox.flX + bar_width, bbox.flY + bbox.flH + 4, D::uSmallFonts[G::iDPIScale], std::to_string(pWeapon->GetAmmo()).c_str(), true, Color(255, 255, 255, (unsigned int)m_flEntityAlpha[pEntity->GetIndex()]));
				}
			}
		}
	}
}

void CVisuals::PaintWeapons(CBaseEntity* pEntity)
{
	if (!m_pLocal)
		return;

	BBox_t bbox;
	if (!CreateBBox(pEntity, bbox))
		return;

	if (pEntity->GetClientClass()->nClassID == EClassIndex::CC4 && pEntity->GetOwnerEntityHandle() == -1)
	{
		if (C::Get<bool>(Vars.bDroppedWeaponName))
			D::String(bbox.flX + (bbox.flW * 0.5f), bbox.flY + (bbox.flH * 0.5f), D::uSmallFonts[G::iDPIScale], _("C4"), 4, Color(150, 220, 10, m_flEntityAlpha[pEntity->GetIndex()]));
	}

	const auto pModel = pEntity->GetModel();
	if (!pModel || 
		pEntity->GetClientClass()->nClassID == EClassIndex::CPlantedC4 ||
		pEntity->GetClientClass()->nClassID == EClassIndex::CC4)
		return;

	const auto pStudioModel = I::ModelInfo->GetStudioModel(pModel);
	if (!pStudioModel)
		return;

	const auto szModelName = I::ModelInfo->GetModelName(pModel);
	if (strstr(szModelName, _("models/weapons/w_")) &&
		strstr(szModelName, _("_dropped.mdl")))
	{
		const auto pWeapon = (CBaseCombatWeapon*)pEntity;
		if (!pWeapon)
			return;

		const auto pWeaponData = I::WeaponSystem->GetWeaponData(*pWeapon->GetItemDefinitionIndex());
		if (!pWeaponData)
			return;

		const auto szWeaponName = pWeapon->GetWeaponName();
		if (szWeaponName == _("ERROR"))
			return;

		if (C::Get<bool>(Vars.bDroppedWeaponName))
			D::String(bbox.flX + (bbox.flW * 0.5f), bbox.flY + (bbox.flH * 0.5f), D::uSmallFonts[G::iDPIScale], szWeaponName, 4, Color(C::Get<Color>(Vars.colDroppedWeaponName), m_flEntityAlpha[pEntity->GetIndex()]));

		if (C::Get<bool>(Vars.bDroppedWeaponAmmo) && pWeaponData->IsGun())
		{
			std::string szAmmo = _("( ");
			szAmmo += std::to_string(pWeapon->GetAmmo()) + _(" / ");
			szAmmo += std::to_string(pWeapon->GetAmmoReserve()) + _(" )");

			D::String(bbox.flX + (bbox.flW * 0.5f), (bbox.flY + (bbox.flH * 0.5f)) + 10, D::uSmallFonts[G::iDPIScale], szAmmo, 4, Color(C::Get<Color>(Vars.colDroppedWeaponAmmo), m_flEntityAlpha[pEntity->GetIndex()]));
		}

		//D::String(bbox.flX + (bbox.flW * 0.5f), (bbox.flY + (bbox.flH * 0.5f)), D::uSmallFonts, std::to_string((int)pEntity->GetClientClass()->nClassID), 4, Color(C::Get<Color>(Vars.colDroppedWeaponAmmo), m_flEntityAlpha[pEntity->GetIndex()]));
	}
}

void CVisuals::PaintGrenades(CBaseEntity* pEntity)
{
	if (!m_pLocal)
		return;

	BBox_t bbox;
	if (!CreateBBox(pEntity, bbox))
		return;

	if (pEntity->GetClientClass()->nClassID == EClassIndex::CInferno)
	{
		if (C::Get<bool>(Vars.bGrenades))
			D::String(bbox.flX + (bbox.flW / 2), (bbox.flY + bbox.flH), D::uSmallFonts[G::iDPIScale], _("INFERNO"), 4, Color(C::Get<Color>(Vars.colGrenades), m_flEntityAlpha[pEntity->GetIndex()]));

		if (C::Get<bool>(Vars.bGrenadeTimer))
		{
			const auto pInferno = (CInferno*)pEntity;
			if (pInferno)
			{
				const float flTime = pInferno->GetMaxTime() - (I::Globals->flIntervalPerTick * (I::Globals->iTickCount - pInferno->GetEffectTickBegin()));
				if (flTime > 0) {
					D::OutlinedRect(bbox.flX + (bbox.flW / 2) - 15, (bbox.flY + bbox.flH) + 11 - 1, 30, 5, Color(0, 0, 0, m_flEntityAlpha[pEntity->GetIndex()]));

					if (m_flEntityAlpha[pEntity->GetIndex()] - 90 > 0)
						D::Rect(bbox.flX + (bbox.flW / 2) - 14, (bbox.flY + bbox.flH) + 11, 28, 3, Color(10, 10, 10, m_flEntityAlpha[pEntity->GetIndex()] - 90));

					D::Rect(bbox.flX + (bbox.flW / 2) - 14, (bbox.flY + bbox.flH) + 11, flTime * 4, 3, Color(C::Get<Color>(Vars.colGrenadeTimer), m_flEntityAlpha[pEntity->GetIndex()]));
				}
			}
		}
	}

	if (!pEntity->GetModel())
		return;

	auto model = I::ModelInfo->GetStudioModel(pEntity->GetModel());
	if (!model || 
		!strstr(model->szName, "thrown") && !strstr(model->szName, "dropped"))
		return;

	const std::string szName = pEntity->GetModel()->szName;
	std::string szGrenadeName = _("ERROR");

	if (szName.find(_("fraggrenade")) != std::string::npos)
		szGrenadeName = _("GRENADE");

	if (szName.find(_("smokegrenade")) != std::string::npos)
		szGrenadeName = _("SMOKE");

	if (szName.find(_("molotov")) != std::string::npos)
		szGrenadeName = _("MOLOTOV");

	if (szName.find(_("incendiarygrenade")) != std::string::npos)
		szGrenadeName = _("INCENDIARY");

	if (szName.find(_("flashbang")) != std::string::npos)
		szGrenadeName = _("FLASH");

	if (szName.find(_("decoy")) != std::string::npos)
		szGrenadeName = _("DECOY");

	if (szGrenadeName.find(_("ERROR")) == std::string::npos)
	{
		if (C::Get<bool>(Vars.bGrenades))
			D::String(bbox.flX + (bbox.flW / 2), (bbox.flY + bbox.flH), D::uSmallFonts[G::iDPIScale], szGrenadeName, 4, Color(C::Get<Color>(Vars.colGrenades), m_flEntityAlpha[pEntity->GetIndex()]));

		if (C::Get<bool>(Vars.bGrenadeTimer))
		{
			const auto pSmoke = (CSmokeGrenade*)pEntity;
			if (pSmoke)
			{
				if (szGrenadeName.find(_("SMOKE")) != std::string::npos &&
					!strstr(model->szName, "dropped")) {
					const auto flTime = pSmoke->GetMaxTime() - (I::Globals->flIntervalPerTick * (I::Globals->iTickCount - pSmoke->GetEffectTickBegin()));
					if (flTime > 0)
					{
						D::OutlinedRect(bbox.flX + (bbox.flW / 2) - 19, (bbox.flY + bbox.flH) + 11 - 1, 38, 5, Color(0, 0, 0, m_flEntityAlpha[pEntity->GetIndex()]));

						if (m_flEntityAlpha[pEntity->GetIndex()] - 90 > 0)
							D::Rect(bbox.flX + (bbox.flW / 2) - 18, (bbox.flY + bbox.flH) + 11, 36, 3, Color(10, 10, 10, m_flEntityAlpha[pEntity->GetIndex()] - 90));

						D::Rect(bbox.flX + (bbox.flW / 2) - 18, (bbox.flY + bbox.flH) + 11, flTime * 2, 3, Color(C::Get<Color>(Vars.colGrenadeTimer), m_flEntityAlpha[pEntity->GetIndex()]));
					}
				}
			}
		}
	}
}

float BombArmor(float flDamage, float flArmorValue)
{
	if (flArmorValue > 0)
	{
		float flNew = flDamage * 0.5f;
		float flArmor = (flDamage - flNew) * 0.5f;

		if (flArmor > flArmorValue) 
		{
			flArmor = flArmorValue * (1.f / 0.5f);
			flNew = flDamage - flArmor;
		}

		flDamage = flNew;
	}

	return flDamage;
}

void CVisuals::PaintC4(CBaseEntity* pEntity)
{
	const auto pC4 = (CPlantedC4*)pEntity;
	if (!pC4 || pC4->GetTimer(I::Globals->flCurrentTime) <= 0 || pC4->IsDefused())
		return;

	BBox_t bbox;
	const auto bInView = CreateBBox(pEntity, bbox);

	char buffer[256];
	sprintf(buffer, _("BOMB %s - %.1f S"), pC4->GetBombSite() ? _("B") : _("A"), pC4->GetTimer(I::Globals->flCurrentTime));

	const auto bombSize = D::GetTextSize(D::uVerdanaBig[G::iDPIScale], buffer);

	if (C::Get<bool>(Vars.bBombTimer))
	{
		D::String(G::vecDisplaySize.x - bombSize.right, C::Get<bool>(Vars.bWatermark) ? 30 : 0, D::uVerdanaBig[G::iDPIScale], buffer, false, Color(225, 0, 0));
		if (bInView)
			D::String(bbox.flX + (bbox.flW / 2), bbox.flY + (bbox.flH / 2), D::uSmallFonts[G::iDPIScale], buffer, 4, Color(225, 0, 0));
	}

	if (G::pLocal->IsAlive())
	{
		const float flHypDist = (pEntity->GetEyePosition() - G::pLocal->GetEyePosition()).Length(), flSigma = 583.333313F;
		const int iDamage = BombArmor((500.f * (exp(-flHypDist * flHypDist / (2.0f * flSigma * flSigma))) * 1.0f), G::pLocal->GetArmor());

		const bool bIsLethal = iDamage >= G::pLocal->GetHealth();
		const std::string szHPToStr = std::to_string(iDamage);
		const std::string szDamage = bIsLethal ? szHPToStr + _(" (LETHAL)") : szHPToStr;
		const Color lethalColor = bIsLethal ? Color(225, 0, 0) : Color(0, 225, 0);

		if (iDamage)
		{
			if (C::Get<bool>(Vars.bBombTimer))
			{
				D::String(G::vecDisplaySize.x - D::GetTextSize(D::uVerdanaBig[G::iDPIScale], szDamage.c_str()).right, C::Get<bool>(Vars.bWatermark) ? 30 + bombSize.bottom : bombSize.bottom, D::uVerdanaBig[G::iDPIScale], szDamage, 0, lethalColor);
				if (bInView)
					D::String(bbox.flX + (bbox.flW / 2), bbox.flY + (bbox.flH / 2) + 10, D::uSmallFonts[G::iDPIScale], szDamage, 4, lethalColor);
			}
		}
	}
}

void CVisuals::Crosshair()
{
	static auto pWeaponDegubSpreadShow = I::ConVar->FindVar("weapon_debug_spread_show");
	if (pWeaponDegubSpreadShow->nFlags & FCVAR_CHEAT)
		pWeaponDegubSpreadShow->nFlags &= ~FCVAR_CHEAT;

	static auto pCrosshairRecoil = I::ConVar->FindVar("cl_crosshair_recoil");
	if (pCrosshairRecoil->nFlags & FCVAR_CHEAT)
		pCrosshairRecoil->nFlags &= ~FCVAR_CHEAT;

	if (G::pLocal && G::pLocal->IsAlive()) {
		pWeaponDegubSpreadShow->SetValue(G::pLocal->IsScoped() || !C::Get<bool>(Vars.bSniperCrosshair) ? 0 : 3);
		pCrosshairRecoil->SetValue(C::Get<bool>(Vars.bRecoilCrosshair));
	}
}

bool CVisuals::CreateBBox(CBaseEntity* pEntity, BBox_t& BBox)
{
	const ICollideable* pCollideable = pEntity->GetCollideable();
	if (pCollideable == nullptr)
		return false;

	const Vector vecMin = pCollideable->OBBMins();
	const Vector vecMax = pCollideable->OBBMaxs();

	std::array<Vector, 8U> arrPoints =
	{
		Vector(vecMin.x, vecMin.y, vecMin.z),
		Vector(vecMin.x, vecMax.y, vecMin.z),
		Vector(vecMax.x, vecMax.y, vecMin.z),
		Vector(vecMax.x, vecMin.y, vecMin.z),
		Vector(vecMax.x, vecMax.y, vecMax.z),
		Vector(vecMin.x, vecMax.y, vecMax.z),
		Vector(vecMin.x, vecMin.y, vecMax.z),
		Vector(vecMax.x, vecMin.y, vecMax.z)
	};

	if (arrPoints.data() == nullptr)
		return false;

	const matrix3x4_t& matTransformed = pEntity->GetCoordinateFrame();

	float flLeft = std::numeric_limits<float>::max();
	float flTop = std::numeric_limits<float>::max();
	float flRight = -std::numeric_limits<float>::max();
	float flBottom = -std::numeric_limits<float>::max();

	std::array<Vector, 8U> arrScreen = { };
	for (std::size_t i = 0U; i < 8U; i++)
	{
		if (!WorldToScreen(M::VectorTransform(arrPoints.at(i), matTransformed), arrScreen.at(i)))
			return false;

		flLeft = std::min(flLeft, arrScreen.at(i).x);
		flTop = std::min(flTop, arrScreen.at(i).y);
		flRight = std::max(flRight, arrScreen.at(i).x);
		flBottom = std::max(flBottom, arrScreen.at(i).y);
	}

	BBox.flX = flLeft;
	BBox.flY = flTop;
	BBox.flW = flRight - flLeft;
	BBox.flH = flBottom - flTop;

	return true;
}

IMaterial* CVisuals::CreateMaterial(std::string_view szName, std::string_view szShader, std::string_view szBaseTexture, std::string_view szEnvMap, bool bIgnorez, bool bWireframe, std::string_view szProxies)
{
	std::string szMaterial = fmt::format(_(R"#("{shader}"
	{{
		"$basetexture"	"{texture}"
		"$ignorez"		"{ignorez}"
		"$envmap"		"{envmap}"
		"$wireframe"	"{wireframe}"

		"$model"		"1"
		"$selfillum"	"1"
		"$halflambert"	"1"
		"$nofog"		"1"
		"$nocull"       "0"
		"$znearer"		"0"
		"$flat"			"1" 
		"$normalmapalphaenvmask" "1"

		"$bumpmap"		"effects\flat_normal"

		"$envmaptint"		"[0 0 0]"
		"$envmapfresnel" "0"

		"$phongalbedotint" "1"
		"$phong" "1"
		"$phongexponent" "15"
		"$phongboost" "0"
		"$phongtint"		"[0 0 0]"

		"$rimlight" "1"
		"$rimlightexponent" "15"
		"$rimlightboost" "1"

		"$phongfresnelranges" "[.5 .5 .5]"

		"$pearlescent" "0"

		"proxies"
		{{ 
			{proxies}
		}}
	}})#"), fmt::arg(_("shader"), szShader), fmt::arg(_("texture"), szBaseTexture), fmt::arg(_("envmap"), szEnvMap), fmt::arg(_("ignorez"), bIgnorez ? 1 : 0), fmt::arg(_("wireframe"), bWireframe ? 1 : 0), fmt::arg(_("proxies"), szProxies));
	
	// load to memory
	CKeyValues* pKeyValues = new CKeyValues(szShader.data());
	pKeyValues->LoadFromBuffer(szName.data(), szMaterial.c_str());

	// create from buffer
	return I::MaterialSystem->CreateMaterial(szName.data(), pKeyValues);
}

bool CVisuals::Chams(CBaseEntity* pLocal, DrawModelResults_t* pResults, const DrawModelInfo_t& info, matrix3x4_t* pBoneToWorld, float* flFlexWeights, float* flFlexDelayedWeights, const Vector& vecModelOrigin, int nFlags)
{
	static auto oDrawModel = DTR::DrawModel.GetOriginal<decltype(&H::hkDrawModel)>();
	if (!info.pClientEntity)
		return false;

	IClientRenderable* pRenderable = info.pClientEntity;
	if (!pRenderable)
		return false;

	IClientUnknown* pClientUnknown = pRenderable->GetIClientUnknown();
	if (!pClientUnknown)
		return false;

	CBaseEntity* pEntity = pRenderable->GetIClientUnknown()->GetBaseEntity();
	if (!pEntity)
		return false;

	static IMaterial* arrMaterials[2] =
	{
		CreateMaterial(_("custom"), _("VertexLitGeneric"), _("vgui/white"), _("env_cubemap")),
		CreateMaterial(_("basic_flat"), _("UnlitGeneric")),
	};

	std::string_view szModelName = info.pStudioHdr->szName;
	if (szModelName.find(_("player")) != std::string_view::npos && szModelName.find(_("shadow")) == std::string_view::npos)
	{
		if (nFlags & (STUDIO_RENDER | STUDIO_SKIP_FLEXES | STUDIO_DONOTMODIFYSTENCILSTATE | STUDIO_NOLIGHTING_OR_CUBEMAP | STUDIO_SKIP_DECALS))
			return false;

		if (!pEntity->IsAlive() || pEntity->IsDormant())
			return false;

		if (pLocal->IsEnemy(pEntity))
		{
			IMaterial* pMaterial = arrMaterials[C::Get<bool>(Vars.bFlat)];

			if (pMaterial == nullptr || pMaterial->IsErrorMaterial())
				return false;

			Color colVisible = C::Get<Color>(Vars.colChams);
			Color colHidden = C::Get<Color>(Vars.colChamsXQZ);

			if (C::Get<bool>(Vars.bChamsXQZ))
			{
				pMaterial->IncrementReferenceCount();
				pMaterial->SetMaterialVarFlag(MATERIAL_VAR_IGNOREZ, true);

				I::StudioRender->SetColorModulation(colHidden.Base().data());
				I::StudioRender->SetAlphaModulation(colHidden.aBase());
				I::StudioRender->ForcedMaterialOverride(pMaterial);

				oDrawModel(I::StudioRender, 0, pResults, info, pBoneToWorld, flFlexWeights, flFlexDelayedWeights, vecModelOrigin, nFlags);
			}

			if (C::Get<bool>(Vars.bChams))
			{
				pMaterial->IncrementReferenceCount();
				pMaterial->SetMaterialVarFlag(MATERIAL_VAR_IGNOREZ, false);

				I::StudioRender->SetColorModulation(colVisible.Base().data());
				I::StudioRender->SetAlphaModulation(colVisible.aBase());
				I::StudioRender->ForcedMaterialOverride(pMaterial);
			}

			static auto flHeldPearlescent = 0.0f;
			const float flPearlescent = C::Get<float>(Vars.flPearlescent);

			if (flPearlescent != flHeldPearlescent)
			{
				IMaterialVar* pPearl = pMaterial->FindVar(_("$pearlescent"), nullptr);

				pPearl->SetVector(flPearlescent / 10.0f, flPearlescent / 10.0f, flPearlescent / 10.0f);
				flHeldPearlescent = flPearlescent;
			}

			static bool bDisablePhongBoost = false, bDidSetDisabledPhong = false;

			if (C::Get<bool>(Vars.bPhong))
			{
				static auto colHeldPhong = Color(255, 255, 255);
				const auto colPhong = C::Get<Color>(Vars.colPhong);

				if (colPhong != colHeldPhong)
				{
					IMaterialVar* pPhongBoost = pMaterial->FindVar(_("$phongboost"), nullptr);
					pPhongBoost->SetFloat((colPhong.a() / 255.0f) * 10.0f);

					IMaterialVar* pPhongTint = pMaterial->FindVar(_("$phongtint"), nullptr);
					pPhongTint->SetVector(colPhong.r() / 255.0f, colPhong.g() / 255.0f, colPhong.b() / 255.0f);
					colHeldPhong = colPhong;
				}
			}
			else
				bDisablePhongBoost = true, bDidSetDisabledPhong = false;

			if (bDisablePhongBoost && !bDidSetDisabledPhong)
			{
				IMaterialVar* pPhongBoost = pMaterial->FindVar(_("$phongboost"), nullptr);
				pPhongBoost->SetFloat(0.0f);
				bDisablePhongBoost = false;
				bDidSetDisabledPhong = true;
			}

			static bool bDisableReflectivity = false, bDidSetDisableReflecitivty = false;

			if (C::Get<bool>(Vars.bReflectivity))
			{
				static auto colHeldReflecitivty = Color(255, 255, 255);
				const auto colReflecitivty = C::Get<Color>(Vars.colReflectivity);
				if (colReflecitivty != colHeldReflecitivty)
				{
					IMaterialVar* reflectivity = pMaterial->FindVar(_("$envmaptint"), nullptr);
					reflectivity->SetVector(
						(colReflecitivty.r() / 255.0f),
						(colReflecitivty.g() / 255.0f),
						(colReflecitivty.b() / 255.0f));
					colHeldReflecitivty = colReflecitivty;
				}
			}
			else
				bDisableReflectivity = true, bDidSetDisableReflecitivty = false;

			if (bDisableReflectivity && !bDidSetDisableReflecitivty)
			{
				IMaterialVar* reflectivity = pMaterial->FindVar(_("$envmaptint"), nullptr);
				reflectivity->SetVector(0, 0, 0);
				bDisableReflectivity = false;
				bDidSetDisableReflecitivty = true;
			}

			return true;
		}
	}
	return false;
}

void CVisuals::Glow(CBaseEntity* pLocal)
{
	m_pLocal = LocalPlayerOrSpectatedPlayer();
	if (!m_pLocal)
		return;

	for (int i = 0; i < I::GlowManager->vecGlowObjectDefinitions.Count(); i++)
	{
		IGlowObjectManager::GlowObject_t& hGlowObject = I::GlowManager->vecGlowObjectDefinitions[i];
		if (hGlowObject.IsEmpty())
			continue;

		CBaseEntity* pEntity = hGlowObject.pEntity;
		if (pEntity == nullptr)
			continue;

		CBaseClient* pClientClass = pEntity->GetClientClass();
		if (pClientClass == nullptr)
			continue;

		const EClassIndex nIndex = pClientClass->nClassID;
		switch (nIndex)
		{
			case EClassIndex::CCSPlayer:
			{
				if (pEntity->IsDormant() || !pEntity->IsAlive())
					break;

				if (m_pLocal->IsEnemy(pEntity))
					hGlowObject.Set(C::Get<Color>(Vars.colGlow));
				break;
			}
			default:
			{
				hGlowObject.flAlpha = 0.0f;
				break;
			}
		}

		hGlowObject.bRenderWhenOccluded = true;
		hGlowObject.bRenderWhenUnoccluded = false;
	}
}

void CVisuals::GatherMovementData()
{
	if (!I::Engine->IsInGame() || !G::pLocal || !C::Get<bool>(Vars.bVelocityGraph))
	{
		if (!vecMovementData.empty())
			vecMovementData.clear();
		return;
	}

	vecMovementData.resize(C::Get<int>(Vars.iVelocityGraphWidth));

	vecMovementData.insert(
		vecMovementData.begin(),
		MovementData_t{
			std::round(G::pLocal->GetVelocity().Length2D()),
			(bool)(G::pLocal->GetFlags() & FL_ONGROUND)
		}
	);
}

void CVisuals::PaintMovementData()
{
	if (!I::Engine->IsInGame() || !G::pLocal)
		return;

	static float flSpeed, flOldGroundSpeed, flLastGroundSpeed, flFrameTime;
	static int iLastFlags;

	const float flVelocity = std::round(G::pLocal->GetVelocity().Length2D());
	const int iFlags = G::pLocal->GetFlags();

	const int iIdealY = G::vecDisplaySize.y  / 2 + C::Get<int>(Vars.iYAdditive);

	if (C::Get<bool>(Vars.bVelocityGraph) && G::pLocal->IsAlive() && vecMovementData.size() > 2)
	{
		for (int i = 0; i < vecMovementData.size() - 1; i++)
		{
			const MovementData_t currentData = vecMovementData[i];
			const MovementData_t nextData = vecMovementData[i + 1];

			const bool bLanded = !currentData.bOnGround && nextData.bOnGround;

			const int iCurrentSpeed = std::clamp((int)currentData.flvelocity, 0, 450);
			const int iNextSpeed = std::clamp((int)nextData.flvelocity, 0, 450);

			const RECT linePos = {
				G::vecDisplaySize.x / 2 + ((C::Get<int>(Vars.iVelocityGraphWidth) / 2) - 8) - ((signed int)i - 1) * 5 * 0.175f,
				iIdealY - 50 - (iCurrentSpeed / C::Get<float>(Vars.flVelocityGraphCompression)),
				G::vecDisplaySize.x / 2 + ((C::Get<int>(Vars.iVelocityGraphWidth) / 2) - 8) - (signed int)i * 5 * 0.175f,
				iIdealY - 50 - (iNextSpeed / C::Get<float>(Vars.flVelocityGraphCompression))
			};

			D::Line(linePos.left, linePos.top, linePos.right, linePos.bottom, Color(200, 200, 200));
		}
	}

	if (C::Get<bool>(Vars.bKeystrokes)) {

			if (GetAsyncKeyState(int('W')))
				D::String(G::vecDisplaySize.x / 2, iIdealY + 80, D::uTrebuchetMS[G::iDPIScale - 5], "W", 4, Color(255, 255, 255, 180));
			else
				D::String(G::vecDisplaySize.x / 2, iIdealY + 80, D::uTrebuchetMS[G::iDPIScale - 5], "_", 4, Color(255, 255, 255, 180));

			if (GetAsyncKeyState(int('S')))
				D::String(G::vecDisplaySize.x / 2, iIdealY + 55, D::uTrebuchetMS[G::iDPIScale - 5], "S", 4, Color(255, 255, 255, 180));
			else
				D::String(G::vecDisplaySize.x / 2, iIdealY + 55, D::uTrebuchetMS[G::iDPIScale - 5], "_", 4, Color(255, 255, 255, 180));

			if (GetAsyncKeyState(int('A')))
				D::String(G::vecDisplaySize.x / 2 - 25, iIdealY + 55, D::uTrebuchetMS[G::iDPIScale - 5], "A", 4, Color(255, 255, 255, 180));
			else
				D::String(G::vecDisplaySize.x / 2 - 25, iIdealY + 55, D::uTrebuchetMS[G::iDPIScale - 5], "_", 4, Color(255, 255, 255, 180));

			if (GetAsyncKeyState(int('D')))
				D::String(G::vecDisplaySize.x / 2 + 25, iIdealY + 55, D::uTrebuchetMS[G::iDPIScale - 5], "D", 4, Color(255, 255, 255, 180));
			else
				D::String(G::vecDisplaySize.x / 2 + 25, iIdealY + 55, D::uTrebuchetMS[G::iDPIScale-5], "_", 4, Color(255,255,255, 180));
		
	}

	if (C::Get<bool>(Vars.bVelocityIndicators))
	{
		if (G::pLocal->IsAlive())
		{
			if (iFlags & FL_ONGROUND && !(iLastFlags & FL_ONGROUND))
			{
				flOldGroundSpeed = flLastGroundSpeed;
				flLastGroundSpeed = flVelocity;
				flFrameTime = 1.0f;
			}

			iLastFlags = iFlags;
		}
		else
			flLastGroundSpeed = 0;

		if (flFrameTime > I::Globals->flFrameTime)
			flFrameTime -= I::Globals->flFrameTime;

		if (G::pLocal->IsAlive())
		{
			const float flDelta = flLastGroundSpeed - flOldGroundSpeed;

			Color col{ 180, 130, 55, 220 };
			if (flDelta > 0 && flFrameTime > 0.5)
				col = { 30, 220, 30, 220 };
			else if (flDelta < 0 && flFrameTime > 0.5)
				col = { 220, 30, 30, 220 };

			D::String(G::vecDisplaySize.x / 2, iIdealY + 24, D::uTrebuchetMS[G::iDPIScale], std::to_string((int)flVelocity), 4, Color(180, 130, 55, 220));
			D::String(G::vecDisplaySize.x / 2, iIdealY - 6, D::uTrebuchetMS[G::iDPIScale], std::to_string((int)flLastGroundSpeed), 4, col);
		}
	}

	if (C::Get<bool>(Vars.bBugIndicators) && G::pLocal->IsAlive())
	{
		static bool bJumpbugToggled = false;
		const bool bJumpbugging = C::Get<bool>(Vars.bJumpBug) && GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iJumpBugKey), C::Get<int>(Vars.iJumpBugKeyMethod), &bJumpbugToggled);
		D::String(G::vecDisplaySize.x / 2 + 55, iIdealY + 12, D::uTrebuchetMS[G::iDPIScale], "jb", 4, bJumpbugging ? Color(30, 220, 30, 220) : Color(180, 130, 55, 220));

		static bool bEdgebugToggled = false;
		const bool bEdgebugging = C::Get<bool>(Vars.bEdgeBug) && GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iEdgeBugKey), C::Get<int>(Vars.iEdgeBugKeyMethod), &bEdgebugToggled);
		D::String(G::vecDisplaySize.x / 2 - 55, iIdealY + 12, D::uTrebuchetMS[G::iDPIScale], "eb", 4, bEdgebugging ? Color(30, 220, 30, 220) : Color(180, 130, 55, 220));
	}
}


bool CVisuals::WorldToScreen(const Vector& vOrigin, Vector& vScreen) {
	return I::DebugOverlay->ScreenPosition(vOrigin, vScreen) != 1;
}

void CVisuals::Reset()
{
	m_vecStart = Vector{};
	m_vecMove = Vector{};
	m_vecVelocity = Vector{};
	m_flVel = 0.f;
	m_flPower= 0.f;

	if (!m_vecPath.empty())
		m_vecPath.clear();

	if (!m_vecBounces.empty())
		m_vecBounces.clear();

	m_pLocal = nullptr;
	m_pCollisionEntity = nullptr;
	m_iCollisionGroup = 0;
}

void CVisuals::OverrideView(CViewSetup* setup)
{
	Reset();

	if (!C::Get<bool>(Vars.bGrenadePrediction))
		return;

	m_pLocal = LocalPlayerOrSpectatedPlayer();
	if (!m_pLocal)
		return;

	const auto pWeapon = m_pLocal->GetWeapon();
	if (!pWeapon)
		return;

	const auto pWeaponData = I::WeaponSystem->GetWeaponData(*pWeapon->GetItemDefinitionIndex());
	if (!pWeaponData)
		return;

	const auto pGrenade = (CBaseCSGrenade*)pWeapon;
	if (!pGrenade)
		return;

	if (pWeaponData->nWeaponType == WEAPONTYPE_GRENADE) {
		if (!pGrenade->IsPinPulled())
			if (pGrenade->GetThrowTime() == 0)
				return;
	}
	else
		return;

	m_iID = *pWeapon->GetItemDefinitionIndex();
	m_flPower = pGrenade->GetThrowStrength();
	m_flVel = pWeaponData->flThrowVelocity;

	Simulate(setup);
}

void CVisuals::Paint()
{
	if (!C::Get<bool>(Vars.bGrenadePrediction) || !m_pLocal)
		return;

	const auto pWeapon = m_pLocal->GetWeapon();
	if (!pWeapon)
		return;

	const auto pWeaponData = I::WeaponSystem->GetWeaponData(*pWeapon->GetItemDefinitionIndex());
	if (!pWeaponData)
		return;

	const auto pGrenade = (CBaseCSGrenade*)pWeapon;
	if (!pGrenade)
		return;

	static CTraceFilter filter(m_pLocal);
	Trace_t trace;
	std::pair< float, CBaseEntity*> target{ 0.f, nullptr };

	if (m_vecPath.size() < 2)
		return;

	Vector vecPrev = m_vecPath.front();

	for (const auto& cur : m_vecPath) {
		Vector vecScreen, vecScreen1;

		if (WorldToScreen(vecPrev, vecScreen) && WorldToScreen(cur, vecScreen1))
		{
			D::Line((int)vecScreen.x - 1, (int)vecScreen.y, (int)vecScreen1.x + 1, (int)vecScreen1.y, C::Get<Color>(Vars.colGrenadePrediction));
			D::Line((int)vecScreen.x + 1, (int)vecScreen.y, (int)vecScreen1.x - 1, (int)vecScreen1.y, C::Get<Color>(Vars.colGrenadePrediction));
		}

		vecPrev = cur;
	}

	// TODO: Fix damage not always working
	//for (int i{ 1 }; i < I::Globals->nMaxClients; i++) {
	//	auto pEntity = I::ClientEntityList->Get<CBaseEntity>(i);
	//	if (!pEntity || pEntity->IsDormant() || !pEntity->IsAlive() ||
	//		!m_pLocal->IsEnemy(pEntity))
	//		continue;

	//	Vector vecCenter = pEntity->WorldSpaceCenter();
	//	Vector vecDelta = vecCenter - vecPrev;

	//	if (m_iID == WEAPON_HEGRENADE) {
	//		if (vecDelta.Length() > 350.f)
	//			continue;

	//		I::EngineTrace->TraceRay(Ray_t(vecPrev, vecCenter), MASK_SHOT, (ITraceFilter*)&filter, &trace);
	//		if (!trace.pHitEntity || trace.pHitEntity != pEntity)
	//			continue;

	//		float d = (vecDelta.Length() - 25.f) / 140.f;
	//		float damage = 105.f * std::exp(-d * d);

	//		g_AutoWall.ScaleDamage(HITGROUP_CHEST, pEntity, 1.f, damage);

	//		//damage = std::min(damage, (pEntity->GetArmor() > 0) ? 57.f : 98.f);

	//		if (damage > target.first) {
	//			target.first = damage;
	//			target.second = pEntity;
	//		}
	//	}
	//}

	//if (target.second) {
	//	Vector vecScreen;

	//	if (!m_vecBounces.empty())
	//		m_vecBounces.back().colColor = { 0, 200, 0 };

	//	if (WorldToScreen(vecPrev, vecScreen))
	//		D::String(vecScreen.x, vecScreen.y + 5, D::uSmallFonts[G::iDPIScale], "-" + std::to_string((int)target.first) + "HP", 4, target.first > target.second->GetHealth() ? Color(50, 200, 50) : Color(200, 200, 200));
	//}

	for (const auto& b : m_vecBounces) {
		Vector vecScreen;

		if (WorldToScreen(b.vecPoint, vecScreen))
			D::DrawFilledCircle(vecScreen, b.colColor, 3, 20);
	}
}

void CVisuals::Setup()
{
	if (!m_pLocal)
		return;

	const auto pWeapon = m_pLocal->GetWeapon();
	if (!pWeapon)
		return;

	const auto pGrenade = (CBaseCSGrenade*)pWeapon;
	if (!pGrenade)
		return;

	QAngle angThrow;
	I::Engine->GetViewAngles(angThrow);
	float pitch = angThrow.x;

	if (pitch <= 90.0f)
	{
		if (pitch < -90.0f)
			pitch += 360.0f;
	}
	else
		pitch -= 360.0f;

	angThrow.x = pitch - (90.0f - fabs(pitch)) * 10.0f / 90.0f;

	float flVel = 750.0f * 0.9f;
	float b = pGrenade->GetThrowStrength();
	b = b * 0.7f; 
	b = b + 0.3f;
	flVel *= b;

	Vector vForward, vRight, vUp;
	M::AngleVectors(angThrow, &vForward, &vRight, &vUp);

	m_vecStart = m_pLocal->GetEyePosition();
	m_vecStart.z += (pGrenade->GetThrowStrength() * 12.0f) - 12.0f;

	Trace_t tr;
	Vector vecDest = m_vecStart;
	vecDest += vForward * 22.0f;

	TraceHull(m_vecStart, vecDest, tr, m_pLocal);

	Vector vecBack = vForward; vecBack *= 6.0f;
	m_vecStart = tr.vecEnd;
	m_vecStart -= vecBack;

	m_vecVelocity = m_pLocal->GetVelocity();
	m_vecVelocity *= 1.25f;
	m_vecVelocity += vForward * flVel;
}

size_t CVisuals::Advance(size_t tick) {
	size_t     flags{ NONE };
	CGameTrace trace;

	PhysicsAddGravityMove(m_vecMove);
	PhysicsPushEntity(m_vecStart, m_vecMove, trace, m_pLocal);

	if (CheckDetonate(trace, tick))
		flags |= DETONATE;

	if (trace.flFraction != 1.f) {
		flags |= BOUNCE;
		ResolveFlyCollisionBounce(trace);
	}

	m_vecStart = trace.vecEnd;

	return flags;
}

void CVisuals::Simulate(CViewSetup* setup)
{
	Setup();

	size_t step = (size_t)TIME_TO_TICKS(0.05f), timer{ 0u };

	for (size_t i{ 0u }; i < 4096u; ++i) 
	{
		if (!timer)
			m_vecPath.push_back(m_vecStart);

		size_t flags = Advance(i);
		if ((flags & DETONATE))
			break;

		if ((flags & BOUNCE) || timer >= step)
			timer = 0;
		else
			++timer;

		if (m_vecVelocity.IsZero())
			break;
	}

	if (m_iID == WEAPON_MOLOTOV || m_iID == WEAPON_INCGRENADE) {
		CGameTrace trace;
		PhysicsPushEntity(m_vecStart, { 0.f, 0.f, -131.f }, trace, m_pLocal);

		if (trace.flFraction < 0.9f)
			m_vecStart = trace.vecEnd;
	}

	m_vecPath.push_back(m_vecStart);
	m_vecBounces.push_back( { m_vecStart, { 200, 0, 0 } } );
}

bool CVisuals::CheckDetonate(const Trace_t& trace, int tick)
{
	static auto weapon_molotov_maxdetonateslope = I::ConVar->FindVar(_("weapon_molotov_maxdetonateslope"));
	static auto molotov_throw_detonate_time = I::ConVar->FindVar(_("molotov_throw_detonate_time"));
	float time = TICKS_TO_TIME(tick);

	switch (m_iID)
	{
	case WEAPON_SMOKEGRENADE:
		return m_vecVelocity.Length() <= 0.1f && !(tick % TIME_TO_TICKS(0.2f));

	case WEAPON_DECOY:
		return m_vecVelocity.Length() <= 0.2f && !(tick % TIME_TO_TICKS(0.2f));

	case WEAPON_MOLOTOV:
	case WEAPON_INCGRENADE:
		if (trace.flFraction != 1.f && (std::cos(DEG2RAD(weapon_molotov_maxdetonateslope->GetFloat())) <= trace.plane.vecNormal.z))
			return true;
		return time >= molotov_throw_detonate_time->GetFloat() && !(tick % TIME_TO_TICKS(0.1f));

	case WEAPON_FLASHBANG:
	case WEAPON_HEGRENADE:
		return time >= 1.5f && !(tick % TIME_TO_TICKS(0.2f));
	default:
		return false;
	}
}

void CVisuals::TraceHull(const Vector& src, const Vector& end, Trace_t& tr, CBaseEntity* pEntity)
{
	unsigned int uMask;
	if (m_iCollisionGroup)
		uMask = (MASK_SOLID | CONTENTS_CURRENT_90) & ~CONTENTS_MONSTER;
	else
		uMask = MASK_SOLID | CONTENTS_OPAQUE | CONTENTS_IGNORE_NODRAW_OPAQUE | CONTENTS_CURRENT_90 | CONTENTS_HITBOX;

	CTraceFilter filter(pEntity);
	I::EngineTrace->TraceRay(Ray_t(src, end, Vector(-2.0f, -2.0f, -2.0f), Vector(2.0f, 2.0f, 2.0f)), uMask, &filter, &tr);
}

void CVisuals::PhysicsAddGravityMove(Vector& move)
{
	static auto sv_gravity = I::ConVar->FindVar(_("sv_gravity"));
	move.x = m_vecVelocity.x * I::Globals->flIntervalPerTick;
	move.y = m_vecVelocity.y * I::Globals->flIntervalPerTick;
	const float z = m_vecVelocity.z - ((sv_gravity->GetFloat() * 0.4f) * I::Globals->flIntervalPerTick);
	move.z = ((m_vecVelocity.z + z) / 2.f) * I::Globals->flIntervalPerTick;
	m_vecVelocity.z = z;
}

void CVisuals::PhysicsPushEntity(Vector& src, const Vector& move, Trace_t& tr, CBaseEntity* pEntity)
{
	TraceHull(src, src + move, tr, pEntity);
}

void CVisuals::ResolveFlyCollisionBounce(Trace_t& trace)
{
	float surface = 1.f;
	
	if (trace.pHitEntity) {
		if (trace.pHitEntity->IsPlayer())
			surface = 0.3f;

		if (!trace.DidHit())
		{
			if (m_pCollisionEntity == trace.pHitEntity)
			{
				if (trace.pHitEntity->IsPlayer())
				{
					m_iCollisionGroup = 1;
					return;
				}
			}

			m_pCollisionEntity = trace.pHitEntity;
		}
	}

	float elasticity = 0.45f * surface;
	elasticity = std::clamp(elasticity, 0.f, 0.9f);

	Vector velocity;
	PhysicsClipVelocity(m_vecVelocity, trace.plane.vecNormal, velocity, 2.f);
	velocity *= elasticity;

	if (trace.plane.vecNormal.z > 0.7f) {
		float speed = velocity.LengthSqr();
		if (speed > 96000.f) {
			float len = velocity.Normalized().DotProduct(trace.plane.vecNormal);
			if (len > 0.5f)
				velocity *= 1.5f - len;
		}

		if (speed < 400.f)
			m_vecVelocity = Vector{};
		else {
			m_vecVelocity = velocity;
			PhysicsPushEntity(trace.vecEnd, velocity * ((1.f - trace.flFraction) * I::Globals->flIntervalPerTick), trace, m_pLocal);
		}
	}
	else {
		m_vecVelocity = velocity;
		PhysicsPushEntity(trace.vecEnd, velocity * ((1.f - trace.flFraction) * I::Globals->flIntervalPerTick), trace, m_pLocal);
	}

	m_vecBounces.push_back( { trace.vecEnd, { 200, 200, 200 } } );
}

void CVisuals::PhysicsClipVelocity(const Vector& in, const Vector& normal, Vector& out, float overbounce)
{
	constexpr float STOP_EPSILON = 0.1f;

	float backoff = in.DotProduct(normal) * overbounce;

	for (int i{}; i < 3; ++i) {
		out[i] = in[i] - (normal[i] * backoff);
		if (out[i] > -STOP_EPSILON && out[i] < STOP_EPSILON)
			out[i] = 0.f;
	}
}

CFlashLightEffect* CVisuals::create_flashlight(int nEntIndex, const char* pszTextureName, float flFov, float flFarZ, float flLinearAtten)
{
	static DWORD oConstructor = (DWORD)MEM::FindPattern(CLIENT_DLL, _("55 8B EC F3 0F 10 45 ? B8"));

	CFlashLightEffect* pFlashLight = (CFlashLightEffect*)I::MemAlloc->Alloc(sizeof(CFlashLightEffect));
	if (!pFlashLight)
		return NULL;

	__asm
	{
		movss xmm3, flFov
		mov ecx, pFlashLight
		push flLinearAtten
		push flFarZ
		push pszTextureName
		push nEntIndex
		call oConstructor
	}

	return pFlashLight;
}

void CVisuals::destroy_flashlight(CFlashLightEffect* pFlashlight)
{
	static DWORD oDestructor = (DWORD)MEM::FindPattern(CLIENT_DLL, _("56 8B F1 E8 ? ? ? ? 8B 4E 28"));
	__asm
	{
		mov ecx, pFlashlight
		push ecx
		call oDestructor
	}
}

void CVisuals::update_flashlight(CFlashLightEffect* pFlashLight, const Vector& vecPos, const Vector& vecForward, const Vector& vecRight, const Vector& vecUp)
{
	typedef void(__thiscall* UpdateLight_t)(void*, int, const Vector&, const Vector&, const Vector&, const Vector&, float, float, float, bool, const char*);

	static UpdateLight_t oUpdateLight = NULL;
	if (!oUpdateLight)
	{
		DWORD callInstruction = (DWORD)MEM::FindPattern(CLIENT_DLL, _("E8 ? ? ? ? 8B 06 F3 0F 10 46")); // get the instruction address
		DWORD relativeAddress = *(DWORD*)(callInstruction + 1); // read the rel32
		DWORD nextInstruction = callInstruction + 5; // get the address of next instruction
		oUpdateLight = (UpdateLight_t)(nextInstruction + relativeAddress); // our function address will be nextInstruction + relativeAddress
	}

	oUpdateLight(pFlashLight, pFlashLight->m_nEntIndex, vecPos, vecForward, vecRight, vecUp, pFlashLight->m_flFov, pFlashLight->m_flFarZ, pFlashLight->m_flLinearAtten, pFlashLight->m_bCastsShadows, pFlashLight->m_szTextureName);
}

void CVisuals::run_flashlight()
{
	if (!G::pLocal)
		return;

	static CFlashLightEffect* pFlashLight = NULL;
	if (!I::Engine->IsInGame()) {
		pFlashLight = NULL;
		return;
	}

	if (!C::Get<bool>(Vars.bFlashlight))
	{
		if (pFlashLight)
		{
			destroy_flashlight(pFlashLight);
			pFlashLight = NULL;
		}
		return;
	}

	static bool bIsOn = false;
	static bool bToggled = false;
	bIsOn = GUI::UTILS::KeybindMethod(C::Get<int>(Vars.iFlashlightKey), C::Get<int>(Vars.iFlashlightKeyMethod), &bToggled);

	if (bIsOn)
	{
		if (!pFlashLight)
			pFlashLight = create_flashlight(I::Engine->GetLocalPlayer(), _("effects/flashlight001"), 35, 1000, 1000);
	}
	else 
	{
		if (pFlashLight)
		{
			destroy_flashlight(pFlashLight);
			pFlashLight = NULL;
		}
		return;
	}

	if (pFlashLight)
	{
		Vector f, r, u;
		QAngle viewAngles;

		I::Engine->GetViewAngles(viewAngles);
		M::AngleVectors(viewAngles, &f, &r, &u);

		pFlashLight->m_bIsOn = true;
		pFlashLight->m_bCastsShadows = false;
		pFlashLight->m_flFov = 35;
		update_flashlight(pFlashLight, G::pLocal->GetEyePosition(), f, r, u);
	}
}
