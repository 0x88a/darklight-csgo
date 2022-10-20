#include <array>

#include "hooks.h"
#include "../global.h"
#include "variables.h"
#include "../utilities/inputsystem.h"
#include "../utilities/logging.h"
#include "../utilities/draw.h"
#include "../utilities.h"

#include "../features/prediction.h"
#include "../features/triggerbot.h"
#include "../features/visuals.h"
#include "../features/misc.h"
#include "../features/aimbot.h"
#include "../features/backtrack.h"
#include "../features/skinchanger.h"
#include "../features/ragebot.h"
#include "../features/entity_cache.h"

#include "gui/gui.h"
#include <windowsx.h>

bool H::Setup()
{
	if (MH_Initialize() != MH_OK)
		throw std::runtime_error(_("Failed MH_Initialize"));

	if (!DTR::FrameStageNotify.Create(MEM::GetVFunc(I::Client, VTABLE::FRAMESTAGENOTIFY), &hkFrameStageNotify))
		throw std::runtime_error(_("Failed FrameStageNotify"));

	if (!DTR::OverrideView.Create(MEM::GetVFunc(I::ClientMode, VTABLE::OVERRIDEVIEW), &hkOverrideView))
		throw std::runtime_error(_("Failed OverrideView"));

	if (!DTR::CreateMove.Create(MEM::GetVFunc(I::ClientMode, VTABLE::CREATEMOVE), &hkCreateMove))
		throw std::runtime_error(_("Failed CreateMove"));

	if (!DTR::DoPostScreenEffects.Create(MEM::GetVFunc(I::ClientMode, VTABLE::DOPOSTSCREENEFFECTS), &hkDoPostScreenEffects))
		throw std::runtime_error(_("Failed DoPostScreenEffects"));

	if (!DTR::IsConnected.Create(MEM::GetVFunc(I::Engine, VTABLE::ISCONNECTED), &hkIsConnected))
		throw std::runtime_error(_("Failed IsConnected"));

	if (!DTR::PaintTraverse.Create(MEM::GetVFunc(I::Panel, VTABLE::PAINTTRAVERSE), &hkPaintTraverse))
		throw std::runtime_error(_("Failed PaintTraverse"));

	if (!DTR::DrawModel.Create(MEM::GetVFunc(I::StudioRender, VTABLE::DRAWMODEL), &hkDrawModel))
		throw std::runtime_error(_("Failed DrawModel"));

	if (!DTR::RunCommand.Create(MEM::GetVFunc(I::Prediction, VTABLE::RUNCOMMAND), &hkRunCommand))
		throw std::runtime_error(_("Failed RunCommand"));

	if (!DTR::SendMessageGC.Create(MEM::GetVFunc(I::SteamGameCoordinator, VTABLE::SENDMESSAGE), &hkSendMessage))
		throw std::runtime_error(_("Failed SendMessageGC"));

	if (!DTR::RetrieveMessage.Create(MEM::GetVFunc(I::SteamGameCoordinator, VTABLE::RETRIEVEMESSAGE), &hkRetrieveMessage))
		throw std::runtime_error(_("Failed RetrieveMessage"));

	if (!DTR::LockCursor.Create(MEM::GetVFunc(I::Surface, VTABLE::LOCKCURSOR), &hkLockCursor))
		throw std::runtime_error(_("Failed LockCursor"));

	if (!DTR::OverrideConfig.Create(MEM::GetVFunc(I::MaterialSystem, VTABLE::OVERRIDECONFIG), &hkOverrideConfig))
		throw std::runtime_error(_("Failed OverrideConfig"));


	if (!DTR::Shutdown.Create(MEM::GetVFunc(I::Client, 7), &hkLevelShutdown))
		throw std::runtime_error(_("Failed LevelShutdown"));

	if (!DTR::SceneEnd.Create(MEM::GetVFunc(I::RenderView, VTABLE::SCENEEND), &hkSceneEnd))
		throw std::runtime_error(_("Failed SceneEnd"));

	if (!DTR::FireGameEvent.Create(MEM::GetVFunc(I::GameEvent, VTABLE::FIREEVENT), &hkFireGameEvent))
		throw std::runtime_error(_("Failed FireGameEvent"));

	if (!DTR::AllocKeyValuesMemory.Create(MEM::GetVFunc(I::KeyValuesSystem, VTABLE::ALLOCKEYVALUESMEMORY), &hkAllocKeyValuesMemory))
		return false;

	return true;
}

void H::Restore()
{
	DTR::FrameStageNotify.~CDetourHook();
	DTR::OverrideView.~CDetourHook();
	DTR::CreateMove.~CDetourHook();
	DTR::SendNetMsg.~CDetourHook();
	DTR::SendDatagram.~CDetourHook();
	DTR::DoPostScreenEffects.~CDetourHook();
	DTR::IsConnected.~CDetourHook();
	DTR::PaintTraverse.~CDetourHook();
	DTR::DrawModel.~CDetourHook();
	DTR::RunCommand.~CDetourHook();
	DTR::SendMessageGC.~CDetourHook();
	DTR::RetrieveMessage.~CDetourHook();
	DTR::LockCursor.~CDetourHook();
	DTR::SvCheatsGetBool.~CDetourHook();
	DTR::OverrideConfig.~CDetourHook();
	DTR::IsHLTV.~CDetourHook();
	DTR::LevelInitPostEntity.~CDetourHook();

	#if 0
	MH_DisableHook(MH_ALL_HOOKS);
	MH_RemoveHook(MH_ALL_HOOKS);
	#endif

	MH_Uninitialize();
}

std::vector<std::string> vecIconOverrides{
	"bayonet",
	"knife_flip",
	"knife_gut",
	"knife_karambit",
	"knife_m9_bayonet",
	"knife_tactical",
	"knife_falchion",
	"knife_survival_bowie" ,
	"knife_butterfly",
	"knife_push",
	"knife_ursus",
	"knife_gypsy_jackknife",
	"knife_stiletto",
	"knife_widowmaker",
	"knife_classic",
	"knife_outdoor",
	"knife_skeleton",
	"knife_cord"
	"knife_canis"
};

bool FASTCALL H::hkFireGameEvent(void* pThis, void* edx, IGameEvent* pEvent)
{
	static auto oFireGameEvent = DTR::FireGameEvent.GetOriginal<decltype(&hkFireGameEvent)>();

	if (FNV1A::Hash(pEvent->GetName()) == FNV1A::Hash("player_death") && I::Engine->IsInGame() && I::Engine->IsConnected() && G::pLocal)
	{
		const auto pAttacker = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("attacker"))));
		if (!pAttacker)
			return oFireGameEvent(pThis, edx, pEvent);;

		const auto pVictim = (CBaseEntity*)I::ClientEntityList->GetClientEntity(I::Engine->GetPlayerForUserID(pEvent->GetInt(_("userid"))));
		if (!pVictim)
			return oFireGameEvent(pThis, edx, pEvent);

		const std::string szWeapon = pEvent->GetString(("weapon"));
		if (pAttacker == G::pLocal && G::pLocal != pVictim)
		{
			CBaseCombatWeapon* pWeapon = G::pLocal->GetWeapon();
			if (pWeapon && pWeapon->GetClientClass()->nClassID == EClassIndex::CKnife)
			{
				if ((szWeapon.find(("knife_default_ct")) != std::string::npos ||
					szWeapon.find(("knife_t")) != std::string::npos) &&
					C::Get<int>(Vars.iKnifeModel))
					pEvent->SetString("weapon", vecIconOverrides[C::Get<int>(Vars.iKnifeModel) - 1].c_str());
			}
		}
	}

	return oFireGameEvent(pThis, edx, pEvent);
}

bool FASTCALL H::hkCreateMove(IClientModeShared* thisptr, int edx, float flInputSampleTime, CUserCmd* pCmd)
{
	static auto oCreateMove = DTR::CreateMove.GetOriginal<decltype(&hkCreateMove)>();
	oCreateMove(thisptr, edx, flInputSampleTime, pCmd);

	CBaseEntity* pLocal = G::pLocal = U::GetLocalPlayer();
	
	if (pCmd->iCommandNumber == 0 || !pLocal || !pCmd)
		return oCreateMove(thisptr, edx, flInputSampleTime, pCmd);

	if (oCreateMove(thisptr, edx, flInputSampleTime, pCmd))
		I::Prediction->SetLocalViewAngles(pCmd->angViewPoint);

	G::pCmd = pCmd;

	if (I::ClientState == nullptr || I::Engine->IsPlayingDemo())
		return oCreateMove(thisptr, edx, flInputSampleTime, pCmd);

	if (!G::pLocal || !G::pCmd)
		return oCreateMove(thisptr, edx, flInputSampleTime, pCmd);

	INetChannel* pNetChannel = (INetChannel*)I::ClientState->pNetChannel;

	const volatile auto vlBaseAddress = *(std::uintptr_t*)((std::uintptr_t)_AddressOfReturnAddress() - sizeof(std::uintptr_t));

	bool& bSendPacket = *(bool*)(vlBaseAddress - 0x34);

	QAngle angOldViewPoint = pCmd->angViewPoint;

	G::cmd = *pCmd;

	if (GUI::m_bOpened)
	{
		if (pCmd->iButtons & IN_ATTACK)
			pCmd->iButtons &= ~IN_ATTACK;

		if (pCmd->iButtons & IN_SECOND_ATTACK)
			pCmd->iButtons &= ~IN_SECOND_ATTACK;
	}

	if (I::ClientState->iDeltaTick > 0)
		I::Prediction->Update(I::ClientState->iDeltaTick, I::ClientState->iDeltaTick > 0, I::ClientState->nLastCommandAck, I::ClientState->nLastOutgoingCommand + I::ClientState->iChokedCommands);

	g_Misc.Run(pCmd, pLocal, bSendPacket);

	const int iFlags = pLocal->GetFlags();

	g_Prediction.Start(pCmd, pLocal);
	{
		g_Misc.NullStrafe(pCmd, pLocal);
		g_Misc.Blockbot(pCmd, pLocal);
		/*g_Backtrack.Run(pCmd, pLocal, bSendPacket);*/
		g_Aimbot.Run(pCmd, pLocal, bSendPacket);
		g_Ragebot.Run(pCmd, pLocal, bSendPacket);
		g_Triggerbot.Run(pCmd, pLocal);
		g_Visuals.GatherMovementData();
	}
	g_Prediction.End(pCmd, pLocal);

	g_Misc.EdgeJump(pCmd, pLocal, iFlags);
	g_Misc.JumpBug(pCmd, pLocal, iFlags);
	g_Misc.EdgeBug(pCmd, pLocal, iFlags);
	g_Misc.StrafeOptimizer(pCmd, pLocal);
	g_Misc.MiniJump(pCmd, pLocal);
	g_Misc.MovementRecorder(pCmd, pLocal);

	g_Misc.CorrectMovement(pLocal, pCmd, angOldViewPoint);

	if (pNetChannel != nullptr)
	{
		if (!DTR::SendNetMsg.IsHooked())
			DTR::SendNetMsg.Create(MEM::GetVFunc(pNetChannel, VTABLE::SENDNETMSG), H::hkSendNetMsg);
	}

	G::angRealView = pCmd->angViewPoint;
	G::bSendPacket = bSendPacket;

	return false;
}

class GifData
{
public:
	inline void Update(float flAddedTime)
	{
		flTime += flAddedTime;
	}
	float flTime = 0;
};

GifData gifData;

void FASTCALL H::hkPaintTraverse(ISurface* thisptr, int edx, unsigned int uPanel, bool bForceRepaint, bool bForce)
{
	static auto oPaintTraverse = DTR::PaintTraverse.GetOriginal<decltype(&hkPaintTraverse)>();
	oPaintTraverse(thisptr, edx, uPanel, bForceRepaint, bForce);

	int iCurrentWidth, iCurrentHeight = 0;
	I::Engine->GetScreenSize(iCurrentWidth, iCurrentHeight);
	if (G::vecDisplaySize.x != iCurrentWidth || G::vecDisplaySize.y != iCurrentHeight)
	{
		G::vecDisplaySize.x = iCurrentWidth, G::vecDisplaySize.y = iCurrentHeight;
		D::Initialize();
	}

	auto nPanel = FNV1A::HashConst(I::Panel->GetName(uPanel));
	switch (nPanel)
	{
	case FNV1A::HashConst(("MatSystemTopPanel")):
	{
		GUI::UTILS::InitializeInput(_("Counter-Strike: Global Offensive"));

		g_Visuals.Run();
		g_Visuals.run_flashlight();

		/*gifData.Update(I::Globals->flFrameTime);

		static auto flPrevTime = 0.0f;
		if (gifData.flTime >= flPrevTime + 0.1f)
		{
			GUI::CONTROLS::m_iCurrentFrame++;
			flPrevTime = gifData.flTime;
		}

		if (GUI::CONTROLS::m_iCurrentFrame > 7)
			GUI::CONTROLS::m_iCurrentFrame = 0;*/

		GUI::Run();
	} break;
	default:
		break;
	}
}

void FASTCALL H::hkSceneEnd(void* _this)
{
	static auto oSceneEnd = DTR::SceneEnd.GetOriginal<decltype(&hkSceneEnd)>();
	oSceneEnd(_this);

	if (!G::pLocal || !C::Get<bool>(Vars.bExtendChams))
		return;

	for (int i = 1; i < I::Globals->nMaxClients; i++)
	{
		CBaseEntity* pEntity = I::ClientEntityList->Get<CBaseEntity>(i);
		if (!pEntity || !pEntity->IsAlive() || pEntity->IsDormant() ||
			!G::pLocal->IsEnemy(pEntity))
			continue;

		pEntity->DrawModel(0x1, 255);
	}
}

void FASTCALL H::hkLockCursor(ISurface* thisptr, int edx)
{
	static auto oLockCursor = DTR::LockCursor.GetOriginal<decltype(&hkLockCursor)>();

	if ((G::pLocal && G::pLocal->IsAlive() && I::Engine->IsInGame()))
	{
		I::InputSystem->EnableInput(true);
		if (G::bTakingInput)
			I::InputSystem->EnableInput(false);
	}

	if (GUI::m_bOpened)
		I::Surface->UnLockCursor();
	else
		oLockCursor(thisptr, edx);
}

std::string GetNewModel(int iTeam) 
{
	static std::vector<std::string> vecCTModels = 
	{
	
	("models/player/custom_player/legacy/tm_leet_variantf.mdl"),
	("models/player/custom_player/legacy/tm_leet_varianti.mdl"),
	("models/player/custom_player/legacy/tm_leet_varianth.mdl"),
	("models/player/custom_player/legacy/tm_leet_variantg.mdl"),
	("models/player/custom_player/legacy/ctm_fbi_variantb.mdl"),
	("models/player/custom_player/legacy/ctm_fbi_varianth.mdl"),
	("models/player/custom_player/legacy/ctm_fbi_variantg.mdl"),
	("models/player/custom_player/legacy/ctm_fbi_variantf.mdl"),
	("models/player/custom_player/legacy/ctm_st6_variante.mdl"),
	("models/player/custom_player/legacy/ctm_st6_variantm.mdl"),
	("models/player/custom_player/legacy/ctm_st6_variantg.mdl"),
	("models/player/custom_player/legacy/ctm_st6_variantk.mdl"),
	("models/player/custom_player/legacy/ctm_st6_varianti.mdl"),
	("models/player/custom_player/legacy/ctm_st6_variantj.mdl"),
	("models/player/custom_player/legacy/ctm_st6_variantl.mdl"),
	("models/player/custom_player/legacy/ctm_swat_variante.mdl"),
	("models/player/custom_player/legacy/ctm_swat_variantf.mdl"),
	("models/player/custom_player/legacy/ctm_swat_variantg.mdl"),
	("models/player/custom_player/legacy/ctm_swat_varianth.mdl"),
	("models/player/custom_player/legacy/ctm_swat_varianti.mdl"),
	("models/player/custom_player/legacy/ctm_swat_variantj.mdl"),
	("models/player/custom_player/legacy/tm_balkan_varianti.mdl"),
	("models/player/custom_player/legacy/tm_balkan_variantf.mdl"),
	("models/player/custom_player/legacy/tm_balkan_varianth.mdl"),
	("models/player/custom_player/legacy/tm_balkan_variantg.mdl"),
	("models/player/custom_player/legacy/tm_balkan_variantj.mdl"),
	("models/player/custom_player/legacy/tm_balkan_variantk.mdl"),
	("models/player/custom_player/legacy/tm_balkan_variantl.mdl"),
	("models/player/custom_player/legacy/ctm_sas_variantf.mdl"),
	("models/player/custom_player/legacy/tm_phoenix_varianth.mdl"),
	("models/player/custom_player/legacy/tm_phoenix_variantf.mdl"),
	("models/player/custom_player/legacy/tm_phoenix_variantg.mdl"),
	("models/player/custom_player/legacy/tm_phoenix_varianti.mdl"),
	("models/player/custom_player/legacy/tm_professional_varf.mdl"),
	("models/player/custom_player/legacy/tm_professional_varf1.mdl"),
	("models/player/custom_player/legacy/tm_professional_varf2.mdl"),
	("models/player/custom_player/legacy/tm_professional_varf3.mdl"),
	("models/player/custom_player/legacy/tm_professional_varf4.mdl"),
	("models/player/custom_player/legacy/tm_professional_varg.mdl"),
	("models/player/custom_player/legacy/tm_professional_varh.mdl"),
	("models/player/custom_player/legacy/tm_professional_vari.mdl"),
	("models/player/custom_player/legacy/tm_professional_varj.mdl")
	};

	static std::vector<std::string> vecTModels =
	{
		("models/player/custom_player/legacy/tm_balkan_variantf.mdl"),
		("models/player/custom_player/legacy/tm_balkan_variantg.mdl"),
		("models/player/custom_player/legacy/tm_balkan_varianth.mdl"),
		("models/player/custom_player/legacy/tm_balkan_varianti.mdl"),
		("models/player/custom_player/legacy/tm_balkan_variantj.mdl"),
		("models/player/custom_player/legacy/tm_leet_variantf.mdl"),
		("models/player/custom_player/legacy/tm_leet_variantg.mdl"),
		("models/player/custom_player/legacy/tm_leet_varianth.mdl"),
		("models/player/custom_player/legacy/tm_leet_varianti.mdl"),
		("models/player/custom_player/legacy/tm_phoenix_variantf.mdl"),
		("models/player/custom_player/legacy/tm_phoenix_variantg.mdl"),
		("models/player/custom_player/legacy/tm_phoenix_varianth.mdl")
	};

	switch (iTeam) {
		case 2: 
			return (C::Get<int>(Vars.iPlayerTModel) - 1) < vecTModels.size() ?
				vecTModels[C::Get<int>(Vars.iPlayerTModel) - 1] : _("");
		case 3:
			return (C::Get<int>(Vars.iPlayerCTModel) - 1) < vecCTModels.size() ?
				vecCTModels[C::Get<int>(Vars.iPlayerCTModel) - 1] : _("");
		default:
			return "";
	}
};

void FASTCALL H::hkFrameStageNotify(IBaseClientDll* thisptr, int edx, EClientFrameStage stage)
{
	static auto oFrameStageNotify = DTR::FrameStageNotify.GetOriginal<decltype(&hkFrameStageNotify)>();

	if (!I::Engine->IsInGame())
		return oFrameStageNotify(thisptr, edx, stage);

	if (I::Engine->IsTakingScreenshot())
		return oFrameStageNotify(thisptr, edx, stage);

	static int iOriginalIndex = 0;

	if (!G::pLocal) 
	{
		iOriginalIndex = 0;
		return oFrameStageNotify(thisptr, edx, stage);
	}

	switch (stage)
	{
	case FRAME_RENDER_START:
	{
		/*
		 * start rendering the scene
		 * e.g. remove visual punch, thirdperson, other render/update stuff
		 */
		g_EntityCache.Clear();
		break;
	};
	case FRAME_NET_UPDATE_END:
	{
		/*
		 * received all packets, now do interpolation, prediction, etc
		 * e.g. backtrack stuff
		 */

		g_EntityCache.Fill();
		break;
	};
	case FRAME_NET_UPDATE_POSTDATAUPDATE_START:
	{
		/*
		 * data has been received and we are going to start calling postdataupdate
		 * e.g. resolver or skinchanger and other visuals
		 */

		g_Skinchanger.Run();
		break;
	};
	case FRAME_NET_UPDATE_POSTDATAUPDATE_END:
	{
		/*
		 * data has been received and called postdataupdate on all data recipients
		 * e.g. now we can modify interpolation, other lagcompensation stuff
		 */
		break;
	}
	default:
		break;
	}

	const auto szModelName = GetNewModel(G::pLocal->GetTeam());
	if (!szModelName.empty()) {
		if (stage == FRAME_RENDER_START)
			iOriginalIndex = G::pLocal->GetModelIndex();

		const auto iIndex = 
			stage == FRAME_RENDER_END && iOriginalIndex ? iOriginalIndex : I::ModelInfo->GetModelIndex(szModelName.c_str());

		G::pLocal->SetModelIndex(iIndex);
	}

	oFrameStageNotify(thisptr, edx, stage);
}

void FASTCALL H::hkDrawModel(IStudioRender* thisptr, int edx, DrawModelResults_t* pResults, const DrawModelInfo_t& info, matrix3x4_t* pBoneToWorld, float* flFlexWeights, float* flFlexDelayedWeights, const Vector& vecModelOrigin, int nFlags)
{
	static auto oDrawModel = DTR::DrawModel.GetOriginal<decltype(&hkDrawModel)>();
	//static auto viewmodel_fov = I::ConVar->FindVar("viewmodel_fov");

	if (!I::Engine->IsInGame() || I::Engine->IsTakingScreenshot())
		return oDrawModel(thisptr, edx, pResults, info, pBoneToWorld, flFlexWeights, flFlexDelayedWeights, vecModelOrigin, nFlags);

	CBaseEntity* pLocal = U::GetLocalPlayer();
	bool bClearOverride = false;

	if (pLocal; pLocal != nullptr && C::Get<bool>(Vars.bChams))
		bClearOverride = g_Visuals.Chams(pLocal, pResults, info, pBoneToWorld, flFlexWeights, flFlexDelayedWeights, vecModelOrigin, nFlags);

	oDrawModel(thisptr, edx, pResults, info, pBoneToWorld, flFlexWeights, flFlexDelayedWeights, vecModelOrigin, nFlags);
	
	if (bClearOverride)
		I::StudioRender->ForcedMaterialOverride(nullptr);
}

bool FASTCALL H::hkIsConnected(IEngineClient* thisptr, int edx)
{
	static auto oIsConnected = DTR::IsConnected.GetOriginal<decltype(&hkIsConnected)>();

	// @xref: "IsLoadoutAllowed"
	// sub above the string
	// sub in that function
	// .text : 103A2120 84 C0		test    al, al; Logical Compare
	static std::uintptr_t uLoadoutAllowedReturn = (MEM::FindPattern(CLIENT_DLL, _("84 C0 75 05 B0 01 5F")) - 0x2);

	if (_ReturnAddress() == (void*)uLoadoutAllowedReturn && C::Get<std::deque<bool>>(Vars.vecMatchmaking).at(0))
		return false;

	return oIsConnected(thisptr, edx);
}

bool FASTCALL H::hkSendNetMsg(INetChannel* thisptr, int edx, INetMessage* pMessage, bool bForceReliable, bool bVoice)
{
	static auto oSendNetMsg = DTR::SendNetMsg.GetOriginal<decltype(&hkSendNetMsg)>();

	/*
	 * @note: disable files crc check (sv_pure)
	 * dont send message if it has FileCRCCheck type
	 */
	if (pMessage->GetType() == 14 && C::Get<std::deque<bool>>(Vars.vecMatchmaking).at(1))
		return false;

	/*
	 * @note: fix lag with chocking packets when voice chat is active
	 * check for voicedata group and enable voice stream
	 */
	if (pMessage->GetGroup() == 9)
		bVoice = true;

	return oSendNetMsg(thisptr, edx, pMessage, bForceReliable, bVoice);
}

void FASTCALL H::hkOverrideView(IClientModeShared* thisptr, int edx, CViewSetup* pSetup)
{
	static auto oOverrideView = DTR::OverrideView.GetOriginal<decltype(&hkOverrideView)>();

	if (!I::Engine->IsInGame() || I::Engine->IsTakingScreenshot())
		return oOverrideView(thisptr, edx, pSetup);

	G::vecCamera = pSetup->vecOrigin;

	g_Visuals.OverrideView(pSetup);

	if (C::Get<bool>(Vars.bFOVChanger)) {
		if (!G::pLocal->IsScoped())
			pSetup->flFOV += C::Get<float>(Vars.flPlayerFOV);
	}

	oOverrideView(thisptr, edx, pSetup);

}

int FASTCALL H::hkDoPostScreenEffects(IClientModeShared* thisptr, int edx, CViewSetup* pSetup)
{
	static auto oDoPostScreenEffects = DTR::DoPostScreenEffects.GetOriginal<decltype(&hkDoPostScreenEffects)>();

	if (!I::Engine->IsInGame() || !I::Engine->IsConnected())
		return oDoPostScreenEffects(thisptr, edx, pSetup);

	if (G::pLocal && I::GlowManager && C::Get<bool>(Vars.bGlow))
		g_Visuals.Glow(G::pLocal);

	return oDoPostScreenEffects(thisptr, edx, pSetup);
}

void FASTCALL H::hkRunCommand(IPrediction* thisptr, int edx, CBaseEntity* pEntity, CUserCmd* pCmd, IMoveHelper* pMoveHelper)
{
	static auto oRunCommand = DTR::RunCommand.GetOriginal<decltype(&hkRunCommand)>();
	oRunCommand(thisptr, edx, pEntity, pCmd, pMoveHelper);

	I::MoveHelper = pMoveHelper;
}

int FASTCALL H::hkSendMessage(ISteamGameCoordinator* thisptr, int edx, std::uint32_t uMsgType, const void* pData, std::uint32_t uData)
{
	static auto oSendMessage = DTR::SendMessageGC.GetOriginal<decltype(&hkSendMessage)>();

	std::uint32_t uMessageType = uMsgType & 0x7FFFFFFF;
	void* pDataMutable = const_cast<void*>(pData);

	int iStatus = oSendMessage(thisptr, edx, uMsgType, pDataMutable, uData);

	if (iStatus != EGCResultOK)
		return iStatus;

	#if _DEBUG
	L::PushConsoleColor(FOREGROUND_INTENSE_GREEN | FOREGROUND_RED);
	L::Print(fmt::format(_("[<-] Message sent to GC {:d}!"), uMessageType));
	L::PopConsoleColor();
	#endif

	return iStatus;
}

int FASTCALL H::hkRetrieveMessage(ISteamGameCoordinator* thisptr, int edx, std::uint32_t* puMsgType, void* pDest, std::uint32_t uDest, std::uint32_t* puMsgSize)
{
	static auto oRetrieveMessage = DTR::RetrieveMessage.GetOriginal<decltype(&hkRetrieveMessage)>();
	int iStatus = oRetrieveMessage(thisptr, edx, puMsgType, pDest, uDest, puMsgSize);

	if (iStatus != EGCResultOK)
		return iStatus;

	std::uint32_t uMessageType = *puMsgType & 0x7FFFFFFF;

	#if _DEBUG
	L::PushConsoleColor(FOREGROUND_INTENSE_GREEN | FOREGROUND_RED);
	L::Print(fmt::format(_("[->] Message received from GC {:d}!"), uMessageType));
	L::PopConsoleColor();
	#endif

	if (C::Get<std::deque<bool>>(Vars.vecMatchmaking).at(2) && uMessageType == 9177)
	{
		U::SetLocalPlayerReady();
		Beep(500, 800);
		U::FlashWindow(IPT::hWindow);
	}

	return iStatus;
}

bool FASTCALL H::hkSvCheatsGetBool(CConVar* thisptr, int edx)
{
	static auto oSvCheatsGetBool = DTR::SvCheatsGetBool.GetOriginal<decltype(&hkSvCheatsGetBool)>();
	static std::uintptr_t uCAM_ThinkReturn = (MEM::FindPattern(CLIENT_DLL, _("85 C0 75 30 38 86"))); // @xref: "Pitch: %6.1f   Yaw: %6.1f   Dist: %6.1f %16s"

	if (_ReturnAddress() == (void*)uCAM_ThinkReturn)
		return true;

	return oSvCheatsGetBool(thisptr, edx);
}

long CALLBACK H::hkWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (G::bTakingInput)
		return 0;

	return CallWindowProcW(IPT::pOldWndProc, hWnd, uMsg, wParam, lParam);
}

bool FASTCALL H::hkOverrideConfig(void* pThis, void* edx, MaterialSystemConfig_t* pConfig, bool bUpdate)
{
	static auto oOverrideConfig = DTR::OverrideConfig.GetOriginal<decltype(&hkOverrideConfig)>();


	return oOverrideConfig(pThis, edx, pConfig, bUpdate);
}

bool FASTCALL H::hkIsHLTV(void* pThis, void* edx)
{
	static auto oIsHLTV = DTR::IsHLTV.GetOriginal<decltype(&hkIsHLTV)>();

	static auto uCalledFromSetupVelocity = MEM::FindPattern(CLIENT_DLL, "84 C0 75 38 8B 0D ?? ?? ?? ?? 8B 01 8B 80"); // 84 C0 75 38 8B 0D ?? ?? ?? ?? 8B 01 8B 80
	if ((uintptr_t)_ReturnAddress() == uCalledFromSetupVelocity)
		return true;

	return oIsHLTV(pThis, edx);
}

void* __fastcall H::hkAllocKeyValuesMemory(IKeyValuesSystem* thisptr, int edx, int iSize)
{
	static auto oAllocKeyValuesMemory = DTR::AllocKeyValuesMemory.GetOriginal<decltype(&hkAllocKeyValuesMemory)>();

	// return addresses of check function
	// @credits: danielkrupinski
	static const std::uintptr_t uAllocKeyValuesEngine = MEM::GetAbsoluteAddress(MEM::FindPattern(ENGINE_DLL, _("E8 ? ? ? ? 83 C4 08 84 C0 75 10 FF 75 0C")) + 0x1) + 0x4A;
	static const std::uintptr_t uAllocKeyValuesClient = MEM::GetAbsoluteAddress(MEM::FindPattern(CLIENT_DLL, _("E8 ? ? ? ? 83 C4 08 84 C0 75 10")) + 0x1) + 0x3E;

	if (const std::uintptr_t uReturnAddress = reinterpret_cast<std::uintptr_t>(_ReturnAddress()); uReturnAddress == uAllocKeyValuesEngine || uReturnAddress == uAllocKeyValuesClient)
		return nullptr;

	return oAllocKeyValuesMemory(thisptr, edx, iSize);
}

void FASTCALL H::hkGetColorModulation(void* ecx, void* edx, float* r, float* g, float* b)
{

}

//float c_anti_aim::fake_angle(float m_cur_view, bool m_invert, float m_max_rotation) {
//	float desync_delta;
//	float m_view_angles;
//	float m_max_angle;
//	float m_real_foot_yaw;
//	float m_real_ang;
//	float m_unk_time;
//	float m_desync_delta;
//	bool m_choke;
//	float m_unk_delta;
//	float m_choked_ang;
//
//	desync_delta = m_max_rotation;
//	m_view_angles = m_cur_view;
//
//	if (!m_invert)
//		desync_delta = -m_max_rotation;
//
//	m_max_angle = math::normalize_yaw(desync_delta + m_cur_view);
//	m_real_foot_yaw = g_client.m_rotation.y;
//	m_real_ang = math::normalize_yaw(m_flRealFootYaw - m_flMaxAngle);
//	m_unk_time = g_gucci_reverse.m_globals->m_interval * 102.0;
//
//	if (fabs(m_real_ang) <= (180.0 - (g_client.m_local->max_body_rotation() + m_unk_time))) = c_animations::body_rotation() {
//		m_desync_delta = g_client.m_local->max_body_rotation();
//		if (m_real_ang <= 0.0)
//			m_view_angles = m_desync_delta + m_max_angle;
//		else
//			m_view_angles = m_max_angle - m_desync_delta;
//	}
//	else {
//		m_desync_delta = g_client.m_local->max_body_rotation();
//		m_view_angles = m_max_angle;
//	}
//	m_choke = 1;
//	if (m_max_rotation >= m_desync_delta) {
//		m_unk_delta = m_real_foot_yaw - m_cur_view;
//		if (m_invert) {
//			if (m_unk_delta < m_max_rotation || m_unk_delta >= 179.0)
//			{
//				if (m_unk_delta > 0.0 && m_unk_delta < 179.0)
//					m_view_angles = m_cur_view + 120.0;
//			}
//		}
//		else if (-m_max_rotation < m_unk_delta || m_unk_delta <= -179.0) {
//			if (m_unk_delta < 0.0 && m_unk_delta > -179.0)
//				m_view_angles = m_cur_view - 120.0;
//		}
//	}
//
//	return math::normalize_yaw(m_view_angles);
//}
//



void FASTCALL H::hkLevelShutdown(void* pThis, void* edx)
{
	static auto oLevelShutdown = DTR::Shutdown.GetOriginal<decltype(&hkLevelShutdown)>();

	g_EntityCache.Clear();

	oLevelShutdown(pThis, edx);
}

std::vector<std::string> vWeaponNames = {
	("models/weapons/v_knife_bayonet.mdl"),
	("models/weapons/v_knife_flip.mdl"),
	("models/weapons/v_knife_gut.mdl"),
	("models/weapons/v_knife_karam.mdl"),
	("models/weapons/v_knife_m9_bay.mdl"),
	("models/weapons/v_knife_tactical.mdl"),
	("models/weapons/v_knife_falchion_advanced.mdl"),
	("models/weapons/v_knife_survival_bowie.mdl"),
	("models/weapons/v_knife_butterfly.mdl"),
	("models/weapons/v_knife_push.mdl"),
	("models/weapons/v_knife_ursus.mdl") ,
	("models/weapons/v_knife_gypsy_jackknife.mdl"),
	("models/weapons/v_knife_stiletto.mdl"),
	("models/weapons/v_knife_widowmaker.mdl"),
	("models/weapons/v_knife_css.mdl"),
	("models/weapons/v_knife_outdoor.mdl"),
	("models/weapons/v_knife_skeleton.mdl"),
	("models/weapons/v_knife_cord.mdl"),
	("models/weapons/v_knife_canis.mdl"),
};

int random_sequence(int low, int high) {
	return rand() % (high - low + 1) + low;
}

std::unordered_map<std::string, int(*)(int)> animation_fix_map{
	{ ("models/weapons/v_knife_butterfly.mdl"), [](int sequence) -> int
	{
		switch (sequence)
			{
			case SEQUENCE_DEFAULT_DRAW:
				return random_sequence(SEQUENCE_BUTTERFLY_DRAW, SEQUENCE_BUTTERFLY_DRAW2);
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(SEQUENCE_BUTTERFLY_LOOKAT01, SEQUENCE_BUTTERFLY_LOOKAT03);
			default:
				return sequence + 1;
			}
	} },
	{ ("models/weapons/v_knife_falchion_advanced.mdl"), [](int sequence) -> int
	{
		switch (sequence)
			{
			case SEQUENCE_DEFAULT_IDLE2:
				return SEQUENCE_FALCHION_IDLE1;
			case SEQUENCE_DEFAULT_HEAVY_MISS1:
				return random_sequence(SEQUENCE_FALCHION_HEAVY_MISS1, SEQUENCE_FALCHION_HEAVY_MISS1_NOFLIP);
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(SEQUENCE_FALCHION_LOOKAT01, SEQUENCE_FALCHION_LOOKAT02);
			case SEQUENCE_DEFAULT_DRAW:
			case SEQUENCE_DEFAULT_IDLE1:
				return sequence;
			default:
				return sequence - 1;
			}
	} },
	{ ("models/weapons/v_knife_css.mdl"), [](int sequence) -> int
	{
		switch (sequence)
		{
		case SEQUENCE_DEFAULT_LOOKAT01:
			return 15;
		default:
			return sequence;
		}
	} },
	{ ("models/weapons/v_knife_push.mdl"), [](int sequence) -> int
	{
		switch (sequence)
			{
			case SEQUENCE_DEFAULT_IDLE2:
				return SEQUENCE_DAGGERS_IDLE1;
			case SEQUENCE_DEFAULT_LIGHT_MISS1:
			case SEQUENCE_DEFAULT_LIGHT_MISS2:
				return random_sequence(SEQUENCE_DAGGERS_LIGHT_MISS1, SEQUENCE_DAGGERS_LIGHT_MISS5);
			case SEQUENCE_DEFAULT_HEAVY_MISS1:
				return random_sequence(SEQUENCE_DAGGERS_HEAVY_MISS2, SEQUENCE_DAGGERS_HEAVY_MISS1);
			case SEQUENCE_DEFAULT_HEAVY_HIT1:
			case SEQUENCE_DEFAULT_HEAVY_BACKSTAB:
			case SEQUENCE_DEFAULT_LOOKAT01:
				return sequence + 3;
			case SEQUENCE_DEFAULT_DRAW:
			case SEQUENCE_DEFAULT_IDLE1:
				return sequence;
			default:
				return sequence + 2;
			}
	} },
	{ ("models/weapons/v_knife_survival_bowie.mdl"), [](int sequence) -> int
	{
		switch (sequence)
			{
			case SEQUENCE_DEFAULT_DRAW:
			case SEQUENCE_DEFAULT_IDLE1:
				return sequence;
			case SEQUENCE_DEFAULT_IDLE2:
				return SEQUENCE_BOWIE_IDLE1;
			default:
				return sequence - 1;
			}
	} },
	{ ("models/weapons/v_knife_ursus.mdl"), [](int sequence) -> int
	{
		switch (sequence)
			{
			case SEQUENCE_DEFAULT_DRAW:
				return random_sequence(SEQUENCE_BUTTERFLY_DRAW, SEQUENCE_BUTTERFLY_DRAW2);
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(SEQUENCE_BUTTERFLY_LOOKAT01, 14);
			default:
				return sequence + 1;
			}
	} },
	{ ("models/weapons/v_knife_stiletto.mdl"), [](int sequence) -> int
	{
		switch (sequence)
			{
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(12, 13);
			default:
				return sequence;
			}
	} },
	{ ("models/weapons/v_knife_widowmaker.mdl"), [](int sequence) -> int
	{
		switch (sequence)
			{
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(14, 15);
			default:
				return sequence;
			}
	} },
	{ ("models/weapons/v_knife_cord.mdl"), [](int sequence) -> int
	{
		switch (sequence)
			{
			case SEQUENCE_DEFAULT_DRAW:
				return random_sequence(SEQUENCE_BUTTERFLY_DRAW, SEQUENCE_BUTTERFLY_DRAW2);
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(SEQUENCE_BUTTERFLY_LOOKAT01, 14);
			default:
				return sequence + 1;
			}
	} },
	{ ("models/weapons/v_knife_canis.mdl"), [](int sequence) -> int
	{
			switch (sequence)
			{
			case SEQUENCE_DEFAULT_DRAW:
				return random_sequence(SEQUENCE_BUTTERFLY_DRAW, SEQUENCE_BUTTERFLY_DRAW2);
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(SEQUENCE_BUTTERFLY_LOOKAT01, 14);
			default:
				return sequence + 1;
			}
	} },
	{ ("models/weapons/v_knife_outdoor.mdl"), [](int sequence) -> int
	{
			switch (sequence)
			{
			case SEQUENCE_DEFAULT_DRAW:
				return random_sequence(SEQUENCE_BUTTERFLY_DRAW, SEQUENCE_BUTTERFLY_DRAW2);
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(SEQUENCE_BUTTERFLY_LOOKAT01, 14);
			default:
				return sequence + 1;
			}
	} },
	{ ("models/weapons/v_knife_skeleton.mdl"), [](int sequence) -> int
	{
			switch (sequence)
			{
			case SEQUENCE_DEFAULT_DRAW:
				return random_sequence(SEQUENCE_BUTTERFLY_DRAW, SEQUENCE_BUTTERFLY_DRAW2);
			case SEQUENCE_DEFAULT_LOOKAT01:
				return random_sequence(SEQUENCE_BUTTERFLY_LOOKAT01, 14);
			default:
				return sequence + 1;
			}
	} }
};

#pragma region proxies_get
bool P::Setup()
{
	RecvProp_t* pSequence = CNetvarManager::Get().mapProps[FNV1A::HashConst(_("CBaseViewModel->m_nSequence"))].pRecvProp;
	if (!pSequence)
		return false;

	RVP::Sequence = std::make_shared<CRecvPropHook>(pSequence, P::Sequence);

	return true;
}

void P::Restore()
{
	RVP::BaseViewModel->~CRecvPropHook();
}
#pragma endregion

#pragma region proxies_handlers
void P::Sequence(const CRecvProxyData* pData, void* pStruct, void* pOut)
{
	static auto oSequence = RVP::Sequence->GetOriginal();

	if (!G::pLocal || !G::pLocal->IsAlive())
	{
		oSequence(pData, pStruct, pOut);
		return;
	}

	CRecvProxyData* pProxyData = const_cast<CRecvProxyData*>(pData);
	CBaseViewModel* pViewModel = static_cast<CBaseViewModel*>(pStruct);

	if (pViewModel && pViewModel->GetOwnerHandle())
	{
		if (G::pLocal->GetWeapon() && C::Get<int>(Vars.iKnifeModel)) {
			auto pKnifeModel = I::ModelInfo->GetModel(pViewModel->GetModelIndex());
			auto szKnifeName = I::ModelInfo->GetModelName(pKnifeModel);

			if (animation_fix_map.count(szKnifeName))
				pProxyData->Value.Int = animation_fix_map.at(szKnifeName)(pProxyData->Value.Int);
		}
	}

	oSequence(pProxyData, pStruct, pOut);
}
#pragma endregion