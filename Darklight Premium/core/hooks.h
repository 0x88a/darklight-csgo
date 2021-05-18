#pragma once
// used: winapi, directx, fmt includes
#include "../common.h"
// used: hook setup/destroy
#include "../utilities/detourhook.h"
// used: recvprop hook setup/destroy, recvproxydata
#include "netvar.h"
// used: baseclasses
#include "interfaces.h"

#ifndef FASTCALL
#define FASTCALL __fastcall
#endif

/*
* VTABLE INDEXES
* functions indexes in their virtual tables
*/
namespace VTABLE
{
	// work with namespace cuz if use enum class need additional convert to int
	enum
	{
		/* directx table */
		RESET = 16,
		PRESENT = 17,
		ENDSCENE = 42,
		RESETEX = 132,

		/* client table */
		FRAMESTAGENOTIFY = 37,

		/* panel table */
		PAINTTRAVERSE = 41,

		/* clientmode table */
		OVERRIDEVIEW = 18,
		OVERRIDEMOUSEINPUT = 23,
		CREATEMOVE = 24,
		GETVIEWMODELFOV = 35,
		DOPOSTSCREENEFFECTS = 44,

		/* modelrender table */
		DRAWMODELEXECUTE = 21,

		/* studiorender table */
		DRAWMODEL = 29,

		/* engine table */
		ISCONNECTED = 27,

		/* bsp query table */
		LISTLEAVESINBOX = 6,

		/* prediction table */
		RUNCOMMAND = 19,

		/* steamgamecoordinator table */
		SENDMESSAGE = 0,
		RETRIEVEMESSAGE = 2,

		/* sound table */
		EMITSOUND = 5,

		/* materialsystem table */
		OVERRIDECONFIG = 21,
		FINDMATERIAL = 84,

		/* renderview table */
		SCENEEND = 9,

		/* surface table */
		LOCKCURSOR = 67,
		PLAYSOUND = 82,

		/* gameevent table */
		FIREEVENT = 9,

		/* convar table */
		GETBOOL = 13,

		/* netchannel table */
		SENDNETMSG = 40,
		SENDDATAGRAM = 46,
	};
}

/*
 * DETOURS
 * detour hook managers
 */
namespace DTR
{
	inline CDetourHook Reset;
	inline CDetourHook Present;
	inline CDetourHook FrameStageNotify;
	inline CDetourHook OverrideView;
	inline CDetourHook OverrideMouseInput;
	inline CDetourHook OverrideConfig;
	inline CDetourHook CreateMove;
	inline CDetourHook SendNetMsg;
	inline CDetourHook SendDatagram;
	inline CDetourHook GetViewModelFOV;
	inline CDetourHook DoPostScreenEffects;
	inline CDetourHook IsConnected;
	inline CDetourHook ListLeavesInBox;
	inline CDetourHook PaintTraverse;
	inline CDetourHook DrawModel;
	inline CDetourHook RunCommand;
	inline CDetourHook SendMessageGC;
	inline CDetourHook RetrieveMessage;
	inline CDetourHook EmitSound;
	inline CDetourHook LockCursor;
	inline CDetourHook PlaySoundSurface;
	inline CDetourHook SvCheatsGetBool;
	inline CDetourHook FindMaterial;
	inline CDetourHook SceneEnd;
	inline CDetourHook FireEvent;
	inline CDetourHook DrawModelExecute;
	inline CDetourHook IsHLTV;
	inline CDetourHook IsPaused;
	inline CDetourHook LevelInitPostEntity;
	inline CDetourHook CsmShadowGetInt;
	inline CDetourHook WeaponDebugSpreadShow;
	inline CDetourHook CrosshairRecoil;
	inline CDetourHook ShouldDrawFog;
	inline CDetourHook FireGameEvent;
	inline CDetourHook Shutdown;
	inline CDetourHook GetColorModulation;
}

/*
 * HOOKS
 * swap functions with given pointers
 */
namespace H
{
	// Get
	bool	Setup();
	void	Restore();

	// Handlers
	/* [type][call]		hk[name] (args...) */
	//long	D3DAPI		hkReset(IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* pPresentationParameters);
	//long	D3DAPI		hkPresent(IDirect3DDevice9* pDevice, RECT* pSourceRect, RECT* pDestRect, HWND hDestWindowOverride, RGNDATA* pDirtyRegion);
	bool	FASTCALL	hkCreateMove(IClientModeShared* thisptr, int edx, float flInputSampleTime, CUserCmd* pCmd);
	void	FASTCALL	hkPaintTraverse(ISurface* thisptr, int edx, unsigned int uPanel, bool bForceRepaint, bool bForce);
	void	FASTCALL	hkLockCursor(ISurface* thisptr, int edx);
	void	FASTCALL	hkFrameStageNotify(IBaseClientDll* thisptr, int edx, EClientFrameStage stage);
	void	FASTCALL	hkDrawModel(IStudioRender* thisptr, int edx, DrawModelResults_t* pResults, const DrawModelInfo_t& info, matrix3x4_t* pBoneToWorld, float* flFlexWeights, float* flFlexDelayedWeights, const Vector& vecModelOrigin, int nFlags);
	bool	FASTCALL	hkIsConnected(IEngineClient* thisptr, int edx);
	bool	FASTCALL	hkSendNetMsg(INetChannel* thisptr, int edx, INetMessage* pMessage, bool bForceReliable, bool bVoice);
	void	FASTCALL	hkOverrideView(IClientModeShared* thisptr, int edx, CViewSetup* pSetup);
	int		FASTCALL	hkDoPostScreenEffects(IClientModeShared* thisptr, int edx, CViewSetup* pSetup);
	void	FASTCALL	hkRunCommand(IPrediction* thisptr, int edx, CBaseEntity* pEntity, CUserCmd* pCmd, IMoveHelper* pMoveHelper);
	int		FASTCALL	hkSendMessage(ISteamGameCoordinator* thisptr, int edx, std::uint32_t uMsgType, const void* pData, std::uint32_t uData);
	int		FASTCALL	hkRetrieveMessage(ISteamGameCoordinator* thisptr, int edx, std::uint32_t* puMsgType, void* pDest, std::uint32_t uDest, std::uint32_t* puMsgSize);
	bool	FASTCALL	hkSvCheatsGetBool(CConVar* thisptr, int edx);
	long	CALLBACK	hkWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	void	FASTCALL	hkSceneEnd(void* _this);
	bool    FASTCALL    hkOverrideConfig(void* pThis, void* edx, MaterialSystemConfig_t* pConfig, bool bUpdate);
	void	FASTCALL	hkLevelShutdown(void* pThis, void* edx);
	bool	FASTCALL	hkFireGameEvent(void* pThis, void* edx, IGameEvent* pEvent);
	void	FASTCALL	hkGetColorModulation(void* ecx, void* edx, float* r, float* g, float* b);

	// Animation fix stuff.

	// Return false.
	// sig: "57 8B F9 8B 07 8B 80 ? ? ? ? FF D0 84 C0 75 02"
	bool	FASTCALL	hkShouldSkipAnimationFrames(void* pThis, void* edx);

	// Return.
	// sig: "55 8B EC 83 E4 F0 83 EC 78 56 8B F1 57 8B 56"
	void	FASTCALL	hkDoProceduralFootPlant(void* pThis, void* edx, void* pBoneToWorld, void* pLeftFootChain, void* pRightFootChain, void* pPos);
	
	// Cast pThis to a play and set is_jiggle_bones_enabled to false, then return orignal.
	// sig: "55 8B EC 56 8B 75 18 57"
	// is_jiggle_bones_enabled: offset of "DT_CSPlayer=>m_hLightingOrigin" - 0x18
	void	FASTCALL	hkBuildTransformations(void* pThis, void* edx, void* hdr, void* pPos, void* q, const void* pCameraTransform, int iMask, void* pBoneComputed);
	
	// Return original, that's it.
	// sig: "55 8B EC 51 53 8B 5D 08 56 8B F1 57 85"
	void	FASTCALL	hkCheckForSequenceChange(void* pThis, void* edx, void* hdr, int iCurSequence, bool bForceNewSequence, bool bInterpolate);
	
	// interface: VEngineClient
	// index: 93
	// static const auto setup_velocity = shared::pattern::find( "client.dll", "84 C0 75 38 8B 0D ? ? ? ? 8B 01 8B 80" );
	// static const auto accumulate_layers = shared::pattern::find( "client.dll", "84 C0 75 0D F6 87" );
	// Check returnaddress for those, return true, otherwise return original.
	bool	FASTCALL	hkIsHLTV(void* pThis, void* edx);

	// sig: "55 8B EC 83 E4 F0 B8 ? ? ? ? E8 ? ? ? ? 56 8B 75 08 57 8B F9 85 F6"
	// m_effects: "8B 87 ? ? ? ? C1 E8 03 C6" + 0x2
	// !( player->get_effects( ) & 8 ) set it, run original, then player->get_effects( ) &= ~8;
	void	FASTCALL	hkStandardBlendingRules(void* pThis, void* edx, void* hdr, void* pPos, void* q, float flCurrentTime, int iMask);
	
	// sig: "55 8B EC 83 EC 14 53 56 57 FF 75 18"
	// use_new_animation_state = "88 87 ? ? ? ? 75" + 0x2
	// Check if player is local, if not, return original, set use_new_animation_state to false, run original, restore it back.
	void	FASTCALL	hkCalculateView(void* pThis, void* edx, Vector& eye_origin, QAngle& eye_angles, float& z_near, float& z_far, float& fov);

	// sig: "55 8B EC 83 E4 F8 83 EC 5C 53 8B D9 56 57 83"
	// m_smooth_height_valid : at 0x32c in animation_state
	// Cast pTHis to animstate, set m_smooth_height_valid to false, return original after.
	void	FASTCALL	hkModifyEyePosition(void* pThis, void* edx, Vector& vecInputEyePosition);

	// sig: "55 8B EC 83 E4 F8 83 EC 18 56 57 8B F9 F3"
	// m_player : at 0x60 in animation_state
	// m_last_update_frame : at 0x70 in animation_state
	// m_angle is the local players real angle
	/*const auto animation_state = reinterpret_cast<sdk::player_animation_state*>(this_pointer);

	// allow animations to be animated in the same frame
	if (animation_state->m_last_update_frame == interfaces::m_global_vars->m_frame_count)
		animation_state->m_last_update_frame -= 1;

	const auto player = animation_state->m_player;

	if (player != globals::m_local_player)
		return original_update_animation_state(this_pointer, unknown, z, y, x, unknown1);

	const auto angle = features::m_animations.m_angle;

	return original_update_animation_state(this_pointer, unknown, z, angle.y, angle.x, unknown1);*/
	void	__vectorcall hkUpdateAnimationState(void* pThis, void* edx, float z, float y, float x, void* pUnknown);


	// sig: "55 8B EC 51 56 8B F1 80 BE ? ? ? ? ? 74"
	// m_should_animate : is set to true on each new tick
	/* 
	const auto player = reinterpret_cast< sdk::cs_player* >( this_pointer );
 
	if ( player != globals::m_local_player )
		return original_update_client_side_animation( this_pointer, edx );
 
	// only update local animations each tick
	if ( globals::m_should_animate )
		original_update_client_side_animation( this_pointer, edx );
	*/
	void	FASTCALL	hkUpdateClientSideAnimation(void* pThis, void* edx);

	/*
	    get_animation_state: "8B 8E ? ? ? ? 85 C9 74 3E" + 0x2
    m_should_animate: is set to true on each new tick
    get_animation_overlay: "8B 80 ? ? ? ? 8D 34 C8" + 0x2
    update_client_side_animation: index 223 of CSPlayer
    m_choked_commands: at 0x4d30 in ClientState
    m_foot_yaw: at 0x80 in animation_state
    get_pose_parameter: "DT_CSPlayer=>m_flPoseParameter"
    set_absolute_angles: "55 8B EC 83 E4 F8 83 EC 64 53 56 57 8B F1"
     
    inline void get_animation_layers( animation_layer* layers ) {
     
    	std::memcpy( layers, get_animation_overlay( ), sizeof( animation_layer ) * 13 );
     
    }
     
    inline void set_animation_layers( animation_layer* layers ) {
     
    	std::memcpy( get_animation_overlay( ), layers, sizeof( animation_layer ) * 13 );
     
    }
     
    inline void get_pose_parameters( float* poses ) {
     
    	std::memcpy( poses, get_pose_parameter( ), sizeof( float ) * 24 );
     
    }
     
    inline void set_pose_parameters( float* poses ) {
     
    	std::memcpy( get_pose_parameter( ), poses, sizeof( float ) * 24 );
     
    }	
     
    class animations {
    public:
     
    	// public functions
     
    	void update_local_animations( );
     
    public:
     
    	// class members
     
    	shared::angle m_angle;
     
    private:
     
    	// class members
     
    	shared::angle m_rotation;
     
    	sdk::animation_layer m_layers[ 13 ];
     
    	float m_poses[ 24 ];
     
    };
     
    void animations::update_local_animations( ) {
     
    	if ( !globals::m_local_player )
    		return;
     
    	const auto animation_state = globals::m_local_player->get_animation_state( );
     
    	if ( !animation_state )
    		return;
     
    	if ( globals::m_should_animate ) {
     
    		// get real layers
    		globals::m_local_player->get_animation_layers( m_layers );
     
    		// update animations
    		globals::m_local_player->update_client_side_animation( );
     
    		// the choke cycle has reset
    		if ( !interfaces::m_client_state->m_choked_commands ) {
     
    			m_rotation.y = animation_state->m_foot_yaw;
     
    			globals::m_local_player->get_pose_parameters( m_poses );
     
    		}
     
    		globals::m_should_animate = false;
     
    	}		
     
    	// update layers, poses, and rotation
    	globals::m_local_player->set_animation_layers( m_layers );
    	globals::m_local_player->set_pose_parameters( m_poses );
    	globals::m_local_player->set_absolute_angles( m_rotation );
     
    }
	*/
}

/*
 * RECV VAR PROXY MANAGERS
 * proxy property hook managers
 */
namespace RVP
{
	inline std::shared_ptr<CRecvPropHook> BaseViewModel;
	inline std::shared_ptr<CRecvPropHook> Sequence;
}

/*
 * PROXIES
 * networkable property proxy swap functions
 */
namespace P
{
	// Get
	bool	Setup();
	void	Restore();

	// Handlers
	//void	BaseViewModel(const CRecvProxyData* pData, void* pStruct, void* pOut);
	void	Sequence(const CRecvProxyData* pData, void* pStruct, void* pOut);
}
