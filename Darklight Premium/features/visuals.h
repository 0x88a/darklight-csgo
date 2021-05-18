#pragma once
#include <deque>
#include "../common.h"
#include "../sdk/datatypes/vector.h"
#include "../sdk/datatypes/color.h"
#include "../sdk/entity.h"
#include "../sdk/interfaces/igameeventmanager.h"
#include "../core/interfaces.h"
#include "../global.h"

struct BBox_t {
	BBox_t() = default;
	BBox_t(float _flX, float _flY, float _flW, float _flH)
	{
		flX = _flX;
		flY = _flY;
		flW = _flW;
		flH = _flH;
	}

	float flX;
	float flY;
	float flW;
	float flH;
};

struct EventLogging_t {
	EventLogging_t(std::string _string) {
		szText = _string;
		flTime = I::Globals->flCurrentTime;
	}

	std::string szText;
	float flTime;
	int flAlpha = 255;
};

struct MovementData_t
{
	MovementData_t() = default;
	MovementData_t(float _flVelocity, bool _bOnGround) {
		flvelocity = _flVelocity;
		bOnGround = _bOnGround;
	}

	float flvelocity;
	bool bOnGround;
};

class CFlashLightEffect
{
public:
	bool m_bIsOn; //0x0000 
	char pad_0x0001[0x3]; //0x0001
	int m_nEntIndex; //0x0004 
	WORD m_FlashLightHandle; //0x0008 
	char pad_0x000A[0x2]; //0x000A
	float m_flMuzzleFlashBrightness; //0x000C 
	float m_flFov; //0x0010 
	float m_flFarZ; //0x0014 
	float m_flLinearAtten; //0x0018 
	bool m_bCastsShadows; //0x001C 
	char pad_0x001D[0x3]; //0x001D
	float m_flCurrentPullBackDist; //0x0020 
	DWORD m_MuzzleFlashTexture; //0x0024 
	DWORD m_FlashLightTexture; //0x0028 
	char m_szTextureName[64]; //0x1559888 
}; //Size=0x006C


class CVisuals
{
public:
	void Run();

	IMaterial* CreateMaterial(std::string_view szName, std::string_view szShader, std::string_view szBaseTexture = _("vgui/white_additive"), std::string_view szEnvMap = "", bool bIgnorez = false, bool bWireframe = false, std::string_view szProxies = "");

	bool Chams(CBaseEntity* pLocal, DrawModelResults_t* pResults, const DrawModelInfo_t& info, matrix3x4_t* pBoneToWorld, float* flFlexWeights, float* flFlexDelayedWeights, const Vector& vecModelOrigin, int nFlags);
	
	void Glow(CBaseEntity* pLocal);


	void OverrideView(CViewSetup* setup);
	void Paint();

	void Event(IGameEvent* pEvent, const FNV1A_t uNameHash);
	void Hitmarker();

	float m_flHitmarkerTime = 0.0f;

	std::vector<EventLogging_t> vecEventVector;
	bool m_bGrabbingSpectatorList;

	void PaintMovementData();
	void GatherMovementData();
	std::vector<MovementData_t> vecMovementData;

	CFlashLightEffect* create_flashlight(int, const char*, float, float, float);
	void destroy_flashlight(CFlashLightEffect*);
	void update_flashlight(CFlashLightEffect*, const Vector&, const Vector&, const Vector&, const Vector&);
	void run_flashlight();

	inline CBaseEntity* LocalPlayerOrSpectatedPlayer()
	{
		if (!G::pLocal)
			return nullptr;

		if (G::pLocal->IsAlive())
			return G::pLocal;

		CBaseEntity* pTarget;
		const auto pObserver = G::pLocal->GetObserverTargetHandle();
		if (pObserver)
		{
			const auto pTarget = I::ClientEntityList->Get<CBaseEntity>(pObserver);
			if (pTarget && pTarget->IsPlayer() && pTarget->IsAlive())
				return pTarget;
		}

		return nullptr;
	}

	std::vector< IMaterial* > vecWorld, vecProps;

private:
	enum GrenadeFlags : size_t {
		NONE = 0,
		DETONATE,
		BOUNCE,
	};

	struct Bounce_t {
		Vector vecPoint;
		Color  colColor;
	};

	using Path_t = std::vector< Vector >;
	using Bounces_t = std::vector< Bounce_t >;

	Path_t    m_vecPath;
	Bounces_t m_vecBounces;

	int       m_iID, m_iCollisionGroup;
	float     m_flVel, m_flPower;
	Vector	  m_vecStart, m_vecVelocity, m_vecMove;
	CBaseEntity* m_pLocal, *m_pCollisionEntity;

	void	Reset();
	void	Setup();
	void	Simulate(CViewSetup* setup);
	size_t	Advance(size_t tick);
	bool	CheckDetonate(const Trace_t& tr, int tick);
	void	ResolveFlyCollisionBounce(Trace_t& tr);
	void	PhysicsPushEntity(Vector& start, const Vector& move, Trace_t& trace, CBaseEntity* ent);
	void	TraceHull(const Vector& start, const Vector& end, Trace_t& trace, CBaseEntity* ent);
	void	PhysicsAddGravityMove(Vector& move);
	void	PhysicsClipVelocity(const Vector& in, const Vector& normal, Vector& out, float overbounce);


	void CollectEntities();

	void PaintPlayers(CBaseEntity* pEntity);
	void PaintGrenades(CBaseEntity* pEntity);
	void PaintWeapons(CBaseEntity* pEntity);
	void PaintC4(CBaseEntity* pEntity);

	bool CreateBBox(CBaseEntity* pEntity, BBox_t& bbox);

	bool WorldToScreen(const Vector& vOrigin, Vector& vScreen);

	void Crosshair();

	void SpectatorList(CBaseEntity* pEntity);
	void SpectatorFrame();

	void Watermark();

	void no_flash();
	void keystrokes();

	Vector2D m_vecPos = { 250, 250 };
	Vector2D m_vecSize;
	int m_iTotalSpectators;

	float m_flEntityAlpha[4096];
	float m_flTimeSinceDormant[4096];
	bool  m_bTimeSet[4096];

	void RunEventLogs();

	float flTextTime = 7.f;
	float flTextFadeInTime = 0.3f;
	float flTextFadeOutTime = 0.2f;
	int flIdealHeight = 1;
	int flIdealWidth = 1;
	int flSlideInDistance = 20;
	int flSlideOutDistance = 20;
	float flSlideOutSpeed = 0.3f;
};

extern CVisuals g_Visuals;