#include "skinchanger.h"

#include "../utilities/logging.h"
#include "../sdk/hash/md5.h"
#include "../core/interfaces.h"
#include "../utilities.h"
#include "../core/variables.h"

CSkinchanger g_Skinchanger;

std::vector<Item_t> weapon_info = {
	{ WEAPON_KNIFE_BAYONET, ("models/weapons/v_knife_bayonet.mdl") },
	{ WEAPON_KNIFE_FLIP, ("models/weapons/v_knife_flip.mdl") },
	{ WEAPON_KNIFE_GUT, ("models/weapons/v_knife_gut.mdl") },
	{ WEAPON_KNIFE_KARAMBIT, ("models/weapons/v_knife_karam.mdl") },
	{ WEAPON_KNIFE_M9_BAYONET, ("models/weapons/v_knife_m9_bay.mdl") },
	{ WEAPON_KNIFE_TACTICAL, ("models/weapons/v_knife_tactical.mdl") },
	{ WEAPON_KNIFE_FALCHION, ("models/weapons/v_knife_falchion_advanced.mdl") },
	{ WEAPON_KNIFE_SURVIVAL_BOWIE, ("models/weapons/v_knife_survival_bowie.mdl") },
	{ WEAPON_KNIFE_BUTTERFLY, ("models/weapons/v_knife_butterfly.mdl")  },
	{ WEAPON_KNIFE_PUSH, ("models/weapons/v_knife_push.mdl") },
	{ WEAPON_KNIFE_URSUS, ("models/weapons/v_knife_ursus.mdl")  },
	{ WEAPON_KNIFE_GYPSY_JACKKNIFE, ("models/weapons/v_knife_gypsy_jackknife.mdl") },
	{ WEAPON_KNIFE_STILETTO, ("models/weapons/v_knife_stiletto.mdl") },
	{ WEAPON_KNIFE_WIDOWMAKER, ("models/weapons/v_knife_widowmaker.mdl") },
	{ WEAPON_KNIFE_CSS, ("models/weapons/v_knife_css.mdl") },
	{ WEAPON_KNIFE_OUTDOOR, ("models/weapons/v_knife_outdoor.mdl") },
	{ WEAPON_KNIFE_SKELETON, ("models/weapons/v_knife_skeleton.mdl") },
	{ WEAPON_KNIFE_CORD, ("models/weapons/v_knife_cord.mdl") },
	{ WEAPON_KNIFE_CANIS, ("models/weapons/v_knife_canis.mdl") },
	{ GLOVE_STUDDED_BLOODHOUND, "models/weapons/v_models/arms/glove_bloodhound/v_glove_bloodhound.mdl" },
	{ GLOVE_SPORTY, "models/weapons/v_models/arms/glove_sporty/v_glove_sporty.mdl" },
	{ GLOVE_SLICK, "models/weapons/v_models/arms/glove_slick/v_glove_slick.mdl" },
	{ GLOVE_LEATHER_WRAP, "models/weapons/v_models/arms/glove_handwrap_leathery/v_glove_handwrap_leathery.mdl" },
	{ GLOVE_MOTORCYCLE, "models/weapons/v_models/arms/glove_motorcycle/v_glove_motorcycle.mdl" },
	{ GLOVE_SPECIALIST, "models/weapons/v_models/arms/glove_specialist/v_glove_specialist.mdl" },
	{ GLOVE_STUDDED_HYDRA, "models/weapons/v_models/arms/glove_bloodhound/v_glove_bloodhound_hydra.mdl" },
	{ GLOVE_STUDDED_BROKENFANG, "models/weapons/v_models/arms/glove_bloodhound/v_glove_bloodhound_brokenfang.mdl" }
};

std::vector<int> vecWeapons = {
	WEAPON_AK47,
	WEAPON_AUG,
	WEAPON_AWP,
	WEAPON_CZ75A, 
	WEAPON_DEAGLE,
	WEAPON_ELITE,
	WEAPON_FAMAS,
	WEAPON_FIVESEVEN,
	WEAPON_G3SG1,
	WEAPON_GALILAR,
	WEAPON_GLOCK,
	WEAPON_M249,
	WEAPON_M4A1_SILENCER,
	WEAPON_M4A1,
	WEAPON_MAC10,
	WEAPON_MAG7,
	WEAPON_MP5SD,
	WEAPON_MP7,
	WEAPON_MP9,
	WEAPON_NEGEV,
	WEAPON_NOVA,
	WEAPON_HKP2000,
	WEAPON_P250,
	WEAPON_P90,
	WEAPON_BIZON,
	WEAPON_REVOLVER,
	WEAPON_SAWEDOFF, 
	WEAPON_SCAR20, 
	WEAPON_SSG08,
	WEAPON_SG556,
	WEAPON_TEC9,
	WEAPON_UMP45,
	WEAPON_USP_SILENCER,
	WEAPON_XM1014,
	WEAPON_KNIFE_BAYONET,
	WEAPON_KNIFE_FLIP,
	WEAPON_KNIFE_GUT,
	WEAPON_KNIFE_KARAMBIT, 
	WEAPON_KNIFE_M9_BAYONET,
	WEAPON_KNIFE_TACTICAL,
	WEAPON_KNIFE_FALCHION, 
	WEAPON_KNIFE_SURVIVAL_BOWIE,
	WEAPON_KNIFE_BUTTERFLY,
	WEAPON_KNIFE_PUSH,
	WEAPON_KNIFE_URSUS, 
	WEAPON_KNIFE_GYPSY_JACKKNIFE,
	WEAPON_KNIFE_STILETTO,
	WEAPON_KNIFE_WIDOWMAKER,
	WEAPON_KNIFE_CSS, 
	WEAPON_KNIFE_OUTDOOR,
	WEAPON_KNIFE_SKELETON,
	WEAPON_KNIFE_CORD,
	WEAPON_KNIFE_CANIS,
	GLOVE_STUDDED_BLOODHOUND,
	GLOVE_SPORTY,
	GLOVE_SLICK, 
	GLOVE_LEATHER_WRAP,
	GLOVE_MOTORCYCLE,
	GLOVE_SPECIALIST, 
	GLOVE_STUDDED_HYDRA,
	GLOVE_STUDDED_BROKENFANG
};

CreateClientClassFn GetWearableCreateFn() {
	auto client_class = I::Client->GetAllClasses();
	for (client_class = I::Client->GetAllClasses();
		client_class; client_class = client_class->pNext) 
	{
		if (client_class->nClassID == EClassIndex::CEconWearable)
			return client_class->pCreateFn;
	}
}

CBaseCombatWeapon* MakeGlove(int entry, int serial) {
	static auto WearableCreateFn = GetWearableCreateFn();
	WearableCreateFn(entry, serial);

	const auto glove = static_cast<CBaseCombatWeapon*>(I::ClientEntityList->GetClientEntity(entry));
	assert(glove); {
		static auto set_abs_origin_addr = MEM::FindPattern(CLIENT_DLL, "55 8B EC 83 E4 F8 51 53 56 57 8B F1 E8");
		const auto set_abs_origin_fn = reinterpret_cast<void(__thiscall*)(void*, const std::array<float, 3>&)>(set_abs_origin_addr);
		static constexpr std::array<float, 3> new_pos = { 10000.f, 10000.f, 10000.f };
		set_abs_origin_fn(glove, new_pos);
	}
	return glove;
}

bool ApplyGloveModel(CBaseCombatWeapon* glove, const char* model) {
	PlayerInfo_t info;
	I::Engine->GetPlayerInfo(I::Engine->GetLocalPlayer(), &info);
	glove->GetAccountID() = info.nXuidLow;
	*reinterpret_cast<int*>(uintptr_t(glove) + 0x64) = -1;
	return true;
}

bool ApplyGloveSkin(CBaseCombatWeapon* glove, int item_definition_index, int paint_kit, const char* model_index, int entity_quality, float fallback_wear) {
	*glove->GetItemDefinitionIndex() = item_definition_index;
	glove->GetFallbackPaintKit() = paint_kit;
	glove->SetModelIndex(I::ModelInfo->GetModelIndex(model_index));
	glove->GetEntityQuality() = entity_quality;
	glove->GetFallbackWear() = fallback_wear;

	return true;
}

void RunGlove() {
	if (!G::pLocal)
		return;

	CBaseHandle* wearables = G::pLocal->GetWearablesHandle();
	if (!wearables) { return; }

	static uintptr_t glove_handle = uintptr_t(0);

	auto glove = reinterpret_cast<CBaseCombatWeapon*>(I::ClientEntityList->GetClientEntityFromHandle(wearables[0]));

	if (!glove) {
		auto our_glove = reinterpret_cast<CBaseCombatWeapon*>(I::ClientEntityList->GetClientEntityFromHandle(glove_handle));
		if (our_glove) {
			wearables[0] = glove_handle;
			glove = our_glove;
		}
	}
	
	if (!G::pLocal->IsAlive()) {
		if (glove) {
			glove->SetDestroyedOnRecreateEntities();
			glove->Release();
		}
		return;
	}

	if (!glove) {
		const auto entry = I::ClientEntityList->GetHighestEntityIndex() + 1;
		const auto serial = rand() % 0x1000;
		glove = MakeGlove(entry, serial);   // He he
		wearables[0] = entry | serial << 16;
		glove_handle = wearables[0]; // Let's store it in case we somehow lose it.
	}

	if (glove) {
		switch (C::Get<int>(Vars.iGloveModel)) {
			case 1: ApplyGloveModel(glove, weapon_info[19].model); ApplyGloveSkin(glove, weapon_info[19].id, atoi(C::Get<std::deque<std::string>>(Vars.vecGloveSkins).at(C::Get<int>(Vars.iGloveModel)).c_str()), weapon_info[19].model, 3, C::Get<std::deque<float>>(Vars.vecGloveWear).at(C::Get<int>(Vars.iGloveModel))); glove->GetFallbackStatTrak() = C::Get<std::deque<int>>(Vars.vecGloveSeed).at(C::Get<int>(Vars.iGloveModel)); break;
			case 2: ApplyGloveModel(glove, weapon_info[20].model); ApplyGloveSkin(glove, weapon_info[20].id, atoi(C::Get<std::deque<std::string>>(Vars.vecGloveSkins).at(C::Get<int>(Vars.iGloveModel)).c_str()), weapon_info[20].model, 3, C::Get<std::deque<float>>(Vars.vecGloveWear).at(C::Get<int>(Vars.iGloveModel))); glove->GetFallbackStatTrak() = C::Get<std::deque<int>>(Vars.vecGloveSeed).at(C::Get<int>(Vars.iGloveModel)); break;
			case 3: ApplyGloveModel(glove, weapon_info[21].model); ApplyGloveSkin(glove, weapon_info[21].id, atoi(C::Get<std::deque<std::string>>(Vars.vecGloveSkins).at(C::Get<int>(Vars.iGloveModel)).c_str()), weapon_info[21].model, 3, C::Get<std::deque<float>>(Vars.vecGloveWear).at(C::Get<int>(Vars.iGloveModel))); glove->GetFallbackStatTrak() = C::Get<std::deque<int>>(Vars.vecGloveSeed).at(C::Get<int>(Vars.iGloveModel)); break;
			case 4: ApplyGloveModel(glove, weapon_info[22].model); ApplyGloveSkin(glove, weapon_info[22].id, atoi(C::Get<std::deque<std::string>>(Vars.vecGloveSkins).at(C::Get<int>(Vars.iGloveModel)).c_str()), weapon_info[22].model, 3, C::Get<std::deque<float>>(Vars.vecGloveWear).at(C::Get<int>(Vars.iGloveModel))); glove->GetFallbackStatTrak() = C::Get<std::deque<int>>(Vars.vecGloveSeed).at(C::Get<int>(Vars.iGloveModel)); break;
			case 5: ApplyGloveModel(glove, weapon_info[23].model); ApplyGloveSkin(glove, weapon_info[23].id, atoi(C::Get<std::deque<std::string>>(Vars.vecGloveSkins).at(C::Get<int>(Vars.iGloveModel)).c_str()), weapon_info[23].model, 3, C::Get<std::deque<float>>(Vars.vecGloveWear).at(C::Get<int>(Vars.iGloveModel))); glove->GetFallbackStatTrak() = C::Get<std::deque<int>>(Vars.vecGloveSeed).at(C::Get<int>(Vars.iGloveModel)); break;
			case 6: ApplyGloveModel(glove, weapon_info[24].model); ApplyGloveSkin(glove, weapon_info[24].id, atoi(C::Get<std::deque<std::string>>(Vars.vecGloveSkins).at(C::Get<int>(Vars.iGloveModel)).c_str()), weapon_info[24].model, 3, C::Get<std::deque<float>>(Vars.vecGloveWear).at(C::Get<int>(Vars.iGloveModel))); glove->GetFallbackStatTrak() = C::Get<std::deque<int>>(Vars.vecGloveSeed).at(C::Get<int>(Vars.iGloveModel)); break;
			case 7: ApplyGloveModel(glove, weapon_info[25].model); ApplyGloveSkin(glove, weapon_info[25].id, atoi(C::Get<std::deque<std::string>>(Vars.vecGloveSkins).at(C::Get<int>(Vars.iGloveModel)).c_str()), weapon_info[25].model, 3, C::Get<std::deque<float>>(Vars.vecGloveWear).at(C::Get<int>(Vars.iGloveModel))); glove->GetFallbackStatTrak() = C::Get<std::deque<int>>(Vars.vecGloveSeed).at(C::Get<int>(Vars.iGloveModel)); break;
			case 8: ApplyGloveModel(glove, weapon_info[26].model); ApplyGloveSkin(glove, weapon_info[26].id, atoi(C::Get<std::deque<std::string>>(Vars.vecGloveSkins).at(C::Get<int>(Vars.iGloveModel)).c_str()), weapon_info[26].model, 3, C::Get<std::deque<float>>(Vars.vecGloveWear).at(C::Get<int>(Vars.iGloveModel))); glove->GetFallbackStatTrak() = C::Get<std::deque<int>>(Vars.vecGloveSeed).at(C::Get<int>(Vars.iGloveModel)); break;
			default: return; break;
		}

		glove->GetItemIDHigh() = -1;
		glove->GetFallbackStatTrak() = -1;

		glove->PreDataUpdate(DATA_UPDATE_CREATED);
	}
}


void CSkinchanger::Run()
{
	RunGlove();

	CBaseEntity* pLocal = U::GetLocalPlayer();
	if (!pLocal || !pLocal->IsAlive())
		return;

	CBaseCombatWeapon* pActiveWeapon = pLocal->GetWeapon();
	if (!pActiveWeapon)
		return;

	PlayerInfo_t playerInfo;
	I::Engine->GetPlayerInfo(I::Engine->GetLocalPlayer(), &playerInfo);

	static int iKnifeModel = C::Get<int>(Vars.iKnifeModel);
	if (iKnifeModel != C::Get<int>(Vars.iKnifeModel))
		iKnifeModel = C::Get<int>(Vars.iKnifeModel);

	CBaseHandle* pMyWeapons = pLocal->GetWeaponsHandle();
	for (unsigned int i = 0; pMyWeapons[i] != INVALID_EHANDLE_INDEX; i++) {
		CBaseCombatWeapon* pWeapon = (CBaseCombatWeapon*)I::ClientEntityList->GetClientEntityFromHandle(pMyWeapons[i]);
		if (pWeapon)
		{
			// Filter out weapons that aren't our own.
			if (pWeapon->GetOwnerXuidLow() != playerInfo.nXuidLow)
				continue;

			// Change knife model.
			if (pActiveWeapon->GetClientClass()->nClassID == EClassIndex::CKnife && iKnifeModel > 0)
				ApplyKnifeModel(pWeapon, weapon_info[iKnifeModel - 1].model);

			// Apply knife skin.
			if (pWeapon->GetClientClass()->nClassID == EClassIndex::CKnife && iKnifeModel > 0)
				ApplyKnifeSkin(pWeapon, weapon_info[iKnifeModel - 1].model, weapon_info[iKnifeModel - 1].id, 0, 3, 0.0001f);

			// We really shouldn't do this, but whatever.
			// Loop thru all possible weapons and set their skins.
			for (auto j = 0; j < 60; j++)
			{
				if (*pWeapon->GetItemDefinitionIndex() == vecWeapons[j] && j < 53)
				{
					pWeapon->GetFallbackPaintKit() = atoi(C::Get<std::deque<std::string>>(Vars.vecSkinIDs).at(*pWeapon->GetItemDefinitionIndex()).c_str());
					pWeapon->GetFallbackWear() = C::Get<std::deque<float>>(Vars.vecSkinWear).at(*pWeapon->GetItemDefinitionIndex());
					pWeapon->GetFallbackSeed() = C::Get<std::deque<int>>(Vars.vecSkinSeed).at(*pWeapon->GetItemDefinitionIndex());
				}
			}
			
			// Force fallback values.
			pWeapon->GetItemIDHigh() = -1;

			// Fix stat-trak.
			pWeapon->GetAccountID() = playerInfo.nXuidLow;
			//pWeapon->GetOwnerXuidHigh() = 0;
			//pWeapon->GetOwnerXuidLow() = 0;
		}
	}
}

bool CSkinchanger::ApplyKnifeModel(CBaseCombatWeapon* pWeapon, const char* szModel)
{
	CBaseViewModel* pViewmodel = (CBaseViewModel*)I::ClientEntityList->GetClientEntityFromHandle(U::GetLocalPlayer()->GetViewModelHandle());
	if (!pViewmodel)
		return false;

	CBaseHandle pWeaponHandle = pViewmodel->GetWeaponHandle();
	if (!pWeaponHandle)
		return false;

	CBaseCombatWeapon* pViewmodelWeapon = (CBaseCombatWeapon*)(I::ClientEntityList->GetClientEntityFromHandle(pWeaponHandle));
	if (pViewmodelWeapon != pWeapon)
		return false;

	pViewmodel->GetModelIndex() = I::ModelInfo->GetModelIndex(szModel);

	return true;
}

bool CSkinchanger::ApplyKnifeSkin(CBaseCombatWeapon* pWeapon, const char* szModel, int iItemDefIndex, int iPaintKit, int iEntityQuality, float flFallbackWear)
{
	*pWeapon->GetItemDefinitionIndex() = iItemDefIndex;
	pWeapon->GetEntityQuality() = iEntityQuality;
	pWeapon->GetModelIndex() = I::ModelInfo->GetModelIndex(szModel);

	CBaseHandle pWorldModelHandle = pWeapon->GetWorldModelHandle();
	if (!pWorldModelHandle)
		return false;

	CBaseCombatWeapon* pWorldModel = (CBaseCombatWeapon*)(I::ClientEntityList->GetClientEntityFromHandle(pWorldModelHandle));
	if (!pWorldModel)
		return false;

	pWorldModel->GetModelIndex() = I::ModelInfo->GetModelIndex(szModel) + 1;
	
	return true;
}