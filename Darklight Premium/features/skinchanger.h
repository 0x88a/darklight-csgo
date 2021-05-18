#pragma once

#include "../common.h"

#include "../sdk/datatypes/usercmd.h"
#include "../sdk/interfaces/iprediction.h"
#include "../sdk/entity.h"
#include "../sdk/interfaces/igameeventmanager.h"

struct weapon_list {
	weapon_list(int _id, std::string _name) {
		id = _id;
		name = _name;
	}

	int id;
	std::string name;
};

struct Item_t {
	Item_t(int _id, const char* _model) {
		id = _id;
		model = _model;
	}

	int id;
	const char* model;
};

class CSkinchanger
{
public:
	void Run();
	//void Event(IGameEvent* pEvent, const FNV1A_t uNameHash);

private:
	bool ApplyKnifeModel(CBaseCombatWeapon* pWeapon, const char* szModel);
	bool ApplyKnifeSkin(CBaseCombatWeapon* pWeapon, const char* szModel, int iItemDefIndex, int iPaintKit, int iEntityQuality, float flFallbackWear);
};

extern CSkinchanger g_Skinchanger;