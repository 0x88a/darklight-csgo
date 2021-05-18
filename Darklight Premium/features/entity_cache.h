#pragma once

#include "../common.h"
#include "../utilities.h"
#include <map>

enum struct GroupType_t
{
	PLAYERS_ALL,
	PLAYERS_ENEMIES,
	PLAYERS_TEAMMATES,

	WORLD_WEAPONS,
	WORLD_GRENADES,
	WORLD_GRENADES_THROWN,
	WORLD_BOMB
};

enum EHashedNames : int
{
	AK47 = 1500694985,
	P2000 = 2007268246,
	DUALIES = 1651687556,
	P250 = -587003976,
	CZ75 = -2034417223,
	REVOLVER = 704157158,
	NOVA = 1286831179,
	XM1014 = -721210086,
	MAG7 = -734304101,
	M249 = -113882922,
	NEGEV = -813127169,
	MP9 = -197000882,
	MP5SD = -1722441343,
	UMP45 = -2051367405,
	P90 = 1492423537,
	PPBIZON = 595259354, 
	FAMAS = -546528134,
	M4A4 = 1705501733,
	SCOUT = -120411296,
	AUG = -1137647009,
	AWP = -648282765,
	SCAR = 1800820534,
	SG553 = -848505812,
	DEAGLE = 973511507,
	TEC9 = 83111206,
	MP7 = 1434709580,
	G3SG1 = 1071570736,
	GALIL = -1137204882,
	FIVESEVEN = -583098884,
	HEGRENADE = 2066476733,
	MOLOTOV = -1280773481,
	SMOKE = -1295636852,
	SMOKE_THROWN = -709713360,
	DECOY = -542470981,
	INCENDIARY = -579069181,
	C4 = 924579812,
};

class CEntityCache
{
private:
	std::map<GroupType_t, std::vector<CBaseEntity*>> m_mapGroups;

public:
	void Fill();
	void Clear();

	bool IsWeapon(int iHash);
	bool IsGrenade(int iHash);
	bool IsBomb(int iHash);

	inline int HashedScreen(const char* szOrg) {
		int iHash = 5381;

		while (int iStr = *szOrg++) iHash = iHash * 33 + iStr;

		return iHash;
	}

	const std::vector<CBaseEntity*>& GetEntityGroup(const GroupType_t& group);
};

extern CEntityCache g_EntityCache;