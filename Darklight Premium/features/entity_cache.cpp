#include "entity_cache.h"
#include "../global.h"
#include "../core/interfaces.h"

bool CEntityCache::IsWeapon(int iHash)
{
	switch (iHash)
	{
	case AK47:
	case P2000:
	case DUALIES:
	case P250:
	case CZ75:
	case REVOLVER:
	case NOVA:
	case XM1014:
	case MAG7:
	case M249:
	case NEGEV:
	case MP9:
	case MP5SD:
	case UMP45:
	case P90:
	case PPBIZON:
	case FAMAS:
	case M4A4:
	case SCOUT:
	case AUG:
	case AWP:
	case SCAR:
	case SG553:
	case DEAGLE:
	case TEC9:
	case MP7:
	case G3SG1:
	case GALIL:
	case FIVESEVEN:
		return true;
	default:
		return false;
	}
}
bool CEntityCache::IsGrenade(int iHash)
{
	switch (iHash)
	{
	case HEGRENADE:
	case MOLOTOV:
	case SMOKE:
	case SMOKE_THROWN:
	case DECOY:
	case INCENDIARY:
		return true;
	default:
		return false;
	}
}
bool CEntityCache::IsBomb(int iHash)
{
	switch (iHash)
	{
	case C4:
		return true;
	default:
		return false;
	}
}

void CEntityCache::Fill()
{
	if (!G::pLocal)
		return;

	for (int n = 1; n < I::ClientEntityList->GetHighestEntityIndex(); n++)
	{
		CBaseEntity* pEntity = I::ClientEntityList->Get<CBaseEntity>(n);
		if (!pEntity)
			continue;

		const auto iIndex = pEntity->GetClientClass()->nClassID;

		if (iIndex == EClassIndex::CAK47 || iIndex == EClassIndex::CDEagle ||
			(iIndex >= EClassIndex::CWeaponAug && iIndex <= EClassIndex::CWeaponXM1014))
			m_mapGroups[GroupType_t::WORLD_WEAPONS].push_back(pEntity);

		if (pEntity->GetClientClass()->nClassID == EClassIndex::CCSPlayer)
		{
			m_mapGroups[GroupType_t::PLAYERS_ALL].push_back(pEntity);
			m_mapGroups[G::pLocal->IsEnemy(pEntity) ? GroupType_t::PLAYERS_ENEMIES : GroupType_t::PLAYERS_TEAMMATES].push_back(pEntity);
		}
	}
}

void CEntityCache::Clear()
{
	for (auto& group : m_mapGroups)
		group.second.clear();
}

const std::vector<CBaseEntity*>& CEntityCache::GetEntityGroup(const GroupType_t& group)
{
	return m_mapGroups[group];
}

CEntityCache g_EntityCache;