#pragma once
//
//#include "../common.h"
//
//#include "../sdk/datatypes/usercmd.h"
//#include "../sdk/interfaces/igameeventmanager.h"
//#include "../sdk/entity.h"
//#include "prediction.h"
//
//#define M_TICK_INTERVAL				( I::Globals->flIntervalPerTick )
//#define M_TIME_TO_TICKS( dt )		( (int)( 0.5f + (float)(dt) / M_TICK_INTERVAL ) )
//#define M_TICKS_TO_TIME( t )		( M_TICK_INTERVAL *( t ) )
//#define M_ROUND_TO_TICKS( t )		( M_TICK_INTERVAL * M_TIME_TO_TICKS( t ) )
//
//#define M_MAX(a,b)					(((a) > (b)) ? (a) : (b))
//
//struct StoredRecords_t {
//	Vector vHead;
//	Vector vBody;
//	float flSimTime;
//	bool bIsValid;
//	matrix3x4_t matrix[128];
//
//	StoredRecords_t(Vector h, Vector b, float s) {
//		vHead = h;
//		vBody = b;
//		flSimTime = s;
//	}
//};
//
//class CBacktrack
//{
//public:
//	void Run(CUserCmd* pCmd, CBaseEntity* pLocal, bool& bSendPacket);
//	bool ValidTick(float flTime);
//	float LerpTime();
//	std::vector<StoredRecords_t> vRecords[65];
//};
//
//extern CBacktrack g_Backtrack;