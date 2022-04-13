#pragma once

#include "../common.h"
#include "../sdk/datatypes/usercmd.h"
#include "../sdk/interfaces/igameeventmanager.h"
#include "../sdk/entity.h"
#include "../global.h"
#include "../utilities/math.h"

struct Frame_t {
	float viewangles[2];
	float forwardmove;
	float sidemove;
	float upmove;
	int buttons;
	unsigned char impulse;
	short mousedx;
	short mousedy;

	Frame_t(CUserCmd* cmd) {
		this->viewangles[0] = cmd->angViewPoint.x;
		this->viewangles[1] = cmd->angViewPoint.y;
		this->forwardmove = cmd->flForwardMove;
		this->sidemove = cmd->flSideMove;
		this->upmove = cmd->flUpMove;
		this->buttons = cmd->iButtons;
		this->impulse = cmd->uImpulse;
		this->mousedx = cmd->sMouseDeltaX;
		this->mousedy = cmd->sMouseDeltaY;
	}

	void Replay(CUserCmd* cmd) {
		cmd->angViewPoint.x = this->viewangles[0];
		cmd->angViewPoint.y = this->viewangles[1];
		G::cmd.flForwardMove = this->forwardmove;
		G::cmd.flSideMove = this->sidemove;
		G::cmd.flUpMove = this->upmove;
		cmd->iButtons = this->buttons;
		cmd->uImpulse = this->impulse;
		cmd->sMouseDeltaX = this->mousedx;
		cmd->sMouseDeltaY = this->mousedy;
	}
};

typedef std::vector<Frame_t> FrameContainer;

class CRecorder {
private:
	bool bIsRecordingActive = false;
	bool bIsReRecordingActive = false;

	size_t uReRecordingStartFrame;

	FrameContainer vecRecordingFrames;
	FrameContainer vecReRecordingFrames;
public:
	Vector vecStartingPosition;
	QAngle angStartingAngle;

	void StartRecording() {
		this->bIsRecordingActive = true;

		if (G::pLocal && G::pCmd)
		{
			vecStartingPosition = G::pLocal->GetOrigin();
			angStartingAngle = G::pCmd->angViewPoint;
		}
	}

	void StopRecording() {
		this->bIsRecordingActive = false;
	}

	bool IsRecordingActive() const {
		return this->bIsRecordingActive;
	}

	FrameContainer& GetActiveRecording() {
		return this->vecRecordingFrames;
	}

	void StartRerecording(size_t uStartFrame) {
		this->bIsReRecordingActive = true;
		this->uReRecordingStartFrame = uStartFrame;
	}

	void StopRerecording(bool merge = false) {
		if (merge) {
			this->vecRecordingFrames.erase(this->vecRecordingFrames.begin() + (this->uReRecordingStartFrame + 1), this->vecRecordingFrames.end());
			this->vecRecordingFrames.reserve(this->vecRecordingFrames.size() + this->vecReRecordingFrames.size());
			this->vecRecordingFrames.insert(this->vecRecordingFrames.end(), this->vecReRecordingFrames.begin(), this->vecReRecordingFrames.end());
		}

		this->bIsReRecordingActive = false;
		this->uReRecordingStartFrame = 0;
		this->vecReRecordingFrames.clear();
	}

	bool IsRerecordingActive() const {
		return this->bIsReRecordingActive;
	}

	FrameContainer& GetActiveRerecording() {
		return this->vecReRecordingFrames;
	}
};

inline CRecorder recorder;

class CPlayback {
private:
	bool bIsPlaybackActive = false;
	size_t uCurrentFrame = 0;
	FrameContainer& vecActiveDemo = FrameContainer();


public:
	void StartPlayback(FrameContainer& frames) {
		this->bIsPlaybackActive = true;
		this->vecActiveDemo = frames;
	};

	void StopPlayback() {
		this->bIsPlaybackActive = false;
		this->uCurrentFrame = 0;
	};

	bool IsPlaybackActive() const {
		return this->bIsPlaybackActive;
	}

	size_t GetCurrentFrame() const {
		return this->uCurrentFrame;
	};

	void SetCurrentFrame(size_t frame) {
		this->uCurrentFrame = frame;
	};

	FrameContainer& GetActiveDemo() const {
		return this->vecActiveDemo;
	}
};

inline CPlayback playback;

class CMiscellaneous
{
public:
	void Run(CUserCmd* pCmd, CBaseEntity* pLocal, bool& bSendPacket);

	void CorrectMovement(CBaseEntity* pLocal, CUserCmd* pCmd, QAngle& angOldViewPoint);

	void JumpBug(CUserCmd* pCmd, CBaseEntity* pLocal, int iFlags);
	void EdgeBug(CUserCmd* pCmd, CBaseEntity* pLocal, int iFlags);
	void EdgeJump(CUserCmd* pCmd, CBaseEntity* pLocal, int iFlags);
	void StrafeOptimizer(CUserCmd* pCmd, CBaseEntity* pLocal);
	void NullStrafe(CUserCmd* pCmd, CBaseEntity* pLocal);
	void MiniJump(CUserCmd* pCmd, CBaseEntity* pLocal);

	void Blockbot(CUserCmd* pCmd, CBaseEntity* pLocal);
	void MovementRecorder(CUserCmd* pCmd, CBaseEntity* pLocal);
	bool m_bPreparedOrigin;
	bool m_bPreparedViewAngs;
	bool m_bMoveViewAngs;
private:
	void Bunnyhop(CUserCmd* pCmd, CBaseEntity* pLocal);
	void ClantagChanger(CUserCmd* pCmd, CBaseEntity* pLocal);
	void MouseDelta(CUserCmd* pCmd, CBaseEntity* pLocal);

	void InfiniteDuck(CUserCmd* pCmd, CBaseEntity* pLocal);
	void AutoPistol(CUserCmd* pCmd, CBaseEntity* pLocal);
	void RankReveal(CUserCmd* pCmd, CBaseEntity* pLocal);

	bool m_bJumpbugging;
};

extern CMiscellaneous g_Misc;