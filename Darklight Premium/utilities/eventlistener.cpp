#include "eventlistener.h"

#include "../core/interfaces.h"
#include "../features/visuals.h"
#include "../features/misc.h"
#include "../features/skinchanger.h"

void CEventListener::Setup(std::deque<const char*> arrEvents)
{
	if (arrEvents.empty())
		return;

	for (auto szEvent : arrEvents)
	{
		I::GameEvent->AddListener(this, szEvent, false);

		if (!I::GameEvent->FindListener(this, szEvent))
			throw std::runtime_error(_("Failed add listener"));
	}
}

void CEventListener::Destroy()
{
	I::GameEvent->RemoveListener(this);
}

void CEventListener::FireGameEvent(IGameEvent* pEvent)
{
	const FNV1A_t uNameHash = FNV1A::Hash(pEvent->GetName());
	g_Visuals.Event(pEvent, uNameHash);
}
