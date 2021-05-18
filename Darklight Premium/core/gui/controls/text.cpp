#include "../gui.h"

void GUI::CONTROLS::Text(const std::string& szName, const bool bUseCustomCol)
{
	if (!m_bInitialized)
		return;

	D::String(m_vOffset.x + 21, m_vOffset.y, D::uMenuFont[G::iDPIScale], szName, false, Color(210, 210, 210, CONTROLS::m_flMenuAlpha));

	m_vOffset.y += 14;

	m_iLastControl = TEXT;
}