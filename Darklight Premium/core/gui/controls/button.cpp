#include "../gui.h"

void GUI::CONTROLS::Button(const std::string& szName, const std::function<void()>& func)
{
	const std::vector<std::string> vSplit = UTILS::SplitStr(szName.c_str(), '#');
	const auto bInBound = UTILS::MouseInRegion(m_vOffset.x + 21, m_vOffset.y, 146, 15);
	const auto bActive = m_uBlocking == UTILS::Hash(szName.data());

	if (!m_bDisableBound) {
		if (!bActive && bInBound && UTILS::KeyPressed(VK_LBUTTON))
			m_uBlocking = UTILS::Hash(szName.data());
		else if (bActive && !UTILS::KeyDown(VK_LBUTTON)) {
			m_uBlocking = 0;
			func();
		}
	}

	D::RectFade(m_vOffset.x + (21), m_vOffset.y, D::ScaleDPI(146), D::ScaleDPI(20), Color(30, 30, 30, CONTROLS::m_flMenuAlpha), (bInBound && !uInfo.m_bOpen) ? UTILS::KeyDown(VK_LBUTTON) ? Color(25, 25, 25, CONTROLS::m_flMenuAlpha) : Color(55, 55, 55, CONTROLS::m_flMenuAlpha) : Color(37, 37, 37, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + (21), m_vOffset.y, D::ScaleDPI(146), D::ScaleDPI(20), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + (22), m_vOffset.y + 1, D::ScaleDPI(144), D::ScaleDPI(18), Color(50, 50, 50, CONTROLS::m_flMenuAlpha));
	D::String(m_vOffset.x + (21) + (D::ScaleDPI(155) / 2), m_vOffset.y + D::ScaleDPI(3), D::uMenuFont[G::iDPIScale], szName, 4, Color(165, 165, 165, CONTROLS::m_flMenuAlpha));

	m_vOffset.y += D::ScaleDPI(24);

	m_iLastControl = BUTTON;
}