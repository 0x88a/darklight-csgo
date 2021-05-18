#include "../gui.h"

void GUI::CONTROLS::Checkbox(const std::string& szName, bool* pValue, Color textCol)
{
	if (!m_bInitialized)
		return;

	const std::vector<std::string> vSplit = UTILS::SplitStr(szName.c_str(), '#');

	const auto bInBound = UTILS::MouseInRegion(m_vOffset.x, m_vOffset.y + (1), D::ScaleDPI(20) + D::GetTextSize(D::uMenuFont[G::iDPIScale], vSplit[0].c_str()).right, 10);
	const auto bActive = m_uBlocking == UTILS::Hash(szName.data());

	if (!m_bDisableBound) {
		if (!bActive && bInBound && UTILS::KeyPressed(VK_LBUTTON))
			m_uBlocking = UTILS::Hash(szName.data());
		else if (bActive && !UTILS::KeyDown(VK_LBUTTON)) {
			m_uBlocking = 0;
			*pValue = !*pValue;
		}
	}

	D::RectFade(m_vOffset.x + (1), m_vOffset.y + (3), D::ScaleDPI(6), D::ScaleDPI(6), *pValue ? Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha) : Color(65, 65, 65, CONTROLS::m_flMenuAlpha), *pValue ? Color(0, 0, 0, CONTROLS::m_flMenuAlpha) : Color(65, 65, 65, CONTROLS::m_flMenuAlpha));
	if (bInBound)
		D::Rect(m_vOffset.x + (1), m_vOffset.y + (3), D::ScaleDPI(6), D::ScaleDPI(6), Color(85, 85, 85, 125));
	
	D::OutlinedRect(m_vOffset.x, m_vOffset.y + (2), D::ScaleDPI(8), D::ScaleDPI(8), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
	D::String(m_vOffset.x + (21), m_vOffset.y - (1), D::uMenuFont[G::iDPIScale], vSplit[0], false, Color(textCol, CONTROLS::m_flMenuAlpha));

	m_vOffset.y += D::ScaleDPI(15);

	m_iLastControl = CHECKBOX;
}