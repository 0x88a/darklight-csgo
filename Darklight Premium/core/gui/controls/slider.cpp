#include "../gui.h"

static int iSliderSize = 146;

void GUI::CONTROLS::Slider(const std::string& szName, int* pValue, int iMin, int iMax, const char* szPrefix, bool bHealthPlus)
{
	if (!m_bInitialized)
		return;

	static bool bTakingInput = false, bBuffer = false;
	static std::string szCurrentName;

	D::String(m_vOffset.x + 21, m_vOffset.y, D::uMenuFont[G::iDPIScale], szName, false, Color(210, 210, 210, CONTROLS::m_flMenuAlpha));

	const auto bInBound = UTILS::MouseInRegion(m_vOffset.x + 21, m_vOffset.y + 15, iSliderSize, 7);

	const float flMinMaxDelta = iMax - iMin;

	if (!m_bDisableBound)
	{
		bool bSkip = false;
		if (UTILS::KeyPressed(VK_LBUTTON) && bInBound)
		{
			bBuffer ? (bTakingInput = !bTakingInput, szCurrentName = szName, bBuffer = false) : NULL;
			bSkip = true;
		}
		else if (bInBound)
		{
			bBuffer = true;
		}

		if (UTILS::KeyDown(VK_LBUTTON) && bTakingInput && szCurrentName == szName)
		{
			*pValue = iMin + flMinMaxDelta * (UTILS::m_vMousePos.x - (m_vOffset.x + 21)) / iSliderSize;
		}
		else if (!UTILS::KeyDown(VK_LBUTTON) && !bInBound && bTakingInput)
		{
			bTakingInput = false;
		}

		m_bHoldingSlider = bTakingInput;
	}

	if (*pValue < iMin)
		*pValue = iMin;
	if (*pValue > iMax)
		*pValue = iMax;

	const float flValueMinDelta = *pValue - iMin;
	const float flValueMod = (flValueMinDelta / flMinMaxDelta) * iSliderSize;

	D::Rect(m_vOffset.x + 21, m_vOffset.y + 15, iSliderSize, 7, Color(40, 40, 40, CONTROLS::m_flMenuAlpha));
	D::RectFade(m_vOffset.x + 22, m_vOffset.y + 16, flValueMod - 2, 5, Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha), Color(40, 40, 40, CONTROLS::m_flMenuAlpha));
	if (bInBound)
		D::Rect(m_vOffset.x + 21, m_vOffset.y + 15, iSliderSize, 7, Color(85, 85, 85, 125));

	D::OutlinedRect(m_vOffset.x + 21, m_vOffset.y + 15, iSliderSize, 7, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));

	std::string szValue = std::to_string(*pValue) + szPrefix;
	if (bHealthPlus && *pValue > 100)
		szValue = "HP+" + std::to_string(*pValue - 100);

	D::String(m_vOffset.x + 21 + flValueMod, m_vOffset.y + 16, D::uMenuSliderFont[G::iDPIScale], szValue, 4, Color(185, 185, 185, CONTROLS::m_flMenuAlpha));

	m_vOffset.y += 30;

	m_iLastControl = SLIDER;
}
void GUI::CONTROLS::Slider(const std::string& szName, float* pValue, float flMin, float flMax, const char* szPrefix, bool bHealthPlus)
{
	if (!m_bInitialized)
		return;

	static bool bTakingInput = false, bBuffer = false;
	static std::string szCurrentName;

	D::String(m_vOffset.x + 21, m_vOffset.y, D::uMenuFont[G::iDPIScale], szName, false, Color(210, 210, 210, CONTROLS::m_flMenuAlpha));

	const auto bInBound = UTILS::MouseInRegion(m_vOffset.x + 21, m_vOffset.y + 15, iSliderSize, 7);

	const float flMinMaxDelta = flMax - flMin;

	if (!m_bDisableBound)
	{
		bool bSkip = false;
		if (UTILS::KeyPressed(VK_LBUTTON) && bInBound)
		{
			bBuffer ? (bTakingInput = !bTakingInput, szCurrentName = szName, bBuffer = false) : NULL;
			bSkip = true;
		}
		else if (bInBound)
		{
			bBuffer = true;
		}

		if (UTILS::KeyDown(VK_LBUTTON) && bTakingInput && szCurrentName == szName)
		{
			*pValue = flMin + flMinMaxDelta * (UTILS::m_vMousePos.x - (m_vOffset.x + 21)) / iSliderSize;
		}
		else if (!UTILS::KeyDown(VK_LBUTTON) && !bInBound && bTakingInput)
		{
			bTakingInput = false;
		}

		m_bHoldingSlider = bTakingInput;
	}

	if (*pValue < flMin)
		*pValue = flMin;
	if (*pValue > flMax)
		*pValue = flMax;


	const float flValueMinDelta = *pValue - flMin;
	const float flValueMod = (flValueMinDelta / flMinMaxDelta) * iSliderSize;

	D::Rect(m_vOffset.x + 21, m_vOffset.y + 15, iSliderSize, 7, Color(40, 40, 40, CONTROLS::m_flMenuAlpha));
	D::RectFade(m_vOffset.x + 22, m_vOffset.y + 16, flValueMod - 2, 5, Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha), Color(40, 40, 40, CONTROLS::m_flMenuAlpha));
	if (bInBound)
		D::Rect(m_vOffset.x + 21, m_vOffset.y + 15, iSliderSize, 7, Color(85, 85, 85, 125));

	D::OutlinedRect(m_vOffset.x + 21, m_vOffset.y + 15, iSliderSize, 7, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));

	std::string szValue = std::to_string((int)*pValue) + szPrefix;
	if (bHealthPlus && *pValue > 100)
		szValue = "HP+" + std::to_string((int)*pValue - 100);

	D::String(m_vOffset.x + 21 + flValueMod, m_vOffset.y + 16, D::uMenuSliderFont[G::iDPIScale], szValue, 4, Color(185, 185, 185, CONTROLS::m_flMenuAlpha));

	m_vOffset.y += 30;

	m_iLastControl = SLIDER;
}