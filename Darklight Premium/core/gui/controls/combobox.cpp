#include "../gui.h"

void GUI::CONTROLS::Combobox(const std::string& szName, const std::vector<std::string> vecItems, int* pValue, bool bAllowHold)
{
	if (!m_bInitialized)
		return;

	auto bInBound = UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(21), m_vOffset.y + D::ScaleDPI(15), D::ScaleDPI(146), D::ScaleDPI(20));

	D::String(m_vOffset.x + D::ScaleDPI(21), m_vOffset.y, D::uMenuFont[G::iDPIScale], szName, false, Color(210, 210, 210, CONTROLS::m_flMenuAlpha));

	D::RectFade(m_vOffset.x + D::ScaleDPI(21), m_vOffset.y + D::ScaleDPI(15), D::ScaleDPI(146), D::ScaleDPI(20), Color(30, 30, 30, CONTROLS::m_flMenuAlpha), (bInBound && !uInfo.m_bOpen) || uInfo.m_bOpen && uInfo.m_szName == szName ? Color(55, 55, 55, CONTROLS::m_flMenuAlpha) : Color(37, 37, 37, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + D::ScaleDPI(21), m_vOffset.y + D::ScaleDPI(15), D::ScaleDPI(146), D::ScaleDPI(20), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + D::ScaleDPI(22), m_vOffset.y + D::ScaleDPI(16), D::ScaleDPI(144), D::ScaleDPI(18), Color(50, 50, 50, CONTROLS::m_flMenuAlpha));

	static auto bBuffer = false;

	if (!m_bDisableBound && !m_bHoldingSlider) {
		bool bSkip = false;
		if (UTILS::KeyPressed(VK_LBUTTON) && bInBound)
		{
			bBuffer ? (uInfo.m_bOpen = !uInfo.m_bOpen, uInfo.m_szName = szName, uInfo.m_flAlpha = 0.0f, bBuffer = false) : NULL;
			bSkip = true;
		}
		else if (bInBound)
		{
			bBuffer = true;
		}

		if (uInfo.m_bOpen && uInfo.m_szName == szName)
		{
			const bool bMouseInBound = UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(21), m_vOffset.y + D::ScaleDPI(35), D::ScaleDPI(146), (vecItems.size() * D::ScaleDPI(20)) + D::ScaleDPI(1));

			for (int i = 0; i < vecItems.size(); i++)
			{
				if ((bAllowHold ? UTILS::KeyPressed(VK_LBUTTON) : UTILS::KeyDown(VK_LBUTTON)) &&
					UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(21), m_vOffset.y + D::ScaleDPI(35) + (i * D::ScaleDPI(20)), D::ScaleDPI(146), D::ScaleDPI(20)))
					*pValue = i;
			}

			if ((UTILS::KeyPressed(VK_LBUTTON) && !bSkip && !bMouseInBound) || m_bCloseBoxes)
				uInfo.m_bOpen = false;
		}

		if ((bInBound || uInfo.m_bOpen) && uInfo.m_szName == szName) {
			uInfo.m_iPrevControl = COMBOBOX;
			uInfo.m_iItem = *pValue;
			uInfo.m_vItems.assign(vecItems.begin(), vecItems.end());
			uInfo.m_vItems = vecItems;
			uInfo.m_vOffset = { m_vOffset.x + D::ScaleDPI(21), m_vOffset.y + D::ScaleDPI(37) };
			uInfo.m_bCopyPaste = false;

			m_bDisableBound = true;
		}
	}

	for (auto i = 5; i >= 2; --i) {
		auto iOffset = 5 - i;

		auto bIsOpen = uInfo.m_bOpen && uInfo.m_szName == szName;
		RECT rDraw = {
			m_vOffset.x + D::ScaleDPI(156) + iOffset,
			bIsOpen ? m_vOffset.y + D::ScaleDPI(23) - iOffset : m_vOffset.y + D::ScaleDPI(23) + iOffset,
			m_vOffset.x + D::ScaleDPI(156) + iOffset + std::clamp(i - iOffset, 0, 5),
			bIsOpen ? m_vOffset.y + D::ScaleDPI(23) - iOffset : m_vOffset.y + D::ScaleDPI(23) + iOffset,
		};

		D::Line(rDraw.left, rDraw.top, rDraw.right, rDraw.bottom, Color(175, 175, 175, CONTROLS::m_flMenuAlpha));
	}

	D::String(m_vOffset.x + D::ScaleDPI(31), m_vOffset.y + D::ScaleDPI(18), D::uMenuFont[G::iDPIScale], (*pValue >= 0) ? vecItems.at(*pValue) : "...", false, Color(165, 165, 165, CONTROLS::m_flMenuAlpha));

	m_iLastControl = COMBOBOX;
	m_vOffset.y += D::ScaleDPI(38);
}

void GUI::CONTROLS::ComboboxFocus()
{
	if (uInfo.m_iPrevControl == COMBOBOX)
	{
		if (uInfo.m_vItems.size() > 0)
		{
			if (uInfo.m_bOpen)
			{
				if (m_bCloseBoxes)
					uInfo.m_bOpen = false;

				D::Rect(uInfo.m_vOffset.x, uInfo.m_vOffset.y, D::ScaleDPI(146), (uInfo.m_vItems.size() * D::ScaleDPI(20)) + D::ScaleDPI(1), Color(35, 35, 35, CONTROLS::m_flMenuAlpha));

				for (int i = 0; i < uInfo.m_vItems.size(); i++)
				{
					const bool bHovered = UTILS::MouseInRegion(uInfo.m_vOffset.x, uInfo.m_vOffset.y + (i * D::ScaleDPI(20)), D::ScaleDPI(146), D::ScaleDPI(20));

					if (bHovered)
						D::Rect(uInfo.m_vOffset.x, uInfo.m_vOffset.y + (i * D::ScaleDPI(20)), D::ScaleDPI(146), D::ScaleDPI(20), Color(25, 25, 25, CONTROLS::m_flMenuAlpha));

					D::String(
						uInfo.m_vOffset.x + D::ScaleDPI(10),
						uInfo.m_vOffset.y + (i * D::ScaleDPI(20)) + D::ScaleDPI(3),
						bHovered ? D::uMenuFontBold[G::iDPIScale] : D::uMenuFont[G::iDPIScale],
						uInfo.m_vItems.at(i),
						false,
						uInfo.m_iItem == i ? Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha) : bHovered ? Color(210, 210, 210, CONTROLS::m_flMenuAlpha) : Color(165, 165, 165, CONTROLS::m_flMenuAlpha));
				}

				D::OutlinedRect(uInfo.m_vOffset.x + D::ScaleDPI(1), uInfo.m_vOffset.y + D::ScaleDPI(1), D::ScaleDPI(144), (uInfo.m_vItems.size() * D::ScaleDPI(20)) - D::ScaleDPI(1), Color(50, 50, 50, CONTROLS::m_flMenuAlpha));
				D::OutlinedRect(uInfo.m_vOffset.x, uInfo.m_vOffset.y, D::ScaleDPI(146), (uInfo.m_vItems.size() * D::ScaleDPI(20)) + D::ScaleDPI(1), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
			}
		}
	}
}