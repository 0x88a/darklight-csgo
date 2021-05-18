#include "../gui.h"

void GUI::CONTROLS::Multibox(const std::string& szName, const std::vector<std::string> vecItems, std::deque<bool>* pValue)
{
	if (!m_bInitialized)
		return;

	std::deque<bool> vecValue = *pValue;

	auto bInBound = UTILS::MouseInRegion(m_vOffset.x + 21, m_vOffset.y + 15, 146, 20);

	D::String(m_vOffset.x + 21, m_vOffset.y, D::uMenuFont[G::iDPIScale], szName, false, Color(210, 210, 210, CONTROLS::m_flMenuAlpha));

	D::RectFade(m_vOffset.x + 21, m_vOffset.y + 15, 146, 20, Color(30, 30, 30, CONTROLS::m_flMenuAlpha), (bInBound && !uInfo.m_bOpen) || uInfo.m_bOpen && uInfo.m_szName == szName ? Color(55, 55, 55, CONTROLS::m_flMenuAlpha) : Color(37, 37, 37, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + 21, m_vOffset.y + 15, 146, 20, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + 22, m_vOffset.y + 16, 144, 18, Color(50, 50, 50, CONTROLS::m_flMenuAlpha));

	static auto bBuffer = false, bBuffer2 = false;

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
			const bool bMouseInBound = UTILS::MouseInRegion(m_vOffset.x + 21, m_vOffset.y + 35, 146, (vecItems.size() * 20) + 1);

			for (int i = 0; i < vecItems.size(); i++)
			{
				const bool bMouseInComBound = UTILS::MouseInRegion(m_vOffset.x + 21, m_vOffset.y + 35 + (i * 20), 155, 20);

				if (UTILS::KeyDown(VK_LBUTTON) && bMouseInComBound)
					bBuffer2 ? (vecValue[i] = !vecValue[i], bBuffer2 = false) : NULL;
				else if (bMouseInComBound)
					bBuffer2 = true;
			}

			*pValue = vecValue;

			if ((UTILS::KeyPressed(VK_LBUTTON) && !bSkip && !bMouseInBound) || m_bCloseBoxes)
				uInfo.m_bOpen = false;
		}

		if ((bInBound || uInfo.m_bOpen) && uInfo.m_szName == szName)
		{
			uInfo.m_iPrevControl = MULTIBOX;
			uInfo.m_bItems = pValue;
			uInfo.m_vItems.assign(vecItems.begin(), vecItems.end());
			uInfo.m_vItems = vecItems;
			uInfo.m_vOffset = { m_vOffset.x + 21, m_vOffset.y + 37 };
			uInfo.m_bCopyPaste = false;

			m_bDisableBound = true;
		}
	}

	for (auto i = 5; i >= 2; --i) {
		auto iOffset = 5 - i;

		auto bIsOpen = uInfo.m_bOpen && uInfo.m_szName == szName;
		RECT rDraw = {
			m_vOffset.x + 156 + iOffset,
			bIsOpen ? m_vOffset.y + 23 - iOffset : m_vOffset.y + 23 + iOffset,
			m_vOffset.x + 156 + iOffset + std::clamp(i - iOffset, 0, 5),
			bIsOpen ? m_vOffset.y + 23 - iOffset : m_vOffset.y + 23 + iOffset,
		};

		D::Line(rDraw.left, rDraw.top, rDraw.right, rDraw.bottom, Color(175, 175, 175, CONTROLS::m_flMenuAlpha));
	}

	std::string ss;
	for (auto n = 0; n < vecItems.size(); n++) {
		if (vecValue[n]) {
			if (ss.length() > 0)
				ss += (", ");

			ss += vecItems[n];
			if (ss.length() > 17)
			{
				ss.resize(20);
				ss += "...";
			}
		}
	}

	if (!ss.length())
		ss += "-";

	D::String(m_vOffset.x + 31, m_vOffset.y + 18, D::uMenuFont[G::iDPIScale], ss, false, Color(165, 165, 165, CONTROLS::m_flMenuAlpha));

	m_iLastControl = MULTIBOX;
	m_vOffset.y += 38;
}

void GUI::CONTROLS::MultiboxFocus()
{
	if (uInfo.m_iPrevControl == MULTIBOX)
	{
		if (uInfo.m_vItems.size() > 0)
		{
			if (uInfo.m_bOpen)
			{
				if (m_bCloseBoxes)
					uInfo.m_bOpen = false;

				D::Rect(uInfo.m_vOffset.x, uInfo.m_vOffset.y, 146, (uInfo.m_vItems.size() * 20) + 1, Color(35, 35, 35, CONTROLS::m_flMenuAlpha));

				for (int i = 0; i < uInfo.m_vItems.size(); i++)
				{
					const std::deque<bool> vecValue = *uInfo.m_bItems;
					const bool bHovered = UTILS::MouseInRegion(uInfo.m_vOffset.x, uInfo.m_vOffset.y + (i * 20), 146, 20);

					if (bHovered)
						D::Rect(uInfo.m_vOffset.x, uInfo.m_vOffset.y + (i * 20), 146, 20, Color(25, 25, 25, CONTROLS::m_flMenuAlpha));

					D::String(
						uInfo.m_vOffset.x + 10,
						uInfo.m_vOffset.y + (i * 20) + 3,
						bHovered ? D::uMenuFontBold[G::iDPIScale] : D::uMenuFont[G::iDPIScale],
						uInfo.m_vItems.at(i),
						false,
						vecValue[i] ? Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha) : bHovered ? Color(210, 210, 210, CONTROLS::m_flMenuAlpha) : Color(165, 165, 165, CONTROLS::m_flMenuAlpha));
				}

				D::OutlinedRect(uInfo.m_vOffset.x + 1, uInfo.m_vOffset.y + 1, 144, (uInfo.m_vItems.size() * 20) - 1, Color(50, 50, 50, CONTROLS::m_flMenuAlpha));
				D::OutlinedRect(uInfo.m_vOffset.x, uInfo.m_vOffset.y, 146, (uInfo.m_vItems.size() * 20) + 1, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
			}
		}
	}
}