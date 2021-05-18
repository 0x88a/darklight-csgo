#include "../gui.h"

const char* szNumbers[254] = { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, ("0"), ("1"), ("2"), ("3"), ("4"), ("5"), ("6"), ("7"), ("8"), ("9"), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, ("0"), ("1"), ("2"), ("3"), ("4"), ("5"), ("6"),
("7"), ("8"), ("9"), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };

void GUI::CONTROLS::NumberField(const std::string& szName, std::string* pValue)
{
	if (!m_bInitialized)
		return;

	static bool bTakingText = false;
	static float flNextBlink = 0.0f;
	static std::string szCurrentItem;

	auto bInBound = UTILS::MouseInRegion(m_vOffset.x + 21, m_vOffset.y + 15, 146, 20);

	D::String(m_vOffset.x + 21, m_vOffset.y, D::uMenuFont[G::iDPIScale], szName, false, Color(210, 210, 210, CONTROLS::m_flMenuAlpha));

	D::RectFade(m_vOffset.x + 21, m_vOffset.y + 15, 146, 20, Color(30, 30, 30, CONTROLS::m_flMenuAlpha), (bInBound && !uInfo.m_bOpen) || uInfo.m_bOpen && uInfo.m_szName == szName ? Color(55, 55, 55, CONTROLS::m_flMenuAlpha) : Color(37, 37, 37, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + 21, m_vOffset.y + 15, 146, 20, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + 22, m_vOffset.y + 16, 144, 18, Color(50, 50, 50, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + 23, m_vOffset.y + 17, 142, 16, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));

	static auto bBuffer = false, bBuffer2 = false;

	if (!m_bDisableBound) {
		bool bSkip = false;
		if (UTILS::KeyPressed(VK_LBUTTON) && bInBound)
		{
			bBuffer ? (bTakingText = !bTakingText, szCurrentItem = szName, bBuffer = false) : NULL;
			bSkip = true;
		}
		else if (bInBound)
		{
			bBuffer = true;
		}

		if (bTakingText && szCurrentItem == szName)
		{
			if (UTILS::KeyPressed(VK_LBUTTON) && !bInBound)
				bTakingText = false;

			std::string szString = *pValue;
			for (int i = 0; i < 255; i++)
			{
				if (UTILS::KeyPressed(i))
				{
					if (i == VK_ESCAPE || i == VK_RETURN || i == VK_INSERT || i == VK_DELETE)
					{
						bTakingText = false;
						continue;
					}

					if (strlen(szString.c_str()) != 0)
					{
						if (GetAsyncKeyState(VK_BACK))
							*pValue = szString.substr(0, strlen(szString.c_str()) - 1);
					}

					if (strlen(szString.c_str()) < 30 && i != NULL &&
						szNumbers[i] != nullptr)
					{
						*pValue = szString + szNumbers[i];
						continue;
					}
				}
			}
		}
	}

	std::string szToRender = *pValue;
	if (GetTickCount64() >= flNextBlink)
		flNextBlink = GetTickCount64() + 800;
	if (bTakingText && szCurrentItem == szName && GetTickCount64() > (flNextBlink - 400) && (szToRender.length() <= 21))
		szToRender += ("_");

	if (szToRender.length() > 21)
	{
		szToRender.resize(24);
		szToRender += "...";
	}

	G::bTakingInput = bTakingText;

	D::String(m_vOffset.x + 31, m_vOffset.y + 18, D::uMenuFont[G::iDPIScale], szToRender, false, bTakingText && szCurrentItem == szName ? Color(210, 210, 210, CONTROLS::m_flMenuAlpha) : Color(165, 165, 165, CONTROLS::m_flMenuAlpha));

	m_iLastControl = NUMBERFIELD;
	m_vOffset.y += 38;
}