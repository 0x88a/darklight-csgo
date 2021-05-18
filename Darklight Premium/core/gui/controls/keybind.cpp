#include "../gui.h"

const char* szKeyStrings[254] = {
	("..."),("M1"),("M2"),("BRK"),("M3"),("M4"),("M5"),
	("..."),("BCK"),("TAB"),("..."),("..."),("..."),("ENT"),("..."),("..."),("SFT"),
	("CTL"),("ALT"),("PUS"),("CAP"),("..."),("..."),("..."),("..."),("..."),("..."),
	("ESC"),("..."),("..."),("..."),("..."),("SPC"),("PGU"),("PGD"),("END"),("HOM"),("LFT"),
	("UP"),("RGT"),("DWN"),("..."),("PRN"),("..."),("PRNS"),("INS"),("DEL"),("..."),("0"),("1"),
	("2"),("3"),("4"),("5"),("6"),("7"),("8"),("9"),("..."),("..."),("..."),("..."),("..."),("..."),
	("..."),("A"),("B"),("C"),("D"),("E"),("F"),("G"),("H"),("I"),("J"),("K"),("L"),("M"),("N"),("O"),("P"),("Q"),("R"),("S"),("T"),("U"),
	("V"),("W"),("X"),("Y"),("Z"),("WIN"),("WIN"),("..."),("..."),("..."),("NU0"),("NU1"),
	("NU2"),("NU3"),("NU4"),("NU5"),("NU6"),("NU7"),("NU8"),("NU9"),("*"),("+"),(""),("..."),("."),("/"),("F1"),("F2"),("F3"),
	("F4"),("F5"),("F6"),("F7"),("F8"),("F9"),("F10"),("F11"),("F12"),("F13"),("F14"),("F15"),("F16"),("F17"),("F18"),("F19"),("F20"),
	("F21"),("F22"),("F23"),("F24"),("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),
	("NLK"),("SCL"),("..."),("..."),("..."),("..."),("..."),("..."),("..."),
	("..."),("..."),("..."),("..."),("..."),("..."),("..."),("SFT"),("SFT"),("CTL"),
	("CTL"),("MEN"),("MEN"),("..."),("..."),("..."),("..."),("..."),("..."),("..."),
	("..."),("..."),("..."),("NRK"),("PRK"),("STP"),("PLY"),("..."),("..."),
	("..."),("..."),("..."),("..."),(";"),("+"),("),"),("..."),("."),("/?"),("~"),("..."),("..."),
	("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),
	("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),
	("..."),("..."),("..."),("..."),("..."),("..."),("{"),("\\|"),("}"),("'\""),("..."),
	("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),
	("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),
	("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),("..."),
	("..."),("...")
};

void GUI::CONTROLS::Keybind(const std::string& szName, int* pBind, int* pMethod, bool bAllowMethod)
{
	if (!m_bInitialized)
		return;

	static std::string szSelectedName;
	static auto bIsGettingKey = false;

	static auto flTimeClicked = 0.0f;
	const char* key_name = "...";
	static auto good_key_name = false;
	char name_buffer[128];

	if (bIsGettingKey && szSelectedName == szName) {
		key_name = "...";
		for (int i = 0; i < 255; i++) {
			if (UTILS::KeyPressed(i)) {
				*pBind = i == VK_ESCAPE ? -1 : i;
				bIsGettingKey = false;
				flTimeClicked = 0.0f;
			}
		}
	}
	else {
		if (*pBind >= 0) {
			key_name = szKeyStrings[*pBind];
			if (key_name) {
				good_key_name = true;
			}
			else {
				if (GetKeyNameText(*pBind << 16, name_buffer, 127)) {
					key_name = name_buffer;
					good_key_name = true;
				}
			}
		}

		if (!good_key_name) {
			key_name = "...";
		}
	}

	static std::vector<std::string> vItems = { ("Always on"), ("On hotkey"), ("Toggle"), ("Off hotkey") };

	const std::string szBuiltKeyName = key_name;

	const auto tSize = D::GetTextSize(D::uSmallFonts[G::iDPIScale], szBuiltKeyName.c_str());

	D::Rect(m_vOffset.x + D::ScaleDPI(166), m_vOffset.y, tSize.right + D::ScaleDPI(7), tSize.bottom + D::ScaleDPI(3), Color(30, 30, 30, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + D::ScaleDPI(167), m_vOffset.y + D::ScaleDPI(1), tSize.right + D::ScaleDPI(5), tSize.bottom + D::ScaleDPI(1), Color(50, 50, 50, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + D::ScaleDPI(166), m_vOffset.y, tSize.right + D::ScaleDPI(7), tSize.bottom + D::ScaleDPI(3), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
	D::String(m_vOffset.x + D::ScaleDPI(169), m_vOffset.y + D::ScaleDPI(2), D::uSmallFonts[G::iDPIScale], szBuiltKeyName, false, bIsGettingKey && szSelectedName == szName ? Color(175, 0, 0, CONTROLS::m_flMenuAlpha) : Color(150, 150, 150, CONTROLS::m_flMenuAlpha));

	const bool bMouseInBound = UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(166), m_vOffset.y, tSize.right + D::ScaleDPI(7), tSize.bottom + D::ScaleDPI(3));
	if (UTILS::KeyPressed(VK_LBUTTON) && bMouseInBound && !bIsGettingKey)
	{
		bIsGettingKey = true;
		szSelectedName = szName;
		flTimeClicked = I::Globals->flFrameTime;
	}

	if (bAllowMethod)
	{

		bool bSkip = false;

		if (UTILS::KeyPressed(VK_RBUTTON) && bMouseInBound && !bIsGettingKey)
		{
			uInfo.m_bOpen = !uInfo.m_bOpen, uInfo.m_szName = szName, uInfo.m_flAlpha = 0.0f;
			bSkip = true;
		}

		if (uInfo.m_bOpen && uInfo.m_szName == szName)
		{
			const bool bMouseInBound = UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(65), m_vOffset.y, D::ScaleDPI(95), (vItems.size() * D::ScaleDPI(20)) + D::ScaleDPI(1));

			for (int i = 0; i < vItems.size(); i++)
			{
				bool bMouseInComBound = UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(65), m_vOffset.y + (i * D::ScaleDPI(20)), D::ScaleDPI(95), D::ScaleDPI(20));

				if (UTILS::KeyDown(VK_LBUTTON) && bMouseInComBound)
					*pMethod = i;
			}

			if ((UTILS::KeyPressed(VK_LBUTTON) && !bSkip && !bMouseInBound) || m_bCloseBoxes)
				uInfo.m_bOpen = false;
		}

		if ((bMouseInBound || uInfo.m_bOpen) && uInfo.m_szName == szName)
		{
			uInfo.m_iPrevControl = KEYBIND;
			uInfo.m_iItem = *pMethod;
			uInfo.m_vItems.assign(vItems.begin(), vItems.end());
			uInfo.m_vItems = vItems;
			uInfo.m_vOffset = { m_vOffset.x + D::ScaleDPI(65), m_vOffset.y };
			uInfo.m_bCopyPaste = false;

			m_bDisableBound = true;
		}
	}

	m_iLastControl = KEYBIND;
}

void GUI::CONTROLS::KeybindFocus()
{
	if (uInfo.m_iPrevControl == KEYBIND)
	{
		if (uInfo.m_bOpen)
		{
			if (m_bCloseBoxes)
				uInfo.m_bOpen = false;

			D::Rect(uInfo.m_vOffset.x, uInfo.m_vOffset.y, D::ScaleDPI(95), (uInfo.m_vItems.size() * D::ScaleDPI(20)) + D::ScaleDPI(1), Color(35, 35, 35, CONTROLS::m_flMenuAlpha));

			for (int i = 0; i < uInfo.m_vItems.size(); i++)
			{
				const bool bHovered = UTILS::MouseInRegion(uInfo.m_vOffset.x, uInfo.m_vOffset.y + (i * D::ScaleDPI(20)), D::ScaleDPI(95), D::ScaleDPI(20));

				if (bHovered)
					D::Rect(uInfo.m_vOffset.x, uInfo.m_vOffset.y + (i * D::ScaleDPI(20)), D::ScaleDPI(95), D::ScaleDPI(20), Color(25, 25, 25, CONTROLS::m_flMenuAlpha));

				D::String(
					uInfo.m_vOffset.x + D::ScaleDPI(10),
					uInfo.m_vOffset.y + (i * D::ScaleDPI(20)) + D::ScaleDPI(3),
					bHovered ? D::uMenuFontBold[G::iDPIScale] : D::uMenuFont[G::iDPIScale],
					uInfo.m_vItems.at(i),
					false,
					uInfo.m_iItem == i ? Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha) : bHovered ? Color(210, 210, 210, CONTROLS::m_flMenuAlpha) : Color(165, 165, 165, CONTROLS::m_flMenuAlpha));
			}


			D::OutlinedRect(uInfo.m_vOffset.x + D::ScaleDPI(1), uInfo.m_vOffset.y + D::ScaleDPI(1), D::ScaleDPI(93), (uInfo.m_vItems.size() * D::ScaleDPI(20)) - D::ScaleDPI(1), Color(50, 50, 50, CONTROLS::m_flMenuAlpha));
			D::OutlinedRect(uInfo.m_vOffset.x, uInfo.m_vOffset.y, D::ScaleDPI(95), (uInfo.m_vItems.size() * D::ScaleDPI(20)) + D::ScaleDPI(1), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
		}
	}
}