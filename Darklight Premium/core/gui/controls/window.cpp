#include "../gui.h"
#include <algorithm>

#include "../../../resource.h"

void GUI::CONTROLS::BeginWindow(const Vector2D vPos, const Vector2D vSize)
{
	/*static auto iDPIScaling = 0;
	if (iDPIScaling != G::iDPIScale)
	{
		iDPIScaling = G::iDPIScale;
		m_bInitialized = !m_bInitialized;
	}*/

	if (!m_bInitialized)
	{
		m_vSize = vSize;
		m_vPos = vPos;
		m_vTabs = { "legitbot", "ragebot", "players", "visuals", "misc", "skins"};

		backgroundTexture = CTextureHolder(CTextureHolder::DecodeResourceImage(IDB_PNG1, 428, 487), 428, 487);
		colorPicker = CTextureHolder(CTextureHolder::DecodeResourceImage(IDB_PNG2, 150, 150), 150, 150);
		transparentBackground = CTextureHolder(CTextureHolder::DecodeResourceImage(IDB_PNG3, 12, 150), 12, 150);
		transparentBackgroundTwo = CTextureHolder(CTextureHolder::DecodeResourceImage(IDB_PNG4, 16, 10), 16, 10);

		//for (int i = 0; i < 8; i++)
		//	catgirlGif[i] = CTextureHolder(CTextureHolder::DecodeResourceImage(202 + i, 500, 500), 500, 500);

		groupboxTexture = CTextureHolder(CTextureHolder::DecodeResourceImage(IDB_PNG13, 123, 7), 123, 7);

		//darklightLogo = CTextureHolder(CTextureHolder::DecodeResourceImage(211, 350, 300), 350, 300);

		m_bInitialized = !m_bInitialized;
	}

	auto vecPos = m_vPos = Vector2D((float)C::Get<int>(Vars.iMenuX), (float)C::Get<int>(Vars.iMenuY));

	CONTROLS::m_cDefaultMenuCol = C::Get<bool>(Vars.bCustomMenuCol) ? CONTROLS::m_cMenuColor : CONTROLS::m_cDefaultMenuColBackup;

	static bool bDrag = false;
	static Vector2D vecLastMousePos;
	static Vector2D vecLastMenuPos;

	if (UTILS::KeyDown(VK_LBUTTON))
	{
		if (!bDrag && UTILS::MouseInRegion(m_vPos.x, m_vPos.y, m_vSize.x, m_vSize.y) &&
			!UTILS::MouseInRegion(m_vPos.x, m_vPos.y + D::ScaleDPI(25), m_vSize.x, m_vSize.y - D::ScaleDPI(25)))
		{
			bDrag = true;
			vecLastMousePos = UTILS::m_vMousePos;
			vecLastMenuPos = m_vPos;
		}

		if (bDrag)
		{
			m_bDisableBound = true;
			m_bCloseBoxes = true;

			C::Get<int>(Vars.iMenuX) = vecLastMenuPos.x + (UTILS::m_vMousePos.x - vecLastMousePos.x);
			C::Get<int>(Vars.iMenuY) = vecLastMenuPos.y + (UTILS::m_vMousePos.y - vecLastMousePos.y);
		}
	}
	else
		bDrag = false;

	m_bGrabbingCheatGUI = bDrag;

	if (C::Get<int>(Vars.iMenuX) < 0)
		C::Get<int>(Vars.iMenuX) = 0;

	if (C::Get<int>(Vars.iMenuY) < 0)
		C::Get<int>(Vars.iMenuY) = 0;

	if ((C::Get<int>(Vars.iMenuX) + m_vSize.x) > G::vecDisplaySize.x)
		C::Get<int>(Vars.iMenuX) = G::vecDisplaySize.x - m_vSize.x;

	if ((C::Get<int>(Vars.iMenuY) + m_vSize.y) > G::vecDisplaySize.y)
		C::Get<int>(Vars.iMenuY) = G::vecDisplaySize.y - m_vSize.y;

	D::Rect(m_vPos.x + (2), m_vPos.y + (2), m_vSize.x - (4), m_vSize.y - (4), Color(40, 40, 40, CONTROLS::m_flMenuAlpha));
	backgroundTexture.Draw(m_vPos.x + 6, m_vPos.y + D::ScaleDPI(27), Color(255, 255, 255, CONTROLS::m_flMenuAlpha), (1.0f + (0.25 * G::iDPIScale)));
	D::OutlinedRect(m_vPos.x, m_vPos.y, m_vSize.x, m_vSize.y, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vPos.x + (1), m_vPos.y + (1), m_vSize.x - (2), m_vSize.y - (2), Color(60, 60, 60, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vPos.x + (5), m_vPos.y + D::ScaleDPI(25), m_vSize.x - (10), m_vSize.y - (30), Color(60, 60, 60, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vPos.x + (6), m_vPos.y + D::ScaleDPI(26), m_vSize.x - (12), m_vSize.y - (32), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));

	D::String(m_vPos.x + (6), m_vPos.y + D::ScaleDPI(12), D::uMenuFont[G::iDPIScale], "Dark", 3, Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha));
	D::String(m_vPos.x + (6) + D::GetTextSize(D::uMenuFont[G::iDPIScale], "Dark").right, m_vPos.y + D::ScaleDPI(12), D::uMenuFont[G::iDPIScale], "light", 3, Color(208, 208, 208, CONTROLS::m_flMenuAlpha));

	/*if (C::Get<bool>(Vars.bReplaceLogo))
	{
		if (catgirlGif[CONTROLS::m_iCurrentFrame].IsValid())
			catgirlGif[CONTROLS::m_iCurrentFrame].Draw(m_vPos.x + m_vSize.x - 500 * 0.5f, m_vPos.y + m_vSize.x - 180, Color(255, 255, 255, CONTROLS::m_flMenuAlpha), .5f);
	}
	else*/

	//if (catgirlGif[CONTROLS::m_iCurrentFrame].IsValid())
	//	catgirlGif[CONTROLS::m_iCurrentFrame].Draw(m_vPos.x + m_vSize.x - 500 * 0.5f, m_vPos.y + m_vSize.x - 180, Color(255, 255, 255, CONTROLS::m_flMenuAlpha), .5f);

	//darklightLogo.Draw(m_vPos.x + (m_vSize.x / 2) - 175, m_vPos.y + m_vSize.y - 300, Color(255, 255, 255, CONTROLS::m_flMenuAlpha));

	if (!m_vTabs.empty())
	{
		static int iCurrentTab = m_iSelectedTab;
		if (m_iSelectedTab != iCurrentTab)
		{
			m_bCloseBoxes = true;
			iCurrentTab = m_iSelectedTab;
		}

		static auto iTabSize = (int)(m_vSize.x - 14) / m_vTabs.size();
		for (int i = 0; i < m_vTabs.size(); i++)
		{
			const RECT tabArea = { m_vPos.x + 7 + ( i * iTabSize), m_vPos.y + 26, iTabSize, 20 };
			if (UTILS::MouseInRegion(tabArea.left, tabArea.top, tabArea.right, tabArea.bottom) &&
				UTILS::KeyPressed(VK_LBUTTON))
				m_iSelectedTab = i;

			D::Rect(tabArea.left, tabArea.top, tabArea.right, tabArea.bottom, Color(25, 25, 25, CONTROLS::m_flMenuAlpha));
			D::OutlinedRect(tabArea.left + 1, tabArea.top + 1, tabArea.right - 2, tabArea.bottom - 2, Color(50, 50, 50, CONTROLS::m_flMenuAlpha));
			if (m_iSelectedTab == i)
				D::Rect(tabArea.left + 1, tabArea.top + tabArea.bottom - 2, tabArea.right - 2, 1, Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha));
			D::OutlinedRect(tabArea.left, tabArea.top, tabArea.right, tabArea.bottom, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
			D::String(tabArea.left + (iTabSize / 2), tabArea.top + 3, D::uMenuFont[G::iDPIScale], m_vTabs[i], 4, m_iSelectedTab == i ? Color(150, 150, 150, CONTROLS::m_flMenuAlpha) : Color(85, 85, 85, CONTROLS::m_flMenuAlpha));
		}
	}
}
void GUI::CONTROLS::EndWindow()
{
	PushFocus();
	ResetVars();
}

void GUI::CONTROLS::ResetVars()
{
	m_iColumn = 0;

	m_iLastControl = NONE;
	m_bCloseBoxes = false;
	m_bDisableBound = false;
	m_vOffset = Vector2D();
	m_vGroupboxPos = Vector2D();
	m_vOldGroupboxPos = { (float)D::ScaleDPI(19), (float)D::ScaleDPI(54) };
	m_iOldGroupboxHeight = 0;
	m_szGroupboxName = ("");

	if (!m_vecColorPickers.empty())
		m_vecColorPickers.clear();
}

void GUI::CONTROLS::PopGroupboxY()
{
	if (!m_bInitialized)
		return;

	m_vOldGroupboxPos.y = D::ScaleDPI(54);
}

void GUI::CONTROLS::PushFocus()
{
	ComboboxFocus();
	MultiboxFocus();
	KeybindFocus();
	ColorpickerFocus();
}