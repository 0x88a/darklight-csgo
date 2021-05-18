#pragma once

#include <functional>
#include <deque>

#include "../../global.h"
#include "../../core/variables.h"
#include "../../core/config.h"
#include "../../utilities/draw.h"
#include "../../core/interfaces.h"
#include "../../features/visuals.h"
#include "../../utilities.h"
#include "../../common.h"
#include "../../sdk/datatypes/color.h"
#include "../../sdk/datatypes/vector.h"

#include "../../lodepng.h"
#include "../../resource.h"

class CTextureHolder
{
public:
	CTextureHolder()
		: m_pSurface(I::Surface), m_iH(0), m_iW(0), m_bValid(false)
	{ };

	CTextureHolder(const unsigned char* pRawRGBAData, int W, int H)
		: m_pSurface(I::Surface), m_iH(H), m_iW(W), m_bValid(false)
	{
		m_iTexture = m_pSurface->CreateNewTextureID(true);
		if (!m_iTexture)
			return;
		m_pSurface->DrawSetTextureRGBA(m_iTexture, pRawRGBAData, W, H);
		m_bValid = true;
	};

	bool IsValid() const
	{
		return m_bValid;
	};

	int GetTextureId() const
	{
		return m_iTexture;
	};

	bool Draw(int x, int y, Color col, float scale = 1.0)
	{
		if (!m_pSurface->IsTexturedIdValid(m_iTexture))
			return false;

		m_pSurface->DrawSetColor(col);
		m_pSurface->DrawSetTexture(m_iTexture);
		m_pSurface->DrawSetTexturedRect(x, y, x + m_iW * scale, y + m_iH * scale);
		return true;
	};

	static std::uint8_t* DecodeResourceImage(unsigned short uID, unsigned int iWidth, unsigned int iHeight)
	{
		const HRSRC pResource = FindResource(G::hDll, MAKEINTRESOURCE(uID), _("PNG"));
		const HGLOBAL hLoadedResource = LoadResource(G::hDll, pResource);
		const LPVOID pResourcePtr = LockResource(hLoadedResource);
		const DWORD dwResourceSize = SizeofResource(G::hDll, pResource);

		std::vector< std::uint8_t > vecImage;

		if (const auto error = lodepng::decode(vecImage, iWidth, iHeight, (unsigned char*)pResourcePtr, dwResourceSize))
			throw std::runtime_error(_("Failed to decode image!"));

		const auto pData = new std::uint8_t[vecImage.size()];

		std::copy(vecImage.begin(), vecImage.end(), pData);

		return pData;
	}

protected:
	int m_iTexture;
	int m_iW, m_iH;
	bool m_bValid;
	ISurface* m_pSurface;
};

namespace GUI
{
	void Run();

	inline bool m_bOpened = false;

	inline bool m_bGrabbingCheatGUI = false;

	namespace CONTROLS
	{
		enum EControls : int {
			NONE,
			CHECKBOX,
			COMBOBOX,
			MULTIBOX,
			SLIDER,
			COLORPICKER,
			KEYBIND,
			BUTTON,
			LISTBOX,
			TEXTFIELD,
			NUMBERFIELD,
			TEXT,
		};

		struct Info_t {
			int m_iPrevControl;
			bool m_bOpen;
			std::string m_szName;
			int m_iItem;
			std::deque<bool>* m_bItems;
			std::vector<std::string> m_vItems;
			int* m_iKeybindMethod;
			int m_iMax = 0;
			Vector2D m_vOffset;
			Color* m_pColor;
			uint8_t* m_iAlpha;
			int m_iColumn = 0;
			bool m_bAlphaSlider = false;
			int m_iColorPickerID = 0;
			float m_flAlpha = 0.0f;
			bool m_bCopyPaste = false;
			float* m_flSaturation;
			bool m_bBlackWhite = false;
			bool m_bAllowHold = false;
		};

		inline Info_t uInfo;

		void BeginWindow(const Vector2D vecPos, const Vector2D vSize);
		void EndWindow();

		void BeginGroupbox(const std::string& szName, const int iHeight, const int iColumn = 0);
		void EndGroupbox();

		void Checkbox(const std::string& szName, bool* pValue, Color textCol = Color(210, 210, 210));

		void Slider(const std::string& szName, int* pValue, int iMin, int iMax, const char* szPrefix = "%", bool bHealthPlus = false);
		void Slider(const std::string& szName, float* pValue, float flMin, float flMax, const char* szPrefix = "%", bool bHealthPlus = false);

		void Combobox(const std::string& szName, const std::vector<std::string> vecItems, int* pItem, bool bAllowHold = false);
		void ComboboxFocus();

		void Multibox(const std::string& szName, const std::vector<std::string> vecItems, std::deque<bool>* pItems);
		void MultiboxFocus();

		void Keybind(const std::string& szName, int* pBind, int* pMethod, bool = true);
		void KeybindFocus();

		void TextField(const std::string& szName, std::string* pValue);
		void NumberField(const std::string& szName, std::string* pValue);

		void Colorpicker(const std::string& szName, Color* pColor, uint8_t* pAlpha, const bool bAlpha = false, const bool bBlackWhite = false, const int iColumn = 0);
		void ColorpickerFocus();

		void Text(const std::string& szName, const bool bUseCustomCol = false);

		void Button(const std::string& szName, const std::function<void()>& func);

		void ResetVars();
		void PopGroupboxY();
		void PushFocus();

		inline CTextureHolder darklightLogo;
		inline CTextureHolder backgroundTexture;
		inline CTextureHolder colorPicker;
		inline CTextureHolder transparentBackground;
		inline CTextureHolder transparentBackgroundTwo;
		inline CTextureHolder catgirlGif[8];
		inline CTextureHolder groupboxTexture;

		inline Vector2D m_vSize, m_vPos;
		inline Vector2D m_vOldGroupboxPos;
		inline int m_iOldGroupboxHeight;
		inline bool m_bInitialized;
		inline std::vector<std::string> m_vTabs;
		inline bool m_bDisableBound = false;
		inline int m_iColumn = 0;
		inline int m_iOldGroupboxY = 0;
		inline EControls m_iLastControl = NONE;
		inline bool m_bCloseBoxes = false;
		inline Vector2D m_vOffset;

		inline Vector2D m_vGroupboxPos;
		inline std::string m_szGroupboxName;

		inline uint32_t m_uBlocking;

		inline Color m_cDefaultMenuCol = Color(200, 80, 145);
		inline Color m_cDefaultMenuColBackup = Color(200, 80, 145);
		inline Color m_cMenuColor = Color(200, 80, 145);

		inline int m_iSelectedCopy = false;
		inline Color m_cCopiedColor = Color(255, 255, 255);

		inline int m_iSelectedTab = 0;

		inline std::vector<int> m_vecColorPickers;
		inline float m_flMenuAlpha = 0.0f;
		inline bool m_bHoldingSlider = false;
		inline int m_iCurrentFrame = 0;
	}

	namespace UTILS
	{
		void InitializeInput(const std::string szWindowName);

		bool KeybindMethod(const int iKey, const int iMethod, bool* pToggled);
		bool KeyPressed(const int iKey);
		bool KeyDown(const int iKey);
		bool KeyReleased(const int iKey);

		bool MouseInRegion(const int iX, const int iY, const int iW, const int iH);

		std::vector<std::string> SplitStr(const char* szName, char szSeperator);
		uint32_t Hash(const char* szName, uint32_t uHash = 0x811c9dc5);

		inline bool m_bKeyState[256];
		inline bool m_bPrevKeyState[256];
		inline bool m_bInputLoopStarted = false;

		inline Vector2D m_vPrevMousePos, m_vMousePos;
	}
}