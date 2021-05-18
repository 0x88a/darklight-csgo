#include "../gui.h"

void GUI::CONTROLS::Colorpicker(const std::string& szName, Color* pColor, uint8_t* pAlpha, const bool bAlpha, const bool bBlackWhite, const int iColumn)
{
	if (!m_bInitialized)
		return;

	bool bMouseInBound = UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(165), m_vOffset.y, D::ScaleDPI(25), D::ScaleDPI(9));
	static auto bBuffer = false;
	bool bSkip = false;

	if (UTILS::KeyDown(VK_CONTROL) && UTILS::KeyDown(0x43) && bMouseInBound)
		m_cCopiedColor = *pColor;

	if (UTILS::KeyDown(VK_CONTROL) && UTILS::KeyDown(0x56) && bMouseInBound)
		*pColor = m_cCopiedColor;

	if (UTILS::KeyPressed(VK_LBUTTON) && bMouseInBound)
	{
		bBuffer ? (uInfo.m_bOpen = !uInfo.m_bOpen, uInfo.m_szName = szName, uInfo.m_flAlpha = 0.0f, uInfo.m_bCopyPaste = false, bBuffer = false) : NULL;
		bSkip = true;
	}
	else if (bMouseInBound)
	{
		bBuffer = true;
	}

	auto bInColorBox = UTILS::MouseInRegion(uInfo.m_vOffset.x, uInfo.m_vOffset.y, uInfo.m_bAlphaSlider && uInfo.m_bBlackWhite ? D::ScaleDPI(176) : uInfo.m_bAlphaSlider || uInfo.m_bBlackWhite ? D::ScaleDPI(164) : D::ScaleDPI(150), D::ScaleDPI(150));
	if (uInfo.m_bOpen && uInfo.m_szName == szName && !uInfo.m_bCopyPaste)
	{
		if ((UTILS::KeyPressed(VK_LBUTTON) && !(bMouseInBound || bInColorBox)) && !bSkip || m_bCloseBoxes)
			uInfo.m_bOpen = false;
	}

	if (uInfo.m_bOpen && uInfo.m_szName == szName && !uInfo.m_bCopyPaste)
	{
		if (m_bCloseBoxes)
			uInfo.m_bOpen = false;

		uInfo.m_iPrevControl = COLORPICKER;
		uInfo.m_pColor = pColor;
		uInfo.m_iAlpha = pAlpha;
		uInfo.m_iColumn = iColumn;
		uInfo.m_vOffset.x = m_vOffset.x + D::ScaleDPI(165);
		uInfo.m_vOffset.y = m_vOffset.y + D::ScaleDPI(20);
		uInfo.m_bAlphaSlider = bAlpha;
		uInfo.m_bBlackWhite = bBlackWhite;
		uInfo.m_bCopyPaste = false;

		m_bDisableBound = true;
	}

	static std::vector<std::string> vItems = { "Copy", "Paste" };

	static int iPlaceHolder = -1;

	if (UTILS::KeyPressed(VK_RBUTTON) && bMouseInBound)
	{
		uInfo.m_bOpen = !uInfo.m_bOpen, uInfo.m_szName = szName, uInfo.m_flAlpha = 0.0f, uInfo.m_bCopyPaste = true;
		bSkip = true;
	}

	if (uInfo.m_bOpen && uInfo.m_szName == szName && uInfo.m_bCopyPaste)
	{
		const bool bMouseInBound = UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(65), m_vOffset.y, D::ScaleDPI(95), (vItems.size() * D::ScaleDPI(20)) + D::ScaleDPI(1));

		for (int i = 0; i < vItems.size(); i++)
		{
			bool bMouseInComBound = UTILS::MouseInRegion(m_vOffset.x + D::ScaleDPI(65), m_vOffset.y + (i * D::ScaleDPI(20)), D::ScaleDPI(95), D::ScaleDPI(20));

			if (UTILS::KeyDown(VK_LBUTTON) && bMouseInComBound)
				iPlaceHolder = i;
		}

		if ((UTILS::KeyPressed(VK_LBUTTON) && !bSkip && !bMouseInBound) || m_bCloseBoxes)
			uInfo.m_bOpen = false;
	}

	if (uInfo.m_bOpen && uInfo.m_szName == szName && uInfo.m_bCopyPaste)
	{
		uInfo.m_iPrevControl = COLORPICKER;
		uInfo.m_iItem = iPlaceHolder;
		uInfo.m_vItems.assign(vItems.begin(), vItems.end());
		uInfo.m_vItems = vItems;
		uInfo.m_vOffset = { m_vOffset.x + D::ScaleDPI(65), m_vOffset.y };
		uInfo.m_bCopyPaste = true;

		m_bDisableBound = true;
	}

	if (iPlaceHolder == 0)
	{
		m_cCopiedColor = *pColor;
		iPlaceHolder = -1;
	}

	if (iPlaceHolder == 1)
	{
		*pColor = m_cCopiedColor;
		iPlaceHolder = -1;
	}

	transparentBackgroundTwo.Draw(m_vOffset.x + D::ScaleDPI(166), m_vOffset.y + D::ScaleDPI(1), Color(255, 255, 255, CONTROLS::m_flMenuAlpha), 1.0f + (0.25f * G::iDPIScale));
	D::RectFade(m_vOffset.x + D::ScaleDPI(167), m_vOffset.y + D::ScaleDPI(2), D::ScaleDPI(14), D::ScaleDPI(8), *pColor, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
	D::OutlinedRect(m_vOffset.x + D::ScaleDPI(166), m_vOffset.y + D::ScaleDPI(1), D::ScaleDPI(16), D::ScaleDPI(10), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));

	m_iLastControl = COLORPICKER;
}

std::unique_ptr<Color[]> pGradient[5] = { nullptr, nullptr, nullptr, nullptr, nullptr };

void ColorSpectrum(int x, int y)
{
	for (auto f = 0; f < 5; f++)
	{
		if (pGradient[f])
			continue;

		int w = D::ScaleDPI(150, f), h = D::ScaleDPI(150, f);

		pGradient[f] = std::make_unique<Color[]>(w * h);

		float hue = 0.0f, sat = 0.99f, lum = 1.0f;
		for (int i = 0; i < w; i++)
		{
			for (int j = 0; j < h; j++)
			{
				*(Color*)(pGradient[f].get() + j + i * h) = Color::HSLToRGB(hue, sat, lum);

				hue += (1.f / w);
			}

			lum -= (1.f / h);
			hue = 0.f;
		}
	}
}

Color GetOfficialColor(int x, int y)
{
	return *(Color*)(pGradient[G::iDPIScale].get() + x + y * D::ScaleDPI(150));
}

void GUI::CONTROLS::ColorpickerFocus()
{
	if (uInfo.m_iPrevControl == COLORPICKER)
	{
		if (uInfo.m_bOpen && !uInfo.m_bCopyPaste)
		{
			if (m_bCloseBoxes)
				uInfo.m_bOpen = false;

			const Vector2D vecPosition = uInfo.m_vOffset;
			const Vector2D vecRelative = { UTILS::m_vMousePos.x - vecPosition.x, UTILS::m_vMousePos.y - vecPosition.y };
			Vector2D vecSize = { (float)D::ScaleDPI(150),  (float)D::ScaleDPI(150) };

			D::Rect(vecPosition.x - D::ScaleDPI(4), vecPosition.y - D::ScaleDPI(4), uInfo.m_bAlphaSlider && uInfo.m_bBlackWhite ? D::ScaleDPI(188) : uInfo.m_bAlphaSlider || uInfo.m_bBlackWhite ? D::ScaleDPI(173) : D::ScaleDPI(158), D::ScaleDPI(158), Color(40, 40, 40, CONTROLS::m_flMenuAlpha));
			D::OutlinedRect(vecPosition.x - D::ScaleDPI(4), vecPosition.y - D::ScaleDPI(4), uInfo.m_bAlphaSlider && uInfo.m_bBlackWhite ? D::ScaleDPI(188) : uInfo.m_bAlphaSlider || uInfo.m_bBlackWhite ? D::ScaleDPI(173) : D::ScaleDPI(158), D::ScaleDPI(158), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
			D::OutlinedRect(vecPosition.x - D::ScaleDPI(3), vecPosition.y - D::ScaleDPI(3), uInfo.m_bAlphaSlider && uInfo.m_bBlackWhite ? D::ScaleDPI(186) : uInfo.m_bAlphaSlider || uInfo.m_bBlackWhite ? D::ScaleDPI(171) : D::ScaleDPI(156), D::ScaleDPI(156), Color(60, 60, 60, CONTROLS::m_flMenuAlpha));

			ColorSpectrum(vecPosition.x, vecPosition.y);

			colorPicker.Draw(vecPosition.x, vecPosition.y, Color(255, 255, 255, CONTROLS::m_flMenuAlpha), (1 + (0.25 * G::iDPIScale)));

			static Vector2D vecMousPos;

			if (UTILS::KeyDown(VK_LBUTTON) &&
				UTILS::MouseInRegion(vecPosition.x, vecPosition.y, vecSize.x, vecSize.y))
			{
				*uInfo.m_pColor =
					Color(
						GetOfficialColor(vecRelative.x, vecRelative.y).r(),
						GetOfficialColor(vecRelative.x, vecRelative.y).g(),
						GetOfficialColor(vecRelative.x, vecRelative.y).b(),
						*uInfo.m_iAlpha
					);

				vecMousPos = UTILS::m_vMousePos;
			}

			if (vecMousPos.x < vecPosition.x)
				vecMousPos.x = vecPosition.x;
			if (vecMousPos.y < vecPosition.y)
				vecMousPos.y = vecPosition.y;
			if (vecMousPos.x + D::ScaleDPI(4) > vecPosition.x + vecSize.x)
				vecMousPos.x = vecPosition.x + vecSize.x - D::ScaleDPI(4);
			if (vecMousPos.y + D::ScaleDPI(4) > vecPosition.y + vecSize.y)
				vecMousPos.y = vecPosition.y + vecSize.y - D::ScaleDPI(4);

			D::Rect(vecMousPos.x + D::ScaleDPI(1), vecMousPos.y + D::ScaleDPI(1), D::ScaleDPI(2), D::ScaleDPI(2), Color(124, 159, 222, CONTROLS::m_flMenuAlpha));
			D::OutlinedRect(vecMousPos.x, vecMousPos.y, D::ScaleDPI(4), D::ScaleDPI(4), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));

			if (uInfo.m_bBlackWhite)
			{
				const Vector2D vecAlphaPos = { vecPosition.x + vecSize.x + 3, vecPosition.y };
				const Vector2D vecAlphaSize = { (float)D::ScaleDPI(12), vecSize.y };

				if (UTILS::KeyDown(VK_LBUTTON) && UTILS::MouseInRegion(vecAlphaPos.x, vecAlphaPos.y, vecAlphaSize.x, vecAlphaSize.y))
				{
					uInfo.m_pColor->flSaturation = 255 * (UTILS::m_vMousePos.y - vecAlphaPos.y) / vecAlphaSize.y;

					if (uInfo.m_pColor->flSaturation < 5)
						uInfo.m_pColor->flSaturation = 0;

					if (uInfo.m_pColor->flSaturation > 245)
						uInfo.m_pColor->flSaturation = 255;

					*uInfo.m_pColor = Color(255 - uInfo.m_pColor->flSaturation, 255 - uInfo.m_pColor->flSaturation, 255 - uInfo.m_pColor->flSaturation, *uInfo.m_iAlpha);
				}

				const float flValueMod = (uInfo.m_pColor->flSaturation / 255.0f) * vecAlphaSize.y;
				D::RectFade(vecAlphaPos.x, vecAlphaPos.y, vecAlphaSize.x, vecAlphaSize.y, Color(255, 255, 255, CONTROLS::m_flMenuAlpha), Color(0, 0, 0, CONTROLS::m_flMenuAlpha), false, true);

				float flYPos = flValueMod;
				if (flValueMod >= vecAlphaSize.y - D::ScaleDPI(3))
					flYPos = vecAlphaSize.y - D::ScaleDPI(3);

				D::Rect(vecAlphaPos.x + D::ScaleDPI(1), vecAlphaPos.y + flYPos + D::ScaleDPI(1), vecAlphaSize.x - D::ScaleDPI(2), 1, Color(124, 159, 222, CONTROLS::m_flMenuAlpha));
				D::OutlinedRect(vecAlphaPos.x, vecAlphaPos.y + flYPos, vecAlphaSize.x, D::ScaleDPI(3), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
				D::OutlinedRect(vecAlphaPos.x, vecAlphaPos.y, vecAlphaSize.x, vecAlphaSize.y, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
			}

			if (uInfo.m_bAlphaSlider)
			{
				const Vector2D vecAlphaPos = { (float)(vecPosition.x + vecSize.x + 3 + (uInfo.m_bBlackWhite ? 15 : 0)), vecPosition.y };
				const Vector2D vecAlphaSize = { (float)D::ScaleDPI(12), vecSize.y };

				if (UTILS::KeyDown(VK_LBUTTON) && UTILS::MouseInRegion(vecAlphaPos.x, vecAlphaPos.y, vecAlphaSize.x, vecAlphaSize.y))
				{
					uInfo.m_pColor->flAlpha = 255 * (UTILS::m_vMousePos.y - vecAlphaPos.y) / vecAlphaSize.y;

					if (uInfo.m_pColor->flAlpha < 5)
						uInfo.m_pColor->flAlpha = 0;

					if (uInfo.m_pColor->flAlpha > 245)
						uInfo.m_pColor->flAlpha = 255;

					*uInfo.m_iAlpha = 255 - uInfo.m_pColor->flAlpha;
				}

				const float flValueMod = (uInfo.m_pColor->flAlpha / 255.0f) * vecAlphaSize.y;
				transparentBackground.Draw(vecAlphaPos.x, vecAlphaPos.y, Color(255, 255, 255, CONTROLS::m_flMenuAlpha), (1 + (0.25 * G::iDPIScale)));
				D::RectFade(vecAlphaPos.x, vecAlphaPos.y, vecAlphaSize.x, vecAlphaSize.y, Color(*uInfo.m_pColor, CONTROLS::m_flMenuAlpha), Color(*uInfo.m_pColor, 0), false, true);

				float flYPos = flValueMod;
				if (flValueMod >= vecAlphaSize.y - D::ScaleDPI(3))
					flYPos = vecAlphaSize.y - D::ScaleDPI(3);

				D::Rect(vecAlphaPos.x + D::ScaleDPI(1), vecAlphaPos.y + flYPos + D::ScaleDPI(1), vecAlphaSize.x - D::ScaleDPI(2), 1, Color(124, 159, 222, CONTROLS::m_flMenuAlpha));
				D::OutlinedRect(vecAlphaPos.x, vecAlphaPos.y + flYPos, vecAlphaSize.x, D::ScaleDPI(3), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
				D::OutlinedRect(vecAlphaPos.x, vecAlphaPos.y, vecAlphaSize.x, vecAlphaSize.y, Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
			}
		}
		else if (uInfo.m_bOpen && uInfo.m_bCopyPaste)
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
					UTILS::KeyDown(VK_LBUTTON) && bHovered ? Color(CONTROLS::m_cDefaultMenuCol, CONTROLS::m_flMenuAlpha) : bHovered ? Color(210, 210, 210, CONTROLS::m_flMenuAlpha) : Color(165, 165, 165, CONTROLS::m_flMenuAlpha));
			}


			D::OutlinedRect(uInfo.m_vOffset.x + D::ScaleDPI(1), uInfo.m_vOffset.y + D::ScaleDPI(1), D::ScaleDPI(93), (uInfo.m_vItems.size() * D::ScaleDPI(20)) - D::ScaleDPI(1), Color(50, 50, 50, CONTROLS::m_flMenuAlpha));
			D::OutlinedRect(uInfo.m_vOffset.x, uInfo.m_vOffset.y, D::ScaleDPI(95), (uInfo.m_vItems.size() * D::ScaleDPI(20)) + D::ScaleDPI(1), Color(0, 0, 0, CONTROLS::m_flMenuAlpha));
		}
	}
}