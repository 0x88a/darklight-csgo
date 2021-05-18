#include "draw.h"

// used: engine interface
#include "../core/interfaces.h"
// used: current window
#include "inputsystem.h"

#include "../utilities/logging.h"
#include "../global.h"

void D::Initialize()
{
	for (int i = 0; i < 5; i++)
	{
		uVerdana[i] = I::Surface->FontCreate();
		I::Surface->SetFontGlyphSet(uVerdana[i], "Verdana", ScaleDPI(12, i), 350, 0, 0, FONTFLAG_DROPSHADOW);

		uSmallFonts[i] = I::Surface->FontCreate();
		I::Surface->SetFontGlyphSet(uSmallFonts[i], "Small Fonts", ScaleDPI(9, i), 350, 0, 0, FONTFLAG_OUTLINE | FONTFLAG_ANTIALIAS);

		uVerdanaBig[i] = I::Surface->FontCreate();
		I::Surface->SetFontGlyphSet(uVerdanaBig[i], "Verdana Bold", ScaleDPI(25, i), 500, 0, 0, FONTFLAG_DROPSHADOW | FONTFLAG_ANTIALIAS);

		uMenuFont[i] = I::Surface->FontCreate();
		I::Surface->SetFontGlyphSet(uMenuFont[i], "Verdana", ScaleDPI(12, i), 500, 0, 0, FONTFLAG_DROPSHADOW | FONTFLAG_ANTIALIAS);

		uTrebuchetMS[i] = I::Surface->FontCreate();
		I::Surface->SetFontGlyphSet(uTrebuchetMS[i], "Trebuchet MS", ScaleDPI(30, i), 200, 0, 0, FONTFLAG_DROPSHADOW | FONTFLAG_ANTIALIAS);
	
		uMenuFontBold[i] = I::Surface->FontCreate();
		I::Surface->SetFontGlyphSet(uMenuFontBold[i], "Verdana Bold", ScaleDPI(12, i), 100, 0, 0, FONTFLAG_DROPSHADOW | FONTFLAG_ANTIALIAS);

		uMenuSliderFont[i] = I::Surface->FontCreate();
		I::Surface->SetFontGlyphSet(uMenuSliderFont[i], "Verdana", ScaleDPI(12, i), 500, 0, 0, FONTFLAG_DROPSHADOW | FONTFLAG_ANTIALIAS);
	}
}

void D::OutlinedRect(int x, int y, int w, int h, Color col) {
	I::Surface->DrawSetColor(col);
	I::Surface->DrawOutlinedRect(x, y, x + w, y + h);
}
void D::Line(int x, int y, int x1, int y1, Color col) {
	I::Surface->DrawSetColor(col);
	I::Surface->DrawLine(x, y, x1, y1);
}
void D::Rect(int x, int y, int w, int h, Color col) {
	I::Surface->DrawSetColor(col);
	I::Surface->DrawFilledRect(x, y, x + w, y + h);
}
void D::String(int x, int y, Color col, unsigned long font, const char* text, ...) {
	if (text == NULL) return;

	va_list			va_alist;
	char			buffer[1024];
	wchar_t			string[1024];

	va_start(va_alist, text);
	_vsnprintf(buffer, sizeof(buffer), text, va_alist);
	va_end(va_alist);

	MultiByteToWideChar(CP_UTF8, 0, buffer, 256, string, 256);

	I::Surface->DrawSetTextPos(x, y);
	I::Surface->DrawSetTextFont(font);
	I::Surface->DrawSetTextColor(col);
	I::Surface->DrawPrintText(string, wcslen(string));
}
void D::String(int x, int y, unsigned long font, std::string string, int mode, Color colour) {
	const auto converted_text = std::wstring(string.begin(), string.end());

	auto text_size = GetTextSize(font, string.c_str());
	Vector2D pos;

	switch (mode) {
	case 0: pos = Vector2D(x, y); break;
	case 1: pos = Vector2D(int(x - (int(.5 + (text_size.left / 2)))), int(y - (int(.5 + (text_size.bottom / 2))) + 1)); break;
	case 2: pos = Vector2D(int(x - text_size.left), int(y - (int(.5 + (text_size.bottom / 2))) + 1)); break;
	case 3: pos = Vector2D(x, int(y - (int(.5 + (text_size.bottom / 2))) + 1)); break;
	case 4: pos = Vector2D(int(x - (int(.5 + (text_size.left / 2)))), y); break;
	}

	I::Surface->DrawSetTextPos(pos.x, pos.y);
	I::Surface->DrawSetTextFont(font);
	I::Surface->DrawSetTextColor(colour);
	I::Surface->DrawPrintText(converted_text.c_str(), wcslen(converted_text.c_str()));
}
RECT D::GetTextSize(unsigned long font, std::string string) {
	/*size_t origsize = strlen(text) + 1;
	const size_t newsize = 100;
	size_t convertedChars = 0;
	wchar_t wcstring[newsize];
	mbstowcs_s(&convertedChars, wcstring, origsize, text, _TRUNCATE);*/

	std::wstring text = std::wstring(string.begin(), string.end());
	const wchar_t* wcstring = text.c_str();

	RECT rect; int x, y;
	I::Surface->GetTextSize(font, wcstring, x, y);
	rect.left = x; rect.bottom = y;
	rect.right = x;
	return rect;
}

void D::TexturedPolygon(int n, Vertex_t* vertice, Color col) 
{
	static int texture_id = I::Surface->CreateNewTextureID(true);
	static unsigned char buf[4] = { 255, 255, 255, 255 };
	I::Surface->DrawSetTextureRGBA(texture_id, buf, 1, 1);
	I::Surface->DrawSetColor(col);
	I::Surface->DrawSetTexture(texture_id);
	I::Surface->DrawTexturedPolygon(n, vertice);
}

void D::DrawFilledTriangle(std::array<Vector, 3> points, Color colour)
{
	std::array<Vertex_t, 3> vertices{ Vertex_t(points.at(0)), Vertex_t(points.at(1)), Vertex_t(points.at(2)) };
	TexturedPolygon(3, vertices.data(), colour);
}

void D::DrawFilledCircle(Vector center, Color color, float r, float points) 
{
	I::Surface->DrawSetColor(color);
	for (int i = 0; i < r; i++)
		I::Surface->DrawOutlinedCircle(center.x, center.y, i, points);
}

void D::RectFade(int x, int y, int x1, int y1, Color first, Color second, bool horizontal, bool secondary_vert)
{
	if (!horizontal && !secondary_vert)
	{
		I::Surface->DrawSetColor(first);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 255, 255, horizontal);

		I::Surface->DrawSetColor(second);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 0, 255, horizontal);
	}
	else if (horizontal)
	{
		I::Surface->DrawSetColor(first);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 255, 0, horizontal);

		I::Surface->DrawSetColor(first);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 128, 0, horizontal);

		I::Surface->DrawSetColor(second);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 0, 255, horizontal);

		I::Surface->DrawSetColor(second);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 0, 125, horizontal);
	}
	else if (secondary_vert)
	{
		I::Surface->DrawSetColor(first);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 255, 0, false);

		I::Surface->DrawSetColor(first);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 128, 0, false);

		I::Surface->DrawSetColor(second);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 0, 255, false);

		I::Surface->DrawSetColor(second);
		I::Surface->DrawFilledRectFade(x, y, x + x1, y + y1, 0, 125, false);
	}
}

//CDirectRender* g_pDrawList;
//
//void CDirectRender::SetRenderStates()
//{
//	pDevice->SetVertexShader(nullptr);
//	pDevice->SetPixelShader(nullptr);
//	pDevice->SetFVF(D3DFVF_XYZRHW | D3DFVF_DIFFUSE);
//	pDevice->SetRenderState(D3DRS_LIGHTING, false);
//	pDevice->SetRenderState(D3DRS_FOGENABLE, false);
//	pDevice->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
//	pDevice->SetRenderState(D3DRS_FILLMODE, D3DFILL_SOLID);
//
//	pDevice->SetRenderState(D3DRS_ZENABLE, D3DZB_FALSE);
//	pDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, true);
//	pDevice->SetRenderState(D3DRS_ZWRITEENABLE, false);
//	pDevice->SetRenderState(D3DRS_STENCILENABLE, false);
//
//	pDevice->SetRenderState(D3DRS_MULTISAMPLEANTIALIAS, true);
//	pDevice->SetRenderState(D3DRS_ANTIALIASEDLINEENABLE, true);
//
//	pDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, true);
//	pDevice->SetRenderState(D3DRS_ALPHATESTENABLE, false);
//	pDevice->SetRenderState(D3DRS_SEPARATEALPHABLENDENABLE, true);
//	pDevice->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
//	pDevice->SetRenderState(D3DRS_SRCBLENDALPHA, D3DBLEND_INVDESTALPHA);
//	pDevice->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
//	pDevice->SetRenderState(D3DRS_DESTBLENDALPHA, D3DBLEND_ONE);
//
//	pDevice->SetRenderState(D3DRS_SRGBWRITEENABLE, false);
//	pDevice->SetRenderState(D3DRS_COLORWRITEENABLE, D3DCOLORWRITEENABLE_RED | D3DCOLORWRITEENABLE_GREEN | D3DCOLORWRITEENABLE_BLUE | D3DCOLORWRITEENABLE_ALPHA);
//
//	pDevice->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
//	pDevice->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
//	pDevice->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
//	pDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
//	pDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
//	pDevice->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
//
//	pDevice->SetSamplerState(0, D3DSAMP_MINFILTER, D3DTEXF_LINEAR);
//	pDevice->SetSamplerState(0, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR);
//}
//
//int CDirectRender::GetTextWidth(const char* szText, LPD3DXFONT font)
//{
//	RECT rcRect = { 0, 0, 0, 0 };
//	if (font)
//		font->DrawText(NULL, szText, strlen(szText), &rcRect, DT_CALCRECT,
//			D3DCOLOR_XRGB(0, 0, 0));
//
//	return rcRect.right - rcRect.left;
//}
//
//void CDirectRender::Text(float x, float y, LPD3DXFONT font, std::string text, Color color, bool centered, int drop_shadow, Color shadow_color)
//{
//	if (centered)
//		x -= (GetTextWidth(text.c_str(), font) / 2);
//
//	RECT DrawArea = { x, y, 1920, DrawArea.top + 200 };
//
//	if (drop_shadow == 1)
//	{
//		RECT DrawArea2 = { x + 1, y, 1920, DrawArea.top + 200 };
//		RECT DrawArea4 = { x, y + 1, 1920, DrawArea.top + 200 };
//		font->DrawTextA(NULL, text.c_str(), -1, &DrawArea2, 0, D3DCOLOR_RGBA(shadow_color.r(), shadow_color.g(), shadow_color.b(), shadow_color.a()));
//		font->DrawTextA(NULL, text.c_str(), -1, &DrawArea4, 0, D3DCOLOR_RGBA(shadow_color.r(), shadow_color.g(), shadow_color.b(), shadow_color.a()));
//	}
//	else if (drop_shadow == 2)
//	{
//		RECT DrawArea2 = { x + 1.f, y, 1920, DrawArea.top + 200 };
//		RECT DrawArea3 = { x - 1.f, y, 1920, DrawArea.top + 200 };
//		RECT DrawArea4 = { x, y + 1.f, 1920, DrawArea.top + 200 };
//		RECT DrawArea5 = { x, y - 1.f, 1920, DrawArea.top + 200 };
//		font->DrawTextA(NULL, text.c_str(), -1, &DrawArea2, 0, D3DCOLOR_RGBA(shadow_color.r(), shadow_color.g(), shadow_color.b(), shadow_color.a()));
//		font->DrawTextA(NULL, text.c_str(), -1, &DrawArea3, 0, D3DCOLOR_RGBA(shadow_color.r(), shadow_color.g(), shadow_color.b(), shadow_color.a()));
//		font->DrawTextA(NULL, text.c_str(), -1, &DrawArea4, 0, D3DCOLOR_RGBA(shadow_color.r(), shadow_color.g(), shadow_color.b(), shadow_color.a()));
//		font->DrawTextA(NULL, text.c_str(), -1, &DrawArea5, 0, D3DCOLOR_RGBA(shadow_color.r(), shadow_color.g(), shadow_color.b(), shadow_color.a()));
//	}
//
//	font->DrawTextA(NULL, text.c_str(), -1, &DrawArea, 0, D3DCOLOR_RGBA(color.r(), color.g(), color.b(), color.a()));
//}
//
//void CDirectRender::GradientVertical(Vector2D a, Vector2D b, Color c_a, Color c_b)
//{
//	b += a;
//
//	Vertice_t verts[4] = {
//		{ a.x, a.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c_a.r(), c_a.g(), c_a.b(), c_a.a()) },
//		{ b.x, a.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c_a.r(), c_a.g(), c_a.b(), c_a.a()) },
//		{ a.x, b.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c_b.r(), c_b.g(), c_b.b(), c_b.a()) },
//		{ b.x, b.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c_b.r(), c_b.g(), c_b.b(), c_b.a()) }
//	};
//
//	pDevice->SetTexture(0, nullptr);
//	pDevice->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, &verts, 20);
//}
//
//void CDirectRender::GradientVerticalInit(float x, float y, float w, float h, Color c_a, Color c_b)
//{
//	GradientVertical({ x, y }, { w, h }, c_a, c_b);
//}
//
//void CDirectRender::GradientHorizontal(Vector2D a, Vector2D b, Color c_a, Color c_b)
//{
//	b += a;
//
//	Vertice_t verts[4] = {
//		{ a.x, a.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c_a.r(), c_a.g(), c_a.b(), c_a.a()) },
//		{ a.x, b.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c_a.r(), c_a.g(), c_a.b(), c_a.a()) },
//		{ b.x, a.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c_b.r(), c_b.g(), c_b.b(), c_b.a()) },
//		{ b.x, b.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c_b.r(), c_b.g(), c_b.b(), c_b.a()) }
//	};
//
//	pDevice->SetTexture(0, nullptr);
//	pDevice->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, &verts, 20);
//}
//
//void CDirectRender::GradientHorizontalInit(float x, float y, float w, float h, Color c_a, Color c_b)
//{
//	GradientHorizontal({ x, y }, { w, h }, c_a, c_b);
//}
//
//void CDirectD::Line(Vector2D a, Vector2D b, Color c)
//{
//	Vertice_t verts[2] = {
//		{ a.x, a.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) },
//		{ b.x, b.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) }
//	};
//
//	pDevice->SetTexture(0, nullptr);
//	pDevice->DrawPrimitiveUP(D3DPT_LINELIST, 1, &verts, 20);
//}
//
//void CDirectD::LineInit(float x, float y, float x1, float x2, Color c)
//{
//	Line({ x, y }, { x1, x2 }, c);
//}
//
//void CDirectRender::Outline(Vector2D a, Vector2D b, Color c)
//{
//	b += a;
//
//	b.x -= 1;
//	b.y -= 1;
//
//	Vertice_t verts[5] = {
//		{ float(a.x), float(a.y), 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) },
//		{ float(b.x), float(a.y), 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) },
//		{ float(b.x), float(b.y), 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) },
//		{ float(a.x), float(b.y), 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) },
//		{ float(a.x), float(a.y), 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) }
//	};
//
//	pDevice->SetTexture(0, nullptr);
//	pDevice->DrawPrimitiveUP(D3DPT_LINESTRIP, 4, &verts, 20);
//}
//
//void CDirectRender::OutlineInit(float x, float y, float w, float h, Color c)
//{
//	Outline({ x, y }, { w + 1, h + 1 }, c);
//}
//
//void CDirectD::Rect(Vector2D a, Vector2D b, Color c)
//{
//	b += a;
//
//	Vertice_t verts[4] = {
//		{ a.x, a.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) },
//		{ b.x, a.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) },
//		{ a.x, b.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) },
//		{ b.x, b.y, 0.01f, 0.01f, D3DCOLOR_RGBA(c.r(), c.g(), c.b(), c.a()) }
//	};
//
//	pDevice->SetTexture(0, nullptr);
//	pDevice->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, &verts, 20);
//}
//
//void CDirectD::RectInit(float x, float y, float w, float h, Color c)
//{
//	Rect({ x, y }, { w, h }, c);
//}
