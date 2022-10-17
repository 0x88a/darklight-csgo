#pragma once
// used: std::function
#include <functional>

// used: winapi, directx, imgui, fmt includes
#include "../common.h"
// used: color
#include "../sdk/datatypes/color.h"
// used: vector
#include "../sdk/datatypes/vector.h"

#include "../sdk/interfaces/isurface.h"
#include "../global.h"
#include "math.h"

/*
 * DRAW
 * ready rendering framework
 */
namespace D
{
	inline unsigned long uVerdana[5];
	inline unsigned long uSmallFonts[5];
	inline unsigned long uVerdanaBig[5];
	inline unsigned long uMenuFont[5];
	inline unsigned long uMenuFontBold[5];
	inline unsigned long uMenuSliderFont[5];
	inline unsigned long uTrebuchetMS[5];

	inline int ScaleDPI(int i, int x = G::iDPIScale)
	{
		return (i * (1.0f + (0.25f * x)));
	}

	void Initialize();

	void OutlinedRect(int x, int y, int w, int h, Color col);
	void Line(int x, int y, int x1, int y1, Color col);
	void Rect(int x, int y, int w, int h, Color col);
	void String(int x, int y, Color col, unsigned long font, const char* text, ...);
	void String(int, int, unsigned long, std::string, int, Color);

	void RectFade(int x, int y, int x1, int y1, Color first, Color second, bool = false, bool = false);

	RECT GetTextSize(unsigned long font, std::string text);

	void TexturedPolygon(int n, Vertex_t* vertice, Color col);
	void DrawFilledTriangle(std::array<Vector, 3> points, Color colour);
	void DrawFilledCircle(Vector center, Color color, float radius, float points);

	bool WorldToScreen(const Vector& vecOrigin, Vector2D& vecScreen);
}

struct Vertice_t
{
	float x, y, z, rhw;
	int c;
};

//class CDirectRender
//{
//public:
//	CDirectRender(IDirect3DDevice9* device)
//	{
//		this->pDevice = device;
//		this->pVertexShader = pVertexShader;
//
//		device->GetViewport(&screenSize);
//	}
//
//	IDirect3DVertexShader9* pVertexShader;
//	IDirect3DDevice9* pDevice;
//	D3DVIEWPORT9 screenSize;
//
//	void SetRenderStates();
//
//	int GetTextWidth(const char*, LPD3DXFONT);
//	void Text(float, float, LPD3DXFONT, std::string, Color, bool = false, int = 0, Color = Color());
//
//	void Line(Vector2D, Vector2D, Color);
//	void LineInit(float, float, float, float, Color);
//
//	void Rect(Vector2D, Vector2D, Color);
//	void RectInit(float, float, float, float, Color);
//
//	void Outline(Vector2D, Vector2D, Color);
//	void OutlineInit(float, float, float, float, Color);
//
//	void GradientVertical(Vector2D, Vector2D, Color, Color);
//	void GradientVerticalInit(float, float, float, float, Color, Color);
//
//	void GradientHorizontal(Vector2D, Vector2D, Color, Color);
//	void GradientHorizontalInit(float, float, float, float, Color, Color);
//
//	inline void SetViewport(D3DVIEWPORT9 vp)
//	{
//		pDevice->SetViewport(&vp);
//	}
//
//	inline D3DVIEWPORT9 GetViewport()
//	{
//		D3DVIEWPORT9 vp;
//		pDevice->GetViewport(&vp);
//		return vp;
//	}
//
//	struct
//	{
//		LPD3DXFONT mainFont;
//		LPD3DXFONT secondFont;
//	} fonts;
//};
//
//extern CDirectRender* g_pDrawList;