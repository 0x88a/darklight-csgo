#pragma once
// @credits: https://github.com/ValveSoftware/source-sdk-2013/blob/master/sp/src/public/vgui/ISurface.h

// used: color
#include "../datatypes/color.h"
// used: vector
#include "../datatypes/vector.h"

typedef unsigned long HScheme, HPanel, HTexture, HCursor, HFont;

#pragma region surface_enumerations
enum EFontDrawType : int
{
	FONT_DRAW_DEFAULT = 0,
	FONT_DRAW_NONADDITIVE,
	FONT_DRAW_ADDITIVE,
	FONT_DRAW_TYPE_COUNT = 2
};

enum EFontFlags
{
	FONTFLAG_NONE,
	FONTFLAG_ITALIC = 0x001,
	FONTFLAG_UNDERLINE = 0x002,
	FONTFLAG_STRIKEOUT = 0x004,
	FONTFLAG_SYMBOL = 0x008,
	FONTFLAG_ANTIALIAS = 0x010,
	FONTFLAG_GAUSSIANBLUR = 0x020,
	FONTFLAG_ROTARY = 0x040,
	FONTFLAG_DROPSHADOW = 0x080,
	FONTFLAG_ADDITIVE = 0x100,
	FONTFLAG_OUTLINE = 0x200,
	FONTFLAG_CUSTOM = 0x400,
	FONTFLAG_BITMAP = 0x800,
};
#pragma endregion

struct Vertex_t
{
	Vertex_t() = default;
	Vertex_t(const Vector2D& pos, const Vector2D& coordinate = Vector2D(0, 0))
	{
		vecPosition = pos;
		vecCoordinate = coordinate;
	}
	Vertex_t(const Vector& pos, const Vector& coordinate = Vector(0, 0, 0))
	{
		vecPosition = { pos.x, pos.y };
		vecCoordinate = { coordinate.x, coordinate.y };
	}

	void Init(const Vector2D& pos, const Vector2D& coordinate = Vector2D(0, 0))
	{
		vecPosition = pos;
		vecCoordinate = coordinate;
	}

	Vector vecPosition;
	Vector vecCoordinate;
};

class ISurface
{
public:
	void DrawSetColor(Color color)
	{
		MEM::CallVFunc<void>(this, 14, color);
	}

	void DrawSetColor(int r, int g, int b, int a)
	{
		MEM::CallVFunc<void>(this, 15, r, g, b, a);
	}

	void DrawFilledRect(int x0, int y0, int x1, int y1)
	{
		MEM::CallVFunc<void>(this, 16, x0, y0, x1, y1);
	}

	void DrawFilledRectFade(int x0, int y0, int x1, int y1, uint32_t uAlpha0, uint32_t uAlpha1, bool bHorizontal)
	{
		MEM::CallVFunc<void>(this, 123, x0, y0, x1, y1, uAlpha0, uAlpha1, bHorizontal);
	}

	void DrawOutlinedRect(int x0, int y0, int x1, int y1)
	{
		MEM::CallVFunc<void>(this, 18, x0, y0, x1, y1);
	}

	void DrawLine(int x0, int y0, int x1, int y1)
	{
		MEM::CallVFunc<void>(this, 19, x0, y0, x1, y1);
	}

	void DrawPolyLine(int* x, int* y, int nPoints)
	{
		MEM::CallVFunc<void>(this, 20, x, y, nPoints);
	}

	void DrawSetTextFont(HFont hFont)
	{
		MEM::CallVFunc<void>(this, 23, hFont);
	}

	void DrawSetTextColor(Color color)
	{
		MEM::CallVFunc<void>(this, 24, color);
	}

	void DrawSetTextColor(int r, int g, int b, int a)
	{
		MEM::CallVFunc<void>(this, 25, r, g, b, a);
	}

	void DrawSetTextPos(int x, int y)
	{
		MEM::CallVFunc<void>(this, 26, x, y);
	}

	void DrawPrintText(const wchar_t* wText, int nTextLength)
	{
		MEM::CallVFunc<void>(this, 28, wText, nTextLength, 0);
	}

	void DrawSetTextureRGBA(int nIndex, const unsigned char* rgba, int iWide, int iTall)
	{
		//MEM::CallVFunc<void>(this, 37, nIndex, rgba, iWide, iTall);
		using original_fn = void(__thiscall*)(void*, int, const unsigned char*, int, int);
		(*(original_fn**)this)[37](this, nIndex, rgba, iWide, iTall);
	}

	void DrawSetTextureRGBA(int nIndex, Color* rgba, int iWide, int iTall)
	{
		//MEM::CallVFunc<void>(this, 37, nIndex, rgba, iWide, iTall);
		using original_fn = void(__thiscall*)(void*, int, Color*, int, int);
		(*(original_fn**)this)[37](this, nIndex, rgba, iWide, iTall);
	}


	void DrawSetTexture(int nIndex)
	{
		//MEM::CallVFunc<void>(this, 38, nIndex);
		using original_fn = void(__thiscall*)(void*, int);
		(*(original_fn**)this)[38](this, nIndex);
	}

	void DrawSetTexturedRect(int iX, int iY, int iX0, int iY0)
	{
		//MEM::CallVFunc<void>(this, 41, iX, iY, iX0, iY0);
		using original_fn = void(__thiscall*)(void*, int, int, int, int);
		(*(original_fn**)this)[41](this, iX, iY, iX0, iY0);
	}

	bool IsTexturedIdValid(int iTextureID)
	{
		return MEM::CallVFunc<bool>(this, 42, iTextureID);
	}

	int CreateNewTextureID(bool bProcedural = false)
	{
		//return MEM::CallVFunc<int>(this, 43, bProcedural);
		using original_fn = int(__thiscall*)(void*, bool);
		return (*(original_fn**)this)[43](this, bProcedural);
	}

	void UnLockCursor()
	{
		return MEM::CallVFunc<void>(this, 66);
	}

	void SetMouseInputEnabled(unsigned int uPanel, bool bState)
	{
		MEM::CallVFunc<void>(this, 32, uPanel, bState);
	}
	void SetKeyboardInputEnabled(unsigned int uPanel, bool bState)
	{
		MEM::CallVFunc<void>(this, 31, uPanel, bState);
	}

	void LockCursor()
	{
		return MEM::CallVFunc<void>(this, 67);
	}

	HFont FontCreate()
	{
		return MEM::CallVFunc<HFont>(this, 71);
	}

	void SetFontGlyphSet(HFont hFont, const char* szWindowsFontName, int iTall, int iWeight, int iBlur, int nScanLines, int iFlags, int nRangeMin = 0, int nRangeMax = 0)
	{
		return MEM::CallVFunc<void>(this, 72, hFont, szWindowsFontName, iTall, iWeight, iBlur, nScanLines, iFlags, nRangeMin, nRangeMax);
	}

	void GetTextSize(HFont hFont, const wchar_t* wText, int& iWide, int& iTall)
	{
		// I don't fucking know, I don't want to know.
		//MEM::CallVFunc<void>(this, 79, hFont, wText, iWide, iTall);
		using original_fn = void(__thiscall*)(void*, unsigned long, const wchar_t*, int&, int&);
		return (*(original_fn**)this)[79](this, hFont, wText, iWide, iTall);
	}

	void PlaySoundSurface(const char* szFileName)
	{
		MEM::CallVFunc<void>(this, 82, szFileName);
	}

	void DrawColoredCircle(int x, int y, float iRadius, Color col)
	{
		using original_fn = void(__thiscall*)(void*, int, int, float, int, int, int, int);
		return (*(original_fn**)this)[162](this, x, y, iRadius, col.r(), col.g(), col.b(), col.a());
	}

	void DrawOutlinedCircle(int x, int y, int iRadius, int nSegments)
	{
		MEM::CallVFunc<void>(this, 103, x, y, iRadius, nSegments);
	}

	void DrawTexturedPolygon(int n, Vertex_t* pVertice, bool bClipVertices = false)
	{
		MEM::CallVFunc<void>(this, 106, n, pVertice, bClipVertices);
	}
};