#pragma once
// used: winapi, fmt includes
#include "../common.h"
// used: std::vector for getfilledvector
#include <vector>
#include <deque>

#pragma region memory_modules_definitions
#define ENGINE_DLL				_("engine.dll")
#define CLIENT_DLL				_("client.dll")
#define LOCALIZE_DLL			_("localize.dll")
#define MATERIALSYSTEM_DLL		_("materialsystem.dll")
#define VGUI_DLL				_("vguimatsurface.dll")
#define VGUI2_DLL				_("vgui2.dll")
#define SHADERPIDX9_DLL			_("shaderapidx9.dll")
#define GAMEOVERLAYRENDERER_DLL _("gameoverlayrenderer.dll")
#define PHYSICS_DLL				_("vphysics.dll")
#define VSTDLIB_DLL				_("vstdlib.dll")
#define TIER0_DLL				_("tier0.dll")
#define INPUTSYSTEM_DLL			_("inputsystem.dll")
#define STUDIORENDER_DLL		_("studiorender.dll")
#define DATACACHE_DLL			_("datacache.dll")
#define STEAM_API_DLL			_("steam_api.dll")
#define MATCHMAKING_DLL			_("matchmaking.dll")
#define SERVER_DLL				_("server.dll")
#define SERVERBROWSER_DLL		_("serverbrowser.dll")
#pragma endregion

#pragma region memory_pattern_convert
#define INRANGE( x, min, max ) (x >= min && x <= max) 
#define GETBITS( x ) ( INRANGE( ( x&( ~0x20 ) ), 'A', 'F' ) ? ( ( x&( ~0x20 ) ) - 'A' + 0xA) : ( INRANGE( x, '0', '9' ) ? x - '0' : 0 ) )
#define GETBYTE( x ) ( GETBITS( x[0] ) << 4 | GETBITS( x[1] ) )
#pragma endregion

/*
 * singleton implementation
 * restricts the instantiation of a class to one single class instance
 */
template <typename T>
class CSingleton
{
protected:
	CSingleton() { }
	~CSingleton() { }

	CSingleton(const CSingleton&) = delete;
	CSingleton& operator=(const CSingleton&) = delete;

	CSingleton(CSingleton&&) = delete;
	CSingleton& operator=(CSingleton&&) = delete;
public:
	static T& Get()
	{
		static T pInstance{ };
		return pInstance;
	}
};

/* virtualprotect raii wrapper */
class CWrappedProtect
{
public:
	CWrappedProtect(void* pBaseAddress, std::size_t uLength, DWORD dwFlags)
	{
		this->pBaseAddress = pBaseAddress;
		this->uLength = uLength;

		if (!VirtualProtect(pBaseAddress, uLength, dwFlags, &dwOldFlags))
			throw std::system_error(GetLastError(), std::system_category(), _("failed to protect region"));
	}

	~CWrappedProtect()
	{
		VirtualProtect(pBaseAddress, uLength, dwOldFlags, &dwOldFlags);
	}
private:
	void*			pBaseAddress;
	std::size_t		uLength;
	DWORD			dwOldFlags;
};

/*
 * MEMORY
 * memory management functions
 */
namespace MEM
{
	/* ida style byte pattern comparison */
	// @todo: make new more modern, faster and simplify findpattern
	std::uintptr_t	FindPattern(const char* szModuleName, const char* szPattern);
	/* can we read/readwrite given memory region */
	bool			IsValidCodePtr(std::uintptr_t uAddress);

	/* returns vector filled with given value */
	template <typename T, std::size_t S>
	std::deque<T> GetFilledVector(const T& fill)
	{
		std::deque<T> vecTemp(S);
		std::fill(vecTemp.begin(), vecTemp.begin() + S, fill);
		return vecTemp;
	}

	/*
	 * virtual function implementation
	 * returns native function of specified class at given index
	 */
	inline constexpr void* GetVFunc(void* thisptr, std::size_t nIndex)
	{
		return (void*)((*(std::uintptr_t**)thisptr)[nIndex]);
	}

	/*
	 * virtual function call implementation
	 * calls function of specified class at given index
	 * @note: doesnt adding references automatic and needs to add it manually!
	 */
	template <typename T, typename ... args_t>
	inline constexpr T CallVFunc(void* thisptr, std::size_t nIndex, args_t... argList)
	{
		using VirtualFn = T(__thiscall*)(void*, decltype(argList)...);
		return (*(VirtualFn**)thisptr)[nIndex](thisptr, argList...);
	}

	inline std::uintptr_t GetAbsoluteAddress(const std::uintptr_t uRelativeAddress)
	{
		return uRelativeAddress + 0x4 + *reinterpret_cast<std::int32_t*>(uRelativeAddress);
	}
}
