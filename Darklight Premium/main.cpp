#include "common.h"
#include <thread>
#include <chrono>
using namespace std::chrono_literals;

#include "global.h"
#include "core/variables.h"
#include "utilities.h"
#include "utilities/logging.h"
#include "utilities/math.h"
#include "utilities/inputsystem.h"
#include "utilities/draw.h"
#include "core/netvar.h"
#include "core/config.h"
#include "core/hooks.h"
#include "features/visuals.h"
#include "core/gui/gui.h"
#include "../Dependencies/json/json.hpp"
#include "winuser.h"

#include <curl/curl.h>
#include "machine_id.h"
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libcurl_a.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "normaliz.lib")

using json = nlohmann::json;

__forceinline uint8_t* find_sig_ida(HMODULE module, std::string str_byte_array) {
	static auto pattern_to_byte = [](const char* pattern) {
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	};

	auto dos_header = (PIMAGE_DOS_HEADER)module;
	auto nt_headers = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dos_header->e_lfanew);

	auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
	auto pattern_bytes = pattern_to_byte(str_byte_array.c_str());
	auto scan_bytes = reinterpret_cast<std::uint8_t*>(module);

	auto s = pattern_bytes.size();
	auto d = pattern_bytes.data();

	for (auto i = 0ul; i < size_of_image - s; ++i) {
		bool found = true;
		for (auto j = 0ul; j < s; ++j) {
			if (scan_bytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}
		if (found) {
			return &scan_bytes[i];
		}
	}
	return nullptr;
}

DWORD WINAPI OnDllAttach(LPVOID lpParameter)
{
	try
	{
		while (GetModuleHandle(SERVERBROWSER_DLL) == nullptr)
			std::this_thread::sleep_for(200ms);

		long amongus = 0x69690004C201B0;
		static std::string sig = ("55 8B EC 56 8B F1 33 C0 57 8B 7D 08");

		LPCWSTR modules[]
		{
			L"client.dll",
			L"engine.dll",
			L"server.dll",
			L"studiorender.dll",
			L"materialsystem.dll"
		};

		// bypass.
		for (auto base : modules) {
			WriteProcessMemory(GetCurrentProcess(), find_sig_ida(GetModuleHandleW(base), sig), &amongus, 5, 0);
		}

		// init interfaces.
		I::Setup();

		// init netvars manager.
		CNetvarManager::Get().Setup(_("netvars.txt"));

		// ini math func.
		M::Setup();

		// init wndc.
		IPT::Setup();

		// init events.
		U::EntityListener.Setup();

		// setup events.
		U::EventListener.Setup(
			{
				_("player_hurt"),
				_("item_purchase"),
				_("player_given_c4"),
				_("bomb_beginplant"),
				_("bomb_abortplant"),
				_("bomb_planted"),
				_("bomb_begindefuse"),
				_("bomb_abortdefuse"),
				_("player_death")
			});

		// init hooks.
		H::Setup();

		// init sequence viewmodel manipulation.
		P::Setup();

		// init fonts.
		D::Initialize();

		if (C::Setup(_("default.cfg")))
			L::Print(_("Default config loaded"));
	}

	catch (const std::runtime_error& ex)
	{
		MessageBox(nullptr, ex.what(), nullptr, MB_OK | MB_ICONERROR | MB_TOPMOST);
		FreeLibraryAndExitThread((HMODULE)lpParameter, EXIT_SUCCESS);
	}

	return 1;
}

DWORD WINAPI OnDllDetach(LPVOID lpParameter)
{
	while (!GUI::UTILS::KeyPressed(VK_F7))

#if DEBUG_CONSOLE
#else
		if (L::ofsFile.is_open())
			L::ofsFile.close();
#endif

	// destoroy events.
	U::EventListener.Destroy();

#if 0
	P::Restore();
#endif

	H::Restore();

	IPT::Restore();

	FreeLibraryAndExitThread((HMODULE)lpParameter, EXIT_SUCCESS);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		if (GetModuleHandle(_("csgo.exe")) == nullptr)
			return FALSE;

		G::hDll = hModule;

		DisableThreadLibraryCalls(hModule);

		if (auto hThread = CreateThread(nullptr, 0U, OnDllAttach, hModule, 0UL, nullptr); hThread != nullptr)
			CloseHandle(hThread);

		return TRUE;
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{

		if (auto hThread = CreateThread(nullptr, 0U, OnDllDetach, hModule, 0UL, nullptr); hThread != nullptr)
			CloseHandle(hThread);

		return TRUE;
	}

	return FALSE;
}
