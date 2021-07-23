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

#define CURL_STATICLIB
#include <curl/curl.h>
#include "machine_id.h"
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libcurl_a.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "normaliz.lib")

using json = nlohmann::json;

CURL* pCurl;

void toClipboard(const std::string& s) {
	OpenClipboard(nullptr);
	EmptyClipboard();
	HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (long)s.size() +1);
	if (!hg) {
		CloseClipboard();
		return;
	}
	memcpy(GlobalLock(hg), s.c_str(), (long)s.size());
	GlobalUnlock(hg);
	SetClipboardData(CF_TEXT, hg);
	CloseClipboard();
	GlobalFree(hg);
}

static size_t WriteCallbackString(void* contents, size_t size, size_t nmemb, void* userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

std::string AuthenticateUser(std::string hwid) {
	pCurl = curl_easy_init();
	CURLcode res;

	curl_easy_setopt(pCurl, CURLOPT_URL, _("http://nullus.io/global/loader/auth.php"));
	curl_easy_setopt(pCurl, CURLOPT_POST, 1L);

	curl_easy_setopt(pCurl, CURLOPT_USERAGENT, _("Mozilla/4.0 (Windows NT 1.3; Win32; x32; rv:70.5) Gecko/10111101 Firefox/70.201"));

	curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, _("Content-Type: application/json"));
	curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);

	std::string szBuild, szResponseMessage;

	szBuild +=
		_("{\"hwid\":\"") + hwid + _("\"\}");

	curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, (long)szBuild.size());
	curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, szBuild.c_str());
	curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, WriteCallbackString);
	curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &szResponseMessage);
	res = curl_easy_perform(pCurl);

	curl_easy_cleanup(pCurl);

	return szResponseMessage;
}

DWORD WINAPI OnDllAttach(LPVOID lpParameter)
{
	try
	{
		while (GetModuleHandle(SERVERBROWSER_DLL) == nullptr)
			std::this_thread::sleep_for(200ms);

		//ForceBluescreen(STATUS_ASSERTION_FAILURE);

		curl_global_init(CURL_GLOBAL_ALL);

		//std::string szResponse = AuthenticateUser(machineid::machineHash());

		//toClipboard(machineid::machineHash());

		//if (szResponse == _("No User"))
		//	throw std::runtime_error(("Bad HWID. Copied to clipboard."));

		//if (szResponse == _("Internal server error"))
		//	throw std::runtime_error(("Cheat Down. PANIC!!11111"));
		//
		//if (szResponse == _("Bad Email"))
		//	throw std::runtime_error(("Please verify your email."));

		//if (szResponse == _("Wrong Group"))
		//	throw std::runtime_error(("Banned or No Subscription."));

		#if DEBUG_CONSOLE
		if (!L::Attach(_("Darklight Debug Console")))
			throw std::runtime_error(_("Failed to attach console"));

		L::Print(_("Console opened"));
		#else
		//L::ofsFile.open(C::GetWorkingPath().append(_("debug.log")), std::ios::out | std::ios::trunc);
		#endif

		G::szUsername = "darklight"; //json::parse(szResponse)[_("username")];
		toClipboard("");

		if (!I::Setup())
			throw std::runtime_error(_("Failed to capture interfaces"));

		L::Print(_("Interfaces captured"));


		//if (strcmp(I::Engine->GetProductVersionString(), _("1.37.9.4")) != 0)
		//	throw std::runtime_error(_(I::Engine->GetProductVersionString()));

		#if DEBUG_CONSOLE
		if (strcmp(I::Engine->GetProductVersionString(), _("1.37.9.1")) != 0)
		{
			L::PushConsoleColor(FOREGROUND_RED | FOREGROUND_YELLOW);
			L::Print(fmt::format(_("[Warning] Version doesnt match! current CS:GO version: {}"), I::Engine->GetProductVersionString()));
			L::PopConsoleColor();
		}
		#endif

		if (!CNetvarManager::Get().Setup(_("netvars.txt")))
			throw std::runtime_error(_("Failed to initialize netvars"));

		L::Print(fmt::format(_("Found [{:d}] props in [{:d}] tables"), CNetvarManager::Get().iStoredProps, CNetvarManager::Get().iStoredTables));

		if (!M::Setup())
			throw std::runtime_error(_("Failed to get math exports"));

		L::Print(_("Math exports loaded"));

		if (!IPT::Setup())
			throw std::runtime_error(_("Failed to set window messages processor"));

		L::Print(_("InputSystem setup complete"));

		U::EntityListener.Setup();
		L::Print(_("Entity Listener initialized"));

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
		L::Print(_("Events registered"));

		if (!H::Setup())
			throw std::runtime_error(_("Failed initialize hooks"));

		L::Print(_("Hooks setup complete"));

		if (!P::Setup())
			throw std::runtime_error(_("Failed initialize proxies"));

		L::Print(_("Proxies applied"));

		D::Initialize();

		if (!C::Setup(_("default.cfg")))
		{
			L::PushConsoleColor(FOREGROUND_RED);
			L::Print(_("[Error] Failed setup and/or load default configuration"));
			L::PopConsoleColor();
		}
		else
			L::Print(_("Default config loaded"));

		L::PushConsoleColor(FOREGROUND_MAGENTA);
		L::Print(_("Darklight successfully loaded"));
		L::PopConsoleColor();
		I::GameConsole->Clear();

		I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight - Build date: %s / %s\n"), __DATE__, __TIME__);
		g_Visuals.vecEventVector.push_back(EventLogging_t{ fmt::format(_("Welcome {name}."), fmt::arg(_("name"), G::szUsername.c_str())) });
		I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("["));
		I::ConVar->ConsoleColorPrintf(Color(GUI::CONTROLS::m_cDefaultMenuCol), _("Darklight"));
		I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), _("]"));
		I::ConVar->ConsoleColorPrintf(Color(255, 255, 255), fmt::format(_(" Welcome {name}.\n"), fmt::arg(_("name"), G::szUsername.c_str())).c_str());

		std::transform(G::szUsername.begin(), G::szUsername.end(), G::szUsername.begin(), toupper);
	}
	catch (const std::runtime_error& ex)
	{
		MessageBox(nullptr, ex.what(), nullptr, MB_OK | MB_ICONERROR | MB_TOPMOST);
		FreeLibraryAndExitThread((HMODULE)lpParameter, EXIT_SUCCESS);
	}

	return 1UL;
}

DWORD WINAPI OnDllDetach(LPVOID lpParameter)
{
	while (!GUI::UTILS::KeyPressed(VK_F7))

	#if DEBUG_CONSOLE
	L::Detach();
	#else
	if (L::ofsFile.is_open())
		L::ofsFile.close();
	#endif

	U::EntityListener.Destroy();

	U::EventListener.Destroy();

	I::ConVar->FindVar(_("crosshair"))->SetValue(true);

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

		if (auto hThread = CreateThread(nullptr, 0U, OnDllDetach, hModule, 0UL, nullptr); hThread != nullptr)
			CloseHandle(hThread);

		return TRUE;
	}

	return FALSE;
}
