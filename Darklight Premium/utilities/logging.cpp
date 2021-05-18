#include "logging.h"

bool L::Attach(const char* szConsoleTitle)
{
	if (!AllocConsole())
		return false;

	if (AttachConsole(GetCurrentProcessId()) != 0)
		return false;

	if (freopen_s(&pStream, _("CONOUT$"), _("w"), stdout) != 0)
		return false;

	if (!SetConsoleTitle(szConsoleTitle))
		return false;

	return true;
}

void L::Detach()
{
	fclose(pStream);

	FreeConsole();

	if (const auto hConsoleWnd = GetConsoleWindow(); hConsoleWnd != nullptr)
		PostMessageW(hConsoleWnd, WM_CLOSE, 0U, 0L);
}

void L::Print(std::string_view szText)
{
	tm time = { };
	const std::chrono::system_clock::time_point systemNow = std::chrono::system_clock::now();
	const std::time_t timeNow = std::chrono::system_clock::to_time_t(systemNow);
	localtime_s(&time, &timeNow);

	std::string szTime = fmt::format(_("[{:%d-%m-%Y %X}] "), time);

	#if DEBUG_CONSOLE
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSE_GREEN);
	fmt::print(szTime);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wConsoleColor);
	fmt::print(_("{}\n"), szText);
	#else
	if (ofsFile.is_open())
		ofsFile << szTime << szText << std::endl;
	#endif
}
