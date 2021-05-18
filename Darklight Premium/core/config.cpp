#include <shlobj.h>

#include "config.h"
#include "variables.h"
#include "../utilities/logging.h"
#include "../../dependencies/json/json.hpp"

bool C::Setup(std::string_view szDefaultFileName)
{
	if (!std::filesystem::is_directory(fsPath / G::szUsername.c_str()))
	{
		std::filesystem::remove(fsPath / G::szUsername.c_str());
		if (!std::filesystem::create_directories(fsPath / G::szUsername.c_str()))
			return false;
	}

	if (!std::filesystem::exists(fsPath / G::szUsername.c_str() / szDefaultFileName))
	{
		if (!Save(szDefaultFileName))
			return false;
	}

	if (!Load(szDefaultFileName))
		return false;

	Refresh();
}

bool C::Save(std::string_view szFileName)
{
	std::filesystem::path fsFilePath(szFileName);
	if (fsFilePath.extension() != _(".cfg"))
		fsFilePath.replace_extension(_(".cfg"));

	const std::string szFile = std::filesystem::path(fsPath / G::szUsername.c_str() / fsFilePath).u8string();
	nlohmann::json config;

	for (auto& variable : vecVariables)
	{
		nlohmann::json entry;

		// save hashes to compare it later
		entry[_("name-id")] = variable.uNameHash;
		entry[_("type-id")] = variable.uTypeHash;

		// get current variable
		switch (variable.uTypeHash)
		{
		case FNV1A::HashConst("int"):
		{
			entry[_("value")] = variable.Get<int>();
			break;
		}
		case FNV1A::HashConst("float"):
		{
			entry[_("value")] = variable.Get<float>();
			break;
		}
		case FNV1A::HashConst("bool"):
		{
			entry[_("value")] = variable.Get<bool>();
			break;
		}
		case FNV1A::HashConst("Color"):
		{
			auto colVariable = variable.Get<Color>();

			nlohmann::json sub;

			sub.push_back(colVariable.r());
			sub.push_back(colVariable.g());
			sub.push_back(colVariable.b());
			sub.push_back(colVariable.a());

			entry[_("value")] = sub.dump();
			break;
		}
		case FNV1A::HashConst("std::deque<bool>"):
		{
			auto vecVariable = variable.Get<std::deque<bool>>();

			nlohmann::json sub;

			for (auto& bValue : vecVariable)
				sub.push_back((bool)bValue);

			entry[_("value")] = sub.dump();
			break;
		}
		case FNV1A::HashConst("std::deque<std::string>"):
		{
			auto vecVariable = variable.Get<std::deque<std::string>>();

			nlohmann::json sub;

			for (auto& bValue : vecVariable)
				sub.push_back((std::string)bValue);

			entry[_("value")] = sub.dump();
			break;
		}
		case FNV1A::HashConst("std::deque<int>"):
		{
			auto vecVariable = variable.Get<std::deque<int>>();

			nlohmann::json sub;

			for (auto& bValue : vecVariable)
				sub.push_back((int)bValue);

			entry[_("value")] = sub.dump();
			break;
		}
		case FNV1A::HashConst("std::deque<float>"):
		{
			auto vecVariable = variable.Get<std::deque<float>>();

			nlohmann::json sub;

			for (auto& bValue : vecVariable)
				sub.push_back((float)bValue);

			entry[_("value")] = sub.dump();
			break;
		}
		default:
			break;
		}

		config.push_back(entry);
	}

	std::ofstream ofsOutFile(szFile, std::ios::out | std::ios::trunc);

	if (!ofsOutFile.good())
		return false;

	try
	{
		ofsOutFile << config.dump(4);
		ofsOutFile.close();
	}
	catch (std::ofstream::failure& ex)
	{
		throw std::runtime_error(fmt::format(_("Failed to save configuration: {}"), ex.what()));
		return false;
	}

	L::Print(fmt::format(_("Saved configuration at: {}"), szFile));
	return true;
}

bool C::Load(std::string_view szFileName)
{
	std::filesystem::path fsFilePath(szFileName);
	if (fsFilePath.extension() != _(".cfg"))
		fsFilePath.replace_extension(_(".cfg"));

	const std::string szFile = std::filesystem::path(fsPath / G::szUsername.c_str() / fsFilePath).u8string();
	nlohmann::json config;

	std::ifstream ifsInputFile(szFile, std::ios::in);

	if (!ifsInputFile.good())
		return false;

	try
	{
		ifsInputFile >> config;
		ifsInputFile.close();
	}
	catch (std::ifstream::failure& ex)
	{
		throw std::runtime_error(fmt::format(_("Failed to load configuration: {}"), ex.what()));
		return false;
	}

	for (auto& variable : config)
	{
		int nIndex = GetVariableIndex(variable[_("name-id")].get<FNV1A_t>());

		if (nIndex == C_INVALID_VARIABLE)
			continue;

		auto& entry = vecVariables.at(nIndex);

		switch (variable[_("type-id")].get<FNV1A_t>())
		{
		case FNV1A::HashConst("bool"):
		{
			entry.Set<bool>(variable[_("value")].get<bool>());
			break;
		}
		case FNV1A::HashConst("float"):
		{
			entry.Set<float>(variable[_("value")].get<float>());
			break;
		}
		case FNV1A::HashConst("int"):
		{
			entry.Set<int>(variable[_("value")].get<int>());
			break;
		}
		case FNV1A::HashConst("Color"):
		{
			auto color = nlohmann::json::parse(variable[_("value")].get<std::string>());

			entry.Set<Color>(Color(
				color.at(0).get<int>(),
				color.at(1).get<int>(),
				color.at(2).get<int>(),
				color.at(3).get<int>()
			));

			break;
		}
		case FNV1A::HashConst("std::deque<bool>"):
		{
			auto vector = nlohmann::json::parse(variable[_("value")].get<std::string>());
			auto& vecVariable = entry.Get<std::deque<bool>>();

			for (std::size_t i = 0U; i < vector.size(); i++)
			{
				if (i < vecVariable.size())
					vecVariable.at(i) = vector.at(i).get<bool>();
			}

			break;
		}
		case FNV1A::HashConst("std::deque<std::string>"):
		{
			auto vector = nlohmann::json::parse(variable[_("value")].get<std::string>());
			auto& vecVariable = entry.Get<std::deque<std::string>>();

			for (std::size_t i = 0U; i < vector.size(); i++)
			{
				if (i < vecVariable.size())
					vecVariable.at(i) = vector.at(i).get<std::string>();
			}

			break;
		}
		case FNV1A::HashConst("std::deque<int>"):
		{
			auto vector = nlohmann::json::parse(variable[_("value")].get<std::string>());
			auto& vecVariable = entry.Get<std::deque<int>>();

			for (std::size_t i = 0U; i < vector.size(); i++)
			{
				if (i < vecVariable.size())
					vecVariable.at(i) = vector.at(i).get<int>();
			}

			break;
		}
		case FNV1A::HashConst("std::deque<float>"):
		{
			auto vector = nlohmann::json::parse(variable[_("value")].get<std::string>());
			auto& vecVariable = entry.Get<std::deque<float>>();

			for (std::size_t i = 0U; i < vector.size(); i++)
			{
				if (i < vecVariable.size())
					vecVariable.at(i) = vector.at(i).get<float>();
			}

			break;
		}
		default:
			break;
		}
	}

	L::Print(fmt::format(_("Loaded configuration at: {}"), szFile));
	return true;
}

bool C::ImportClipboard(std::string_view szFileName)
{
	const auto ClipboardData = []() -> std::string {
		OpenClipboard(0);
		HANDLE hData = GetClipboardData(CF_TEXT);
		char* szData = static_cast<char*>(GlobalLock(hData));
		std::string szText = szData;
		GlobalUnlock(hData);
		CloseClipboard();
		return szText;
	};

	std::filesystem::path fsFilePath(szFileName);
	if (fsFilePath.extension() != _(".cfg"))
		fsFilePath.replace_extension(_(".cfg"));

	const std::string szFile = std::filesystem::path(fsPath / G::szUsername.c_str() / fsFilePath).u8string();

	auto szClipboard = ClipboardData();

	auto ofOutput = std::ofstream(szFile);
	if (!ofOutput.good())
		return false;

	ofOutput.clear();
	ofOutput << szClipboard;
	ofOutput.close();

	return Load(szFileName);
}

bool C::ExportClipboard(std::string_view szFileName)
{
	std::filesystem::path fsFilePath(szFileName);
	if (fsFilePath.extension() != _(".cfg"))
		fsFilePath.replace_extension(_(".cfg"));

	const std::string szFile = std::filesystem::path(fsPath / G::szUsername.c_str() / fsFilePath).u8string();

	if (!Save(szFileName))
		return false;

	std::ifstream szInputFile = std::ifstream(szFile);
	std::string str((std::istreambuf_iterator< char >(szInputFile)), std::istreambuf_iterator< char >());

	const char* szOutput = str.c_str();
	const size_t nLen = strlen(szOutput) + 1;

	HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, nLen);
	memcpy(GlobalLock(hMem), szOutput, nLen);

	GlobalUnlock(hMem);
	OpenClipboard(0);
	EmptyClipboard();
	SetClipboardData(CF_TEXT, hMem);
	CloseClipboard();

	return true;
}

void C::Remove(std::string_view szFileName)
{
	std::filesystem::path fsFilePath(szFileName);
	if (fsFilePath.extension() != _(".cfg"))
		fsFilePath.replace_extension(_(".cfg"));

	if (!szFileName.compare(_("default")))
		return;

	const std::string szFile = std::filesystem::path(fsPath / G::szUsername.c_str() / szFileName).u8string();

	if (std::remove(szFile.c_str()))
		L::Print(fmt::format(_("Removed configuration at: {}"), szFile));
}

void C::Refresh()
{
	vecFileNames.clear();

	for (const auto& it : std::filesystem::directory_iterator(fsPath / G::szUsername.c_str()))
    {
		if (it.path().filename().extension() == _(".cfg"))
		{
			std::string szName = it.path().filename().string();

			L::Print(fmt::format(_("Found configuration file: {}"), it.path().filename().string()));

			if (!szName.empty())
				std::transform(szName.begin(), szName.end(), szName.begin(), toupper);

			vecFileNames.push_back(szName);
		}
    }
}

std::size_t C::GetVariableIndex(const FNV1A_t uNameHash)
{
	for (std::size_t i = 0U; i < vecVariables.size(); i++)
	{
		if (vecVariables.at(i).uNameHash == uNameHash)
			return i;
	}

	return C_INVALID_VARIABLE;
}

std::filesystem::path C::GetWorkingPath()
{
	std::filesystem::path fsWorkingPath;

	if (PWSTR pszPathToDocuments; SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0UL, nullptr, &pszPathToDocuments)))
	{
		fsWorkingPath.assign(pszPathToDocuments);
		CoTaskMemFree(pszPathToDocuments);
	}
	
	return fsWorkingPath;
}
