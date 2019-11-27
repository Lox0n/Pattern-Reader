#include <windows.h>
#include <cstdio>
#include <vector>
#include <memory>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <atlbase.h>
#include <ctime>

#pragma comment( lib, "Urlmon")

static constexpr auto WEBSITE_URL = L"http://localhost/Patterns.txt";
static constexpr auto DOWNLOAD_TO_FILE = false;

//https://github.com/spirthack/CSGOSimple/blob/ce77886d094596138f4a63d355250834744b6a75/CSGOSimple/helpers/utils.cpp#L226
std::uint8_t* PatternScan(void* module, const char* signature)
{
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

	auto dosHeader = (PIMAGE_DOS_HEADER)module;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

	auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = pattern_to_byte(signature);
	auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

	auto s = patternBytes.size();
	auto d = patternBytes.data();

	for (auto i = 0ul; i < sizeOfImage - s; ++i) {
		bool found = true;
		for (auto j = 0ul; j < s; ++j) {
			if (scanBytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}
		if (found) {
			return &scanBytes[i];
		}
	}
	return nullptr;
}

namespace FileHelper
{
	auto ReadFileByLine(const wchar_t* wsFilePath)
	{
		std::ifstream ifs(wsFilePath);
		std::vector<std::string> lines;

		std::string line;
		while (std::getline(ifs, line))
		{
			//Skip empty lines and comments.
			if (line.empty() || line.find('#') != std::string::npos || line.find("//") != std::string::npos)
				continue;

			lines.push_back(line);
		}
		return lines;
	}

	auto ReadFileByLine(char* buffer)
	{
		std::istringstream str(buffer);

		std::vector<std::string> lines;

		std::string line;
		while (std::getline(str, line))
		{
			//Skip empty lines and comments.
			if (line.empty() || line.find('#') != std::string::npos || line.find("//") != std::string::npos)
				continue;

			lines.push_back(line);
		}
		return lines;
	}
}

//https://stackoverflow.com/a/44029974
struct ComInit
{
	HRESULT hr;
	ComInit() : hr(::CoInitialize(nullptr)) {}
	~ComInit() { if (SUCCEEDED(hr)) ::CoUninitialize(); }
};

int main()
{
	//Initialize COM.
	ComInit com;
	HRESULT hr;

	std::vector<std::string> patterns;
	bool success = false;

	if (DOWNLOAD_TO_FILE)
	{
		wchar_t wsPath[MAX_PATH];
		GetCurrentDirectoryW(MAX_PATH, wsPath);

		SYSTEMTIME st{ };
		GetLocalTime(&st);

		//Save it with time and date, for prettier view and control.
		swprintf_s(wsPath, L"%ws\\patterns_%.2d-%.2d-%.4d_(%.2d:%.2d).txt", wsPath, st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);

		if (FAILED(hr = URLDownloadToFileW(nullptr, WEBSITE_URL, wsPath, 0, nullptr)))
		{
			std::cout << "ERROR: URLDownloadToFileA failed! HRESULT: 0x" << std::hex << hr << std::dec << "\n";
			return 1;
		}

		patterns = FileHelper::ReadFileByLine(wsPath);
		success = true;
	}
	else
	{
		CComPtr<IStream> pStream;

		//Basically download it and use it directly from the memory stream.
		if (FAILED(hr = URLOpenBlockingStreamW(nullptr, WEBSITE_URL, &pStream, 0, nullptr)))
		{
			std::cout << "ERROR: URLOpenBlockingStreamA failed! HRESULT: 0x" << std::hex << hr << std::dec << "\n";
			return 1;
		}

		STATSTG stat{ };
		if (FAILED(hr = pStream->Stat(&stat, STATFLAG_NONAME)))
		{
			std::cout << "ERROR: pStream->Stat failed! HRESULT: 0x" << std::hex << hr << std::dec << "\n";
			return 1;
		}

		DWORD dwSize = stat.cbSize.LowPart + 1;

		auto buffer = PCHAR(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize));
		if (!buffer)
		{
			std::cout << "ERROR: HeapAlloc failed! Code: 0x" << std::hex << GetLastError() << std::dec << "\n";
			return 1;
		}

		LARGE_INTEGER liPos{ };
		if (FAILED(hr = pStream->Seek(liPos, STREAM_SEEK_SET, NULL)))
		{
			if (buffer)
				HeapFree(GetProcessHeap(), NULL, buffer);

			std::cout << "ERROR: pStream->Seek failed! HRESULT: 0x" << std::hex << hr << std::dec << "\n";
			return 1;
		}

		if (FAILED(hr = pStream->Read(buffer, dwSize - 1, NULL)))
		{
			if (buffer)
				HeapFree(GetProcessHeap(), NULL, buffer);

			std::cout << "ERROR: pStream->Read failed! HRESULT: 0x" << std::hex << hr << std::dec << "\n";
			return 1;
		}

		patterns = FileHelper::ReadFileByLine(buffer);
		success = true;

		if (buffer)
			HeapFree(GetProcessHeap(), NULL, buffer);
	}

	//The sig-scanning itself.
	if (success)
	{
		for (auto& sig : patterns)
		{
			auto Address = PatternScan(GetModuleHandleW(nullptr), sig.c_str());

			if (!Address)
			{
				//do w/e you want...
			}
		}
	}

	return 0;
}