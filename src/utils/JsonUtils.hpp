#pragma once
#include <json.hpp>
#include <Windows.h>
#include <codecvt>
#include <locale>

using namespace nlohmann;

class json_utils {
public:
	static std::string to_utf8(std::wstring& wide_string)
    {
        if (wide_string.empty()) {
            return std::string();
        }
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wide_string[0], (int)wide_string.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wide_string[0], (int)wide_string.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;

        //static std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8_conv;
        //return utf8_conv.to_bytes(wide_string);
    }

    static std::wstring to_wstring(std::string& str)
    {
        if (str.empty()) {
            return std::wstring();
        }
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring strTo(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &strTo[0], size_needed);
        return strTo;
    }
};