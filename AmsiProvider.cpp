#include "stdafx.h"
#include <Windows.h>
#include "yara.h"
#include <fstream>
#include <string>
#include "nlohmann/json.hpp"
#include <fstream>
#include <codecvt>
#include <locale>
#include <chrono>
#include <ctime>
#include <vector>
#include <iostream>
#include <sstream>
#include "YaraRule.h"
#include "cpp-base64-2.rc.08/base64.h"


using json = nlohmann::json;

using namespace Microsoft::WRL;

// Use the folloing trace logging provider: 0eb41778-68b3-4a08-8974-0788cbf094b4 
TRACELOGGING_DEFINE_PROVIDER(g_traceLoggingProvider, "CaseyAmsiProvider",
    (0x0eb41778, 0x68b3, 0x4a08, 0x89, 0x74, 0x07, 0x88, 0xcb, 0xf0, 0x94, 0xb4));

HRESULT SetKeyStringValue(_In_ HKEY key, _In_opt_ PCWSTR subkey, _In_opt_ PCWSTR valueName, _In_ PCWSTR stringValue)
{
    //LONG status = RegSetKeyValue(key, subkey, valueName, REG_SZ, stringValue, (wcslen(stringValue) + 1) * sizeof(wchar_t));
    LONG status = RegSetKeyValue(key, subkey, valueName, REG_SZ, stringValue, static_cast<DWORD>((wcslen(stringValue) + 1) * sizeof(wchar_t)));

    return HRESULT_FROM_WIN32(status);
}

HRESULT SetKeyDWORDValue(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwValue)
{
    HKEY hSubKey = nullptr;
    HRESULT hr = HRESULT_FROM_WIN32(RegCreateKeyEx(hKey, lpSubKey, 0, nullptr, 0, KEY_WRITE, nullptr, &hSubKey, nullptr));
    if (FAILED(hr)) return hr;

    hr = HRESULT_FROM_WIN32(RegSetValueEx(hSubKey, lpValueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwValue), sizeof(dwValue)));
    if (FAILED(hr)) return hr;

    RegCloseKey(hSubKey);
    return S_OK;
}

struct ScanUserData
{
    bool found_match = false;
    std::vector<std::string> matched_rules;
};



bool initializeYaraRulesIfNeeded()
{
    if (yaraData.compiler == nullptr && yaraData.rules == nullptr)
    {
        yaraData = validateYaraRules();
        if (yaraData.compiler == nullptr || yaraData.rules == nullptr)
        {
            // Failed to initialize Yara rules
            return false;
        }
    }
    return true;
}


struct BlockingStatus
{
    std::string Status;
    bool State = false;
};

BlockingStatus AMSIBlocking;

int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
    ScanUserData* scan_data = (ScanUserData*)user_data;
    //std::ofstream logFile("C:\\programdata\\caseyamsi\\yara.log", std::ios_base::app); // Open log file for appending
    //logFile << "Processing Callback " << std::endl;
    switch (message)
    {
    case CALLBACK_MSG_RULE_MATCHING:
    {
        //    logFile << "Processing Matched Rule CALLBACK_MSG_RULE_MATCHING" << std::endl;
        scan_data->found_match = true;

        YR_RULE* rule = (YR_RULE*)message_data;
        scan_data->matched_rules.push_back(rule->identifier);

        return CALLBACK_CONTINUE;
    }
    case CALLBACK_MSG_RULE_NOT_MATCHING:
    {
        //    logFile << "Processing CALLBACK_MSG_RULE_NOT_MATCHING Rule " << std::endl;
        return CALLBACK_CONTINUE;
    }
    case CALLBACK_MSG_SCAN_FINISHED:
    {
        //   logFile << "Processing CALLBACK_MSG_SCAN_FINISHED Rule " << std::endl;
        return CALLBACK_CONTINUE;
    }
    default:
    {
        //    logFile << "Processing CALLBACK_ERROR Rule " << std::endl;
        return CALLBACK_ERROR;
    }
    }
}


HMODULE g_currentModule;

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        g_currentModule = module;
        DisableThreadLibraryCalls(module);
        TraceLoggingRegister(g_traceLoggingProvider);
        TraceLoggingWrite(g_traceLoggingProvider, "Loaded");
        Module<InProc>::GetModule().Create();
        break;

    case DLL_PROCESS_DETACH:
        Module<InProc>::GetModule().Terminate();
        TraceLoggingWrite(g_traceLoggingProvider, "Unloaded");
        TraceLoggingUnregister(g_traceLoggingProvider);
        yr_rules_destroy(yaraData.rules);
        yr_compiler_destroy(yaraData.compiler);
        break;
    }

    return TRUE;
}


#pragma region COM server boilerplate
HRESULT WINAPI DllCanUnloadNow()
{
    return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv)
{
    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}
#pragma endregion

// Simple RAII class to ensure memory is freed.
template<typename T>
class HeapMemPtr
{
public:
    HeapMemPtr() { }
    HeapMemPtr(const HeapMemPtr& other) = delete;
    HeapMemPtr(HeapMemPtr&& other) : p(other.p) { other.p = nullptr; }
    HeapMemPtr& operator=(const HeapMemPtr& other) = delete;
    HeapMemPtr& operator=(HeapMemPtr&& other) {
        auto t = p; p = other.p; other.p = t;
    }

    ~HeapMemPtr()
    {
        if (p) HeapFree(GetProcessHeap(), 0, p);
    }

    HRESULT Alloc(size_t size)
    {
        p = reinterpret_cast<T*>(HeapAlloc(GetProcessHeap(), 0, size));
        return p ? S_OK : E_OUTOFMEMORY;
    }

    T* Get() { return p; }
    operator bool() { return p != nullptr; }

private:
    T* p = nullptr;
};

class
    DECLSPEC_UUID("00000A62-77F9-4F7B-A90C-2744820139B2")
    CaseyAmsiProvider : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IAntimalwareProvider, FtmBase>
{
public:
    IFACEMETHOD(Scan)(_In_ IAmsiStream * stream, _Out_ AMSI_RESULT * result) override;
    IFACEMETHOD_(void, CloseSession)(_In_ ULONGLONG session) override;
    IFACEMETHOD(DisplayName)(_Outptr_ LPWSTR * displayName) override;

private:
    // We assign each Scan request a unique number for logging purposes.
    LONG m_requestNumber = 0;
};

template<typename T>
T GetFixedSizeAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute)
{
    T result;

    ULONG actualSize;
    if (SUCCEEDED(stream->GetAttribute(attribute, sizeof(T), reinterpret_cast<PBYTE>(&result), &actualSize)) &&
        actualSize == sizeof(T))
    {
        return result;
    }
    return T();
}

HeapMemPtr<wchar_t> GetStringAttribute(_In_ IAmsiStream* stream, _In_ AMSI_ATTRIBUTE attribute)
{
    HeapMemPtr<wchar_t> result;

    ULONG allocSize;
    ULONG actualSize;
    if (stream->GetAttribute(attribute, 0, nullptr, &allocSize) == E_NOT_SUFFICIENT_BUFFER &&
        SUCCEEDED(result.Alloc(allocSize)) &&
        SUCCEEDED(stream->GetAttribute(attribute, allocSize, reinterpret_cast<PBYTE>(result.Get()), &actualSize)) &&
        actualSize <= allocSize)
    {
        return result;
    }
    return HeapMemPtr<wchar_t>();
}

BYTE CalculateBufferXor(_In_ LPCBYTE buffer, _In_ ULONGLONG size)
{
    BYTE value = 0;
    for (ULONGLONG i = 0; i < size; i++)
    {
        value ^= buffer[i];
    }
    return value;
}


bool CheckEnforcementEnabledNeeded()
{
    if (AMSIBlocking.Status == "")
    {
        wchar_t clsidString[40];
        if (StringFromGUID2(__uuidof(CaseyAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
        {
            return false;
        }
        
        wchar_t keyPath[200];
        HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
        if (FAILED(hr)) 
        {
            return false;
        }
        
        hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
        if (FAILED(hr))
        {
            return false;
        }

        DWORD keyData;
        DWORD keyDataSize = sizeof(DWORD);
        LONG regQueryResult = RegGetValue(HKEY_LOCAL_MACHINE, keyPath, L"Enforcement", RRF_RT_REG_DWORD, nullptr, &keyData, &keyDataSize);

        if (regQueryResult == ERROR_SUCCESS)
        {
            if (keyData == 1)
            {
                AMSIBlocking.Status = "Blocking";
                AMSIBlocking.State = true;
            }
            else
            {
                AMSIBlocking.Status = "Detection Only";
                AMSIBlocking.State = false;
            }
        }
        else {
            AMSIBlocking.Status = "Detection Only";
            AMSIBlocking.State = false;
        }
    }
    return true;
}
HRESULT CaseyAmsiProvider::Scan(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result)
{
    LONG requestNumber = InterlockedIncrement(&m_requestNumber);
    TraceLoggingWrite(g_traceLoggingProvider, "Scan Start", TraceLoggingValue(requestNumber));

    auto appName = GetStringAttribute(stream, AMSI_ATTRIBUTE_APP_NAME);
    auto contentName = GetStringAttribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
    auto contentSize = GetFixedSizeAttribute<ULONGLONG>(stream, AMSI_ATTRIBUTE_CONTENT_SIZE);
    auto session = GetFixedSizeAttribute<ULONGLONG>(stream, AMSI_ATTRIBUTE_SESSION);
    auto contentAddress = GetFixedSizeAttribute<PBYTE>(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS);

    std::string contentNameStr;
    std::string appNameStr;

    if (appName.Get())
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        appNameStr = converter.to_bytes(appName.Get());
    }
    else
    {
        appNameStr = "";
    }

    if (contentName.Get())
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        contentNameStr = converter.to_bytes(contentName.Get());
    }
    else
    {
        contentNameStr = "";
    }

    std::wstring logDirectoryPath = L"C:\\ProgramData\\CaseyAMSI";
    CreateDirectoryW(logDirectoryPath.c_str(), NULL);

    //Getting Current time and converting it to a string for json...
    time_t currentTime;
    time(&currentTime);
    tm localTime;
    localtime_s(&localTime, &currentTime);
    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTime);

    //convert the PBYTE into a string for JSON.....WCGW
    size_t contentLength = wcslen(reinterpret_cast<wchar_t*>(contentAddress));
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<wchar_t*>(contentAddress), static_cast<int>(contentLength), NULL, 0, NULL, NULL);
    char* utf8Buffer = new char[bufferSize + 1];
    WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<wchar_t*>(contentAddress), static_cast<int>(contentLength), utf8Buffer, bufferSize, NULL, NULL);
    utf8Buffer[bufferSize] = '\0';
    std::string contentString(utf8Buffer);
    delete[] utf8Buffer;

    if (appNameStr.find("DotNet") != std::string::npos) {
        contentNameStr = "Binary";
        contentString = base64_encode(contentAddress, contentSize);
    }

    //If we dont have cotentname then its part of the interactive prompt.
    if (contentNameStr.empty()) {
        contentNameStr = "Interactive";
    }
    // Check if the content string is "prompt" because this provides a lot of noise.
    if (contentString == "prompt") {
        *result = AMSI_RESULT_NOT_DETECTED;
        return S_OK;
    }
   
    if (!initializeYaraRulesIfNeeded())
    {
        std::ofstream logFile("C:\\programdata\\caseyamsi\\yara.log", std::ios_base::app);
        logFile << "Error: Unable to Initialize Yara Rules" << std::endl;
    }

    if (!CheckEnforcementEnabledNeeded())
    {
        std::ofstream logFile("C:\\programdata\\caseyamsi\\yara.log", std::ios_base::app);
        logFile << "Error: Something is wrong" << std::endl;
    }

    ScanUserData scan_data;
    YR_COMPILER* compiler = yaraData.compiler;
    YR_RULES* rules = yaraData.rules;

    YR_RULE* rule = &(rules->rules_table[0]);
    //logFile << "Verified Rule " << rule->identifier << " Exists." << std::endl;

    //logFile << "Content: " << reinterpret_cast<const uint8_t*>(contentString.c_str()) << std::endl;
    //logFile << "Content size: " << contentSize << std::endl;

    int yr_result = yr_rules_scan_mem(rules, contentAddress, contentSize, 0, yara_callback, &scan_data, 0);

    if (yr_result == 0) {
        if (!scan_data.found_match)
        {
            scan_data.matched_rules.push_back("None");
        }
    }
    else
    {
        std::ofstream logFile("C:\\programdata\\caseyamsi\\yara.log", std::ios_base::app);
        logFile << "Error: " << yr_result << std::endl;
    }

    TraceLoggingWrite(g_traceLoggingProvider, "Attributes",
        TraceLoggingValue(requestNumber),
        TraceLoggingWideString(appName.Get(), "App Name"),
        TraceLoggingWideString(contentName.Get(), "Content Name"),
        TraceLoggingUInt64(contentSize, "Content Size"),
        TraceLoggingUInt64(session, "Session"),
        TraceLoggingWideString((LPCWSTR)contentAddress, "Content Data"));

    
    std::string amsiAction;
    
    if (AMSIBlocking.State == true)
    {
        if (!scan_data.found_match)
        {
            *result = AMSI_RESULT_NOT_DETECTED;
            amsiAction = "Allow";
        }
        else
        {
            *result = AMSI_RESULT_DETECTED;
            amsiAction = "Blocked";
        }
    }
    else
    {
        if (!scan_data.found_match)
        {
            *result = AMSI_RESULT_NOT_DETECTED;
            amsiAction = "Allow";
        }
        else
        {
            *result = AMSI_RESULT_NOT_DETECTED;
            amsiAction = "Detected and Allowed";
        }
    }



    // create a JSON object
    json logData = {
        {"0_Timestamp", timeStr},
        {"1_Provider",appNameStr},
        {"2_Source", contentNameStr},
        {"5_Data", contentString},
        {"3_Matches",  scan_data.matched_rules},
        {"4_Action",  amsiAction}
    };
    std::string prettyLogData = logData.dump(4, ' ', true);
    // open the log file in append mode
    std::ofstream log("C:\\ProgramData\\CaseyAMSI\\amsi.log", std::ios_base::app | std::ios_base::out);

    // write the JSON object to the log file
    log << std::setw(4) << prettyLogData << std::endl;
    return S_OK;
}

void CaseyAmsiProvider::CloseSession(_In_ ULONGLONG session)
{
    TraceLoggingWrite(g_traceLoggingProvider, "Close session",
        TraceLoggingValue(session));
}

HRESULT CaseyAmsiProvider::DisplayName(_Outptr_ LPWSTR* displayName)
{
    *displayName = const_cast<LPWSTR>(L"Casey AMSI Provider");
    return S_OK;
}

CoCreatableClass(CaseyAmsiProvider);

#pragma region Install / uninstall

STDAPI DllRegisterServer()
{
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileName(g_currentModule, modulePath, ARRAYSIZE(modulePath)) >= ARRAYSIZE(modulePath))
    {
        return E_UNEXPECTED;
    }
    // Create a standard COM registration for our CLSID.
    // The class must be registered as "Both" threading model
    // and support multithreaded access.
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(CaseyAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        return E_UNEXPECTED;
    }

    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"CaseyAmsiProvider");
    if (FAILED(hr)) return hr;

    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, modulePath);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
    if (FAILED(hr)) return hr;

    DWORD keyData;
    DWORD keyDataSize = sizeof(DWORD);
    LONG regQueryResult = RegGetValue(HKEY_LOCAL_MACHINE, keyPath, L"Enforcement", RRF_RT_REG_DWORD, nullptr, &keyData, &keyDataSize);
    if (regQueryResult == ERROR_FILE_NOT_FOUND)
    {
        hr = SetKeyDWORDValue(HKEY_LOCAL_MACHINE, keyPath, L"Enforcement", 0);
        if (FAILED(hr)) return hr;
    }


    // Register this CLSID as an anti-malware provider.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;

    hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"CaseyAmsiProvider");
    if (FAILED(hr)) return hr;

    return S_OK;
}



STDAPI DllUnregisterServer()
{
    wchar_t clsidString[40];
    if (StringFromGUID2(__uuidof(CaseyAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
    {
        return E_UNEXPECTED;
    }

    // Unregister this CLSID as an anti-malware provider.
    wchar_t keyPath[200];
    HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    LONG status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    // Unregister this CLSID as a COM server.
    hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
    if (FAILED(hr)) return hr;
    status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
    if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

    return S_OK;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllInstall(BOOL bInstall, PCWSTR pszCmdLine)
{

    if (bInstall)
    {

        wchar_t clsidString[40];
        if (StringFromGUID2(__uuidof(CaseyAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
        {
            return E_UNEXPECTED;
        }

        wchar_t keyPath[200];
        HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
        if (FAILED(hr)) return hr;

        hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
        if (FAILED(hr)) return hr;

        if (pszCmdLine != nullptr && wcsstr(pszCmdLine, L"blocking") != nullptr)
        {
            hr = SetKeyDWORDValue(HKEY_LOCAL_MACHINE, keyPath, L"Enforcement", 1);
            if (FAILED(hr)) return hr;
        }
        else
        {
            hr = SetKeyDWORDValue(HKEY_LOCAL_MACHINE, keyPath, L"Enforcement", 0);
            if (FAILED(hr)) return hr;
        }
    }

    return S_OK;
}

#pragma endregion
