#include <Windows.h>

#include <string>

#include "md5.h"
#include "StdString.h"
#include "zlib/zlib.h"

struct SupportInfo
{
    char Code[300];
    char Email[300];
    char Name[300];
    char MachineID[300];
    uint32_t RunCount;
    time_t LastUpdated;
    time_t LastShown;
    bool Validated;
};

static std::string GenerateMachineID(void)
{
    wchar_t ComputerName[256];
    DWORD Length = sizeof(ComputerName) / sizeof(ComputerName[0]);
    GetComputerName(ComputerName, &Length);

    wchar_t SysPath[MAX_PATH] = { 0 }, VolumePath[MAX_PATH] = { 0 };
    GetSystemDirectory(SysPath, sizeof(SysPath) / sizeof(SysPath[0]));

    GetVolumePathName(SysPath, VolumePath, sizeof(VolumePath) / sizeof(VolumePath[0]));

    DWORD SerialNumber = 0;
    GetVolumeInformation(VolumePath, nullptr, NULL, &SerialNumber, nullptr, nullptr, nullptr, NULL);

    wchar_t MachineGuid[200] = { 0 };
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        DWORD Type, dwDataSize = sizeof(MachineGuid);
        RegQueryValueEx(hKey, L"MachineGuid", nullptr, &Type, (LPBYTE)MachineGuid, &dwDataSize);
        RegCloseKey(hKey);
    }

    stdstr_f Machine("%s.%ud.%s", stdstr().FromUTF16(ComputerName).c_str(), SerialNumber, stdstr().FromUTF16(MachineGuid).c_str());
    return std::string(MD5((const unsigned char*)Machine.c_str(), Machine.size()).hex_digest());
}

static SupportInfo LoadSupportInfo(void)
{
    SupportInfo m_SupportInfo;
    std::string MachineID = GenerateMachineID();
    std::vector<uint8_t> InData;

    HKEY hKeyResults = 0;
    long lResult = RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Project64", 0, KEY_READ, &hKeyResults);
    if (lResult == ERROR_SUCCESS)
    {
        DWORD DataSize = 0;
        if (RegQueryValueEx(hKeyResults, L"user", nullptr, nullptr, nullptr, &DataSize) == ERROR_SUCCESS)
        {
            InData.resize(DataSize);
            if (RegQueryValueEx(hKeyResults, L"user", nullptr, nullptr, InData.data(), &DataSize) != ERROR_SUCCESS)
            {
                InData.clear();
            }
        }
    }

    if (hKeyResults != nullptr)
    {
        RegCloseKey(hKeyResults);
        nullptr;
    }

    std::vector<uint8_t> OutData;
    if (InData.size() > 0)
    {
        for (size_t i = 0, n = InData.size(); i < n; i++)
        {
            InData[i] ^= 0xAA;
        }
        OutData.resize(sizeof(m_SupportInfo) + 100);
        uLongf DestLen = OutData.size();
        if (uncompress(OutData.data(), &DestLen, InData.data(), InData.size()) >= 0)
        {
            OutData.resize(DestLen);
        }
        else
        {
            OutData.clear();
        }
    }

    if (OutData.size() == sizeof(SupportInfo) + 32)
    {
        SupportInfo* Info = (SupportInfo*)OutData.data();
        const char* CurrentHash = (const char*)(OutData.data() + sizeof(SupportInfo));
        std::string hash = MD5((const unsigned char*)Info, sizeof(SupportInfo)).hex_digest();
        if (strcmp(hash.c_str(), CurrentHash) == 0 && strcmp(Info->MachineID, MachineID.c_str()) == 0)
        {
            memcpy(&m_SupportInfo, Info, sizeof(SupportInfo));
        }
    }
    strcpy(m_SupportInfo.MachineID, MachineID.c_str());

    return m_SupportInfo;
}

void SaveSupportInfo(const SupportInfo& m_SupportInfo)
{
    std::string hash = MD5((const unsigned char*)&m_SupportInfo, sizeof(m_SupportInfo)).hex_digest();

    std::vector<uint8_t> InData(sizeof(m_SupportInfo) + hash.length());
    memcpy(InData.data(), (const unsigned char*)&m_SupportInfo, sizeof(m_SupportInfo));
    memcpy(InData.data() + sizeof(m_SupportInfo), hash.data(), hash.length());
    std::vector<uint8_t> OutData(InData.size());

    z_stream defstream;
    defstream.zalloc = Z_NULL;
    defstream.zfree = Z_NULL;
    defstream.opaque = Z_NULL;
    defstream.avail_in = (uInt)InData.size();
    defstream.next_in = (Bytef*)InData.data();
    defstream.avail_out = (uInt)OutData.size();
    defstream.next_out = (Bytef*)OutData.data();

    deflateInit(&defstream, Z_BEST_COMPRESSION);
    deflate(&defstream, Z_FINISH);
    deflateEnd(&defstream);

    OutData.resize(defstream.total_out);

    for (size_t i = 0, n = OutData.size(); i < n; i++)
    {
        OutData[i] ^= 0xAA;
    }

    HKEY hKeyResults = 0;
    DWORD Disposition = 0;
    long lResult = RegCreateKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Project64", 0, (LPWSTR) L"", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hKeyResults, &Disposition);
    if (lResult == ERROR_SUCCESS)
    {
        RegSetValueEx(hKeyResults, L"user", 0, REG_BINARY, (BYTE*)OutData.data(), OutData.size());
        RegCloseKey(hKeyResults);
    }
}

int main()
{
    auto info = LoadSupportInfo();
    info.Validated = true;
    SaveSupportInfo(info);
    return 0;
}
