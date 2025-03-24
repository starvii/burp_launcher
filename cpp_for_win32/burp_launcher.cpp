/**
 * copyright by starvii
 * compile command:
 * cl
 */

#pragma warning(disable : 4996)

#include <windows.h>
#include <tchar.h>
#include <cstdio>
#include <string>
#include <vector>
#include <memory>

#define PASS \
    do       \
    {        \
    } while (false)

using namespace std;

static FILE *fp{};

namespace burp
{
    /*
    参考启动命令：
    %JAVA_HOME%\bin\javaw.exe -noverify -Dsun.java2d.uiScale=1 -Dsun.java2d.d3d=false -Dsun.java2d.noddraw=true --add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED --add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED -javaagent:"BurpSuiteLoader.jar" -jar burpsuite_pro_v2025.1.4.jar
    */

    constexpr auto CommandTemplate = LR"("%s\bin\javaw.exe" -noverify -Dsun.java2d.uiScale=1 -Dsun.java2d.d3d=false -Dsun.java2d.noddraw=true --add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED --add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED -javaagent:"%s" -jar "%s")";
    constexpr auto JavaAgent = L"BurpSuiteLoader.jar";

    inline static wstring Lower(const wstring &str)
    {
        wstring ret = str;
        for (auto i = 0; i < ret.length(); i++)
        {
            const auto ch = ret.at(i);
            if (L'A' <= ch && ch <= L'Z')
            {
                ret[i] = ch + L'a' - L'A';
            }
        }
        return ret;
    }

    /*inline static int32_t FromWString(const wstring &s, string &out, const UINT CodePage = CP_ACP)
    {
        int32_t retCode = ERROR_SUCCESS;
        const auto size = WideCharToMultiByte(CodePage, 0, s.data(), -1, nullptr, 0, nullptr, nullptr);
        const auto buffer = new (nothrow) CHAR[size];
        if (nullptr == buffer)
        {
            retCode = ERROR_NOT_ENOUGH_MEMORY;
            goto __ERROR__;
        }
        {
            const auto r0 = WideCharToMultiByte(CodePage, 0, s.data(), -1, buffer, size, nullptr, nullptr);
            if (0 == r0)
            {
                const auto e = GetLastError();
                retCode = static_cast<int32_t>(e);
                goto __ERROR__;
            }
            out = string(buffer);
        }

        goto __FREE__;
    __ERROR__:
        PASS;
    __FREE__:
        delete[] buffer;
        return retCode;
    }

    inline static string w2a(const wstring &s, const UINT CodePage = CP_ACP)
    {
        string ret{};
        FromWString(s, ret, CodePage);
        return ret;
    }*/

    inline static bool FileExists(const wstring &filePath)
    {
        const auto attributes = GetFileAttributesW(filePath.data());
        return (attributes != INVALID_FILE_ATTRIBUTES &&
                !(attributes & FILE_ATTRIBUTE_DIRECTORY));
    }

    inline static INT32 FindBurpJar(wstring &wszBurpJar)
    {
        INT32 retCode = ERROR_SUCCESS;
        WIN32_FIND_DATAW findFileData{};
        HANDLE hFind = INVALID_HANDLE_VALUE;
        vector<wstring> filenames{};
        wstring path = L".\\*"; // 当前目录
        DWORD index{};

        hFind = FindFirstFileW(path.data(), &findFileData);

        if (hFind == INVALID_HANDLE_VALUE)
        {
            const auto e = wstring(L"Open Directory [") + path + L"] failed!";
            MessageBoxW(nullptr, e.data(), L"ERROR", MB_OK | MB_ICONERROR);
            retCode = ERROR_OPEN_FAILED;
            goto __ERROR__;
        }

        do
        {
            if (nullptr != fp)
            {
                fwprintf_s(fp, L"FindBurpJar: [%s]\n", findFileData.cFileName);
                fflush(fp);
            }
            // 排除当前目录 "." 和上级目录 ".."
            if (wcsicmp(findFileData.cFileName, L".") == 0)
            {
                continue;
            }
            if (wcsicmp(findFileData.cFileName, L"..") == 0)
            {
                continue;
            }
            // 检查是否为文件
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                continue;
            }
            wstring filename = Lower(findFileData.cFileName);
            if (filename.length() <= wstring(L"burpsuite_pro_v.jar").length())
            {
                continue;
            }
            const auto lfn = filename.substr(0, wstring(L"burpsuite_pro_v").length());
            const auto rfn = filename.substr(filename.size() - 4);
            const auto mfn = filename.substr(lfn.length(), filename.length() - lfn.length() - rfn.length());
            if (nullptr != fp)
            {
                fwprintf_s(fp, L"FindBurpJar: [%lu][%s] is match [%s]...[%s]...[%s]\n", index++, filename.data(), lfn.data(), mfn.data(), rfn.data());
                fflush(fp);
            }
            if (lfn != L"burpsuite_pro_v")
            {
                continue;
            }
            if (rfn != L".jar")
            {
                continue;
            }
            bool isAllNumberOrDot = true;
            for (const auto ch : mfn)
            {
                if (!(ch == L'.' || (L'0' <= ch && ch <= L'9')))
                {
                    isAllNumberOrDot = false;
                    break;
                }
            }
            if (!isAllNumberOrDot)
            {
                continue;
            }
            // burpsuite_pro_v2025.1.4.jar
            filenames.push_back(filename);
        } while (FindNextFile(hFind, &findFileData) != 0);
        goto __FREE__;
    __ERROR__:
        PASS;
    __FREE__:
        if (hFind != INVALID_HANDLE_VALUE)
        {
            FindClose(hFind);
        }
        if (nullptr != fp)
        {
            fwprintf_s(fp, L"[#] filenames.size = %lu\n", filenames.size());
            fflush(fp);
        }
        if (!filenames.empty())
        {
            wszBurpJar = filenames.at(0);
            if (nullptr != fp)
            {
                for (auto i = 0; i < filenames.size(); i++)
                {
                    const auto &fn = filenames[i];
                    fwprintf_s(fp, L"[#] filenames[%ld] = %s\n", i, fn.data());
                    fflush(fp);
                }
            }
        }
        else
        {
            retCode = ERROR_NOT_FOUND;
        }
        return retCode;
    }
}

using namespace burp;

int APIENTRY _tWinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR lpCmdLine,
    int nCmdShow)
{
    int retCode = ERROR_SUCCESS;
    constexpr size_t MaxPath = MAX_PATH << 2u;
    wstring JavaHome{};
    wstring burpJar{};
    wstring cmd{};
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi{};

    if (wstring(lpCmdLine) == L"--debug")
    {
        const auto r00 = _wfopen_s(&fp, L"burp_launcher-debug.log", L"ab");
        if (r00 != 0 || fp == nullptr)
        {
            MessageBoxW(nullptr, L"Open [burp_launcher.log] failed!", L"ERROR", MB_OK | MB_ICONERROR);
            retCode = r00;
            goto __ERROR__;
        }
        fwprintf_s(fp, L"[*] burp_launcher debug mode start\n");
        fflush(fp);
    }
    // Get JavaHome env
    {
        const auto java_home = _wgetenv(L"JAVA_HOME");
        if (nullptr == java_home)
        {
            if (nullptr != fp)
            {
                fwprintf_s(fp, L"[x] JAVA_HOME = nullptr\n");
                fflush(fp);
            }
            MessageBoxW(nullptr, L"Please set [JAVA_HOME] Environment Variable!", L"ERROR", MB_OK | MB_ICONERROR);
            retCode = ERROR_NOT_FOUND;
            goto __ERROR__;
        }
        JavaHome = wstring(java_home);
        if (JavaHome.empty())
        {
            MessageBoxW(nullptr, L"Please set [JAVA_HOME] Environment Variable!", L"ERROR", MB_OK | MB_ICONERROR);
            retCode = ERROR_NOT_FOUND;
            goto __ERROR__;
        }
        if (nullptr != fp)
        {
            fwprintf_s(fp, L"[!] JAVA_HOME = %s\n", JavaHome.data());
            fflush(fp);
        }
    }
    // check JavaAgent
    {
        const auto r00 = FileExists(JavaAgent);
        if (!r00)
        {
            wstring buffer{};
            buffer.reserve(4096);
            wsprintfW(&buffer[0], L"[x] Find JavaAgent [%s] failed!\n", JavaAgent);
            if (nullptr != fp)
            {
                fwprintf_s(fp, buffer.data());
                fflush(fp);
            }
            MessageBoxW(nullptr, buffer.data(), L"ERROR", MB_OK | MB_ICONERROR);
            retCode = ERROR_NOT_FOUND;
            goto __ERROR__;
        }
    }
    // Find Burp Jar
    {
        const auto r00 = burp::FindBurpJar(burpJar);
        if (r00 != ERROR_SUCCESS)
        {
            wstring buffer{};
            buffer.reserve(4096);
            wsprintfW(&buffer[0], L"[x] Find Burp Jar file failed!\n");
            if (nullptr != fp)
            {
                fwprintf_s(fp, buffer.data());
                fflush(fp);
            }
            MessageBoxW(nullptr, buffer.data(), L"ERROR", MB_OK | MB_ICONERROR);
            retCode = r00;
            goto __ERROR__;
        }
        if (nullptr != fp)
        {
            fwprintf_s(fp, L"[!] [BurpJar] = %s\n", burpJar.data());
            fflush(fp);
        }
    }
    // join cmd
    {
        wstring javaHome = JavaHome;
        // MessageBoxW(nullptr, javaHome.data(), L"test", MB_OK);
        if (JavaHome[0] == L'"' && JavaHome.at(JavaHome.length() - 1) == L'"')
        {
            javaHome = JavaHome.substr(1, JavaHome.length() - 2);
        }
        // const auto javaw = javaHome + L"\\bin\\javaw.exe";

        cmd.reserve(4096);
        wsprintfW(&cmd[0], CommandTemplate, javaHome.data(), JavaAgent, burpJar.data());
        if (nullptr != fp)
        {
            fwprintf_s(fp, L"[!] cmd = [%s]\n", cmd.data());
            fflush(fp);
        }
    }
    // create process
    {
        const auto r00 = CreateProcessW(
            nullptr,
            &cmd[0],
            nullptr,
            nullptr,
            FALSE,
            DETACHED_PROCESS,
            nullptr,
            nullptr,
            &si,
            &pi
        );

        if (r00)
        {
            if (nullptr != fp)
            {
                fwprintf_s(fp, L"[!] CreateProcessW SUCCESS! cmd = [%s]\n", cmd.data());
                fflush(fp);
            }
        }
        else
        {
            wstring buffer{};
            buffer.reserve(4096);
            const auto e = GetLastError();
            wsprintfW(&buffer[0], L"[x] CreateProcessW Failed %lu\n", e);
            if (nullptr != fp)
            {
                fwprintf_s(fp, buffer.data());
                fflush(fp);
            }
            MessageBoxW(nullptr, buffer.data(), L"ERROR", MB_OK | MB_ICONERROR);
            retCode = static_cast<int>(e);
            goto __ERROR__;
        }
    }

    goto __FREE__;
__ERROR__:
    PASS;
__FREE__:
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (nullptr != fp)
    {
        fclose(fp);
    }
    return ERROR_SUCCESS;
}