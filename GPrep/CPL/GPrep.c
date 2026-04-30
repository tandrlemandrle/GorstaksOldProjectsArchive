/*
 * GPrep.cpl - Control Panel Applet
 * Launches GPrepUI.hta when double-clicked in Control Panel.
 * Provides backwards compatibility with Windows 7 and earlier.
 *
 * Build: cl /LD GPrep.c shell32.lib /Fe:GPrep.cpl
 * Or: gcc -shared -o GPrep.cpl GPrep.c -lshell32 -s
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <cpl.h>
#include <string.h>

static BOOL LaunchHTA(void);

static HMODULE g_hModule = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH)
        g_hModule = hinstDLL;
    return TRUE;
}

/* CPlApplet entry point - exported */
__declspec(dllexport) LONG APIENTRY CPlApplet(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2)
{
    switch (uMsg) {
        case CPL_INIT:
            return 1;

        case CPL_GETCOUNT:
            return 1;

        case CPL_INQUIRE: {
            CPLINFO *pInfo = (CPLINFO *)lParam2;
            pInfo->idIcon = 101;  /* Use default icon */
            pInfo->idName = 1;
            pInfo->idInfo = 2;
            pInfo->lData = 0;
            return 0;
        }

        case CPL_NEWINQUIRE: {
            NEWCPLINFO *pInfo = (NEWCPLINFO *)lParam2;
            pInfo->dwSize = sizeof(NEWCPLINFO);
            pInfo->hIcon = LoadIcon(NULL, IDI_APPLICATION);
            lstrcpynA(pInfo->szName, "GPrep", sizeof(pInfo->szName));
            lstrcpynA(pInfo->szInfo, "System Software Installer - Modern & Legacy (Win7) support", sizeof(pInfo->szInfo));
            pInfo->lData = 0;
            return 0;
        }

        case CPL_DBLCLK:
        case CPL_STARTWPARMS:
            LaunchHTA();
            return 0;

        case CPL_STOP:
            return 0;

        case CPL_EXIT:
            return 0;

        default:
            return 0;
    }
}

static BOOL LaunchHTA(void)
{
    char cplPath[MAX_PATH];
    char htaPath[MAX_PATH];
    char resolved[MAX_PATH];
    char *lastSlash;
    HINSTANCE hInst = g_hModule;

    if (!GetModuleFileNameA(hInst, cplPath, MAX_PATH))
        return FALSE;

    lastSlash = strrchr(cplPath, '\\');
    if (lastSlash) {
        size_t baseLen = (size_t)(lastSlash - cplPath + 1);
        memcpy(htaPath, cplPath, baseLen);
        htaPath[baseLen] = '\0';
        lstrcatA(htaPath, "GPrepUI.hta");
    } else {
        lstrcpyA(htaPath, "GPrepUI.hta");
    }

    /* Try same folder as CPL first */
    if (GetFileAttributesA(htaPath) != INVALID_FILE_ATTRIBUTES)
        return (INT_PTR)ShellExecuteA(NULL, "open", htaPath, NULL, NULL, SW_SHOWNORMAL) > 32;

    /* Fallback: parent folder (e.g. CPL\GPrep.cpl vs GPrepUI.hta) */
    if (lastSlash) {
        *lastSlash = '\0';
        lastSlash = strrchr(cplPath, '\\');
        if (lastSlash) {
            lastSlash[1] = '\0';
            wsprintfA(htaPath, "%sGPrepUI.hta", cplPath);
            if (GetFullPathNameA(htaPath, MAX_PATH, resolved, NULL) != 0)
                lstrcpyA(htaPath, resolved);
            if (GetFileAttributesA(htaPath) != INVALID_FILE_ATTRIBUTES)
                return (INT_PTR)ShellExecuteA(NULL, "open", htaPath, NULL, NULL, SW_SHOWNORMAL) > 32;
        }
    }

    /* Last resort: current directory */
    lstrcpyA(htaPath, "GPrepUI.hta");
    return (INT_PTR)ShellExecuteA(NULL, "open", htaPath, NULL, NULL, SW_SHOWNORMAL) > 32;
}
