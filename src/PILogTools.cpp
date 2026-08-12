// PILogTools - Notepad++ plugin
// A Notepad++ native plugin that replicates pi_log_tools.py:
//   1. Find time ranges when an interface was in Primary state.
//   2. Separate log messages for separate interface instances.
// Runs on the currently open document and writes results into new documents.

#include <windows.h>
#include <string>
#include <vector>

#include "PluginInterface.h"
#include "menuCmdID.h"
#include "LogParser.h"
#include "resource.h"

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static HINSTANCE g_hInst = nullptr;
static NppData   nppData;

#ifndef NPPM_SETUNTITLEDNAME
#define NPPM_SETUNTITLEDNAME (NPPMSG + 115)
#endif

// ---------------------------------------------------------------------------
// Small string helpers
// ---------------------------------------------------------------------------

static std::wstring utf8ToWide(const std::string& s)
{
    if (s.empty())
        return L"";
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::string wideToUtf8(const wchar_t* w)
{
    if (!w || !*w)
        return "";
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        return "";
    std::string s((size_t)n - 1, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

static std::string rstripped(const std::string& s)
{
    size_t b = s.find_last_not_of(" \t\r\n");
    return b == std::string::npos ? "" : s.substr(0, b + 1);
}

// ---------------------------------------------------------------------------
// Dialog: prompt for point source + interface ID
// ---------------------------------------------------------------------------

struct InputDlgData {
    wchar_t pointSource[256];
    wchar_t interfaceId[64];
};

static INT_PTR CALLBACK InputDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static InputDlgData* s_data = nullptr;

    switch (msg) {
    case WM_INITDIALOG:
        s_data = reinterpret_cast<InputDlgData*>(lParam);
        ::SetDlgItemTextW(hDlg, IDC_POINT_SOURCE, L"OPC");
        ::SetDlgItemTextW(hDlg, IDC_INTERFACE_ID, L"1");
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
            ::GetDlgItemTextW(hDlg, IDC_POINT_SOURCE, s_data->pointSource, 256);
            ::GetDlgItemTextW(hDlg, IDC_INTERFACE_ID, s_data->interfaceId, 64);
            ::EndDialog(hDlg, IDOK);
            return TRUE;
        case IDCANCEL:
            ::EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        ::EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Document helpers
// ---------------------------------------------------------------------------

static HWND currentScintilla()
{
    int view = 0;
    ::SendMessage(nppData._nppHandle, NPPM_GETCURRENTSCINTILLA, 0, (LPARAM)&view);
    return (view == 1) ? nppData._scintillaSecondHandle : nppData._scintillaMainHandle;
}

static std::string getCurrentDocumentText()
{
    HWND sci = currentScintilla();
    LRESULT len = ::SendMessage(sci, SCI_GETTEXTLENGTH, 0, 0);
    std::string text((size_t)len + 1, '\0');
    ::SendMessage(sci, SCI_GETTEXT, (WPARAM)len + 1, (LPARAM)&text[0]);
    text.resize((size_t)len);
    return text;
}

static void createResultDocument(const std::string& tabName, const std::string& content)
{
    // New untitled document becomes the active one.
    ::SendMessage(nppData._nppHandle, NPPM_MENUCOMMAND, 0, IDM_FILE_NEW);

    UINT_PTR bufId = (UINT_PTR)::SendMessage(nppData._nppHandle, NPPM_GETCURRENTBUFFERID, 0, 0);
    std::wstring wname = utf8ToWide(tabName);
    ::SendMessage(nppData._nppHandle, NPPM_SETUNTITLEDNAME, bufId, (LPARAM)wname.c_str());

    HWND sci = currentScintilla();
    ::SendMessage(sci, SCI_SETTEXT, 0, (LPARAM)content.c_str());
    ::SendMessage(sci, SCI_GOTOPOS, 0, 0);
}

// ---------------------------------------------------------------------------
// Menu command implementations
// ---------------------------------------------------------------------------

static void __cdecl cmdFindPrimary()
{
    InputDlgData in = {};
    INT_PTR res = ::DialogBoxParam(g_hInst, MAKEINTRESOURCE(IDD_INPUT_DLG),
                                   nppData._nppHandle, InputDlgProc, (LPARAM)&in);
    if (res != IDOK)
        return;

    std::string ps = rstripped(wideToUtf8(in.pointSource));
    std::string id = rstripped(wideToUtf8(in.interfaceId));

    if (ps.empty() || id.empty()) {
        ::MessageBoxW(nppData._nppHandle,
                      L"Please enter both a point source and an interface ID.",
                      L"PI Log Tools", MB_OK | MB_ICONINFORMATION);
        return;
    }

    try {
        std::string text = getCurrentDocumentText();
        LogParser parser(ps, id);
        parser.findPrimaryPeriods(text);
        std::string out = parser.buildPrimaryResults();
        createResultDocument(ps + "_" + id + "_primary_periods", out);
    } catch (const std::exception& e) {
        std::string msg = "An error occurred while parsing the log.\n\n";
        msg += e.what();
        ::MessageBoxW(nppData._nppHandle, utf8ToWide(msg).c_str(),
                      L"PI Log Tools", MB_OK | MB_ICONERROR);
    }
}

static void __cdecl cmdSeparate()
{
    try {
        std::string text = getCurrentDocumentText();
        auto docs = LogParser::separateInterfaces(text);

        if (docs.empty()) {
            ::MessageBoxW(nppData._nppHandle,
                          L"No interface instances found in the current document.",
                          L"PI Log Tools", MB_OK | MB_ICONINFORMATION);
            return;
        }

        for (const auto& d : docs)
            createResultDocument(d.first, d.second);
    } catch (const std::exception& e) {
        std::string msg = "An error occurred while parsing the log.\n\n";
        msg += e.what();
        ::MessageBoxW(nppData._nppHandle, utf8ToWide(msg).c_str(),
                      L"PI Log Tools", MB_OK | MB_ICONERROR);
    }
}

static void __cdecl cmdJoinMessages()
{
    HWND sci = currentScintilla();
    std::string text = getCurrentDocumentText();
    std::string joined = joinMessagesOntoOneLine(text);

    if (joined == text) {
        ::MessageBoxW(nppData._nppHandle,
                      L"No multi-line messages found to join.",
                      L"PI Log Tools", MB_OK | MB_ICONINFORMATION);
        return;
    }

    ::SendMessage(sci, SCI_BEGINUNDOACTION, 0, 0);
    ::SendMessage(sci, SCI_SETTEXT, 0, (LPARAM)joined.c_str());
    ::SendMessage(sci, SCI_ENDUNDOACTION, 0, 0);
    ::SendMessage(sci, SCI_GOTOPOS, 0, 0);
}

// ---------------------------------------------------------------------------
// Notepad++ plugin interface
// ---------------------------------------------------------------------------

static FuncItem funcItems[] = {
    { L"Find primary time ranges...", cmdFindPrimary, 0, false, nullptr },
    { L"Separate log messages by interface instance", cmdSeparate, 0, false, nullptr },
    { L"Join messages onto one line", cmdJoinMessages, 0, false, nullptr },
};

static const int nbFuncItems = sizeof(funcItems) / sizeof(funcItems[0]);

extern "C" __declspec(dllexport) void setInfo(NppData nd) { nppData = nd; }
extern "C" __declspec(dllexport) const wchar_t* getName() { return L"PI Log Tools"; }
extern "C" __declspec(dllexport) FuncItem* getFuncsArray(int* nbF) { *nbF = nbFuncItems; return funcItems; }
extern "C" __declspec(dllexport) void beNotified(SCNotification*) { }
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        g_hInst = hInst;
    return TRUE;
}
