/*
 * BamDamForensics - Forensics Tool (WinToolsSuite Serie 3 #23)
 * Parse Background Activity Moderator / Desktop Activity Moderator, timestamps précis exécutions
 *
 * Fonctionnalités :
 * - Registry : HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}
 * - Registry : HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}
 * - Parse valeurs : nom = chemin exécutable, data = FILETIME (8 bytes)
 * - Conversion FILETIME → timestamp lisible (précision microsecondes)
 * - Association SID → username via LookupAccountSid
 * - Timeline ultra-précise dernières exécutions
 * - Export CSV UTF-8 avec logging complet
 *
 * APIs : advapi32.lib, comctl32.lib
 * Auteur : WinToolsSuite
 * License : MIT
 */

#define _WIN32_WINNT 0x0601
#define UNICODE
#define _UNICODE
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <sddl.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <memory>
#include <map>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Constantes UI
constexpr int WINDOW_WIDTH = 1400;
constexpr int WINDOW_HEIGHT = 700;
constexpr int MARGIN = 10;
constexpr int BUTTON_WIDTH = 180;
constexpr int BUTTON_HEIGHT = 30;

// IDs des contrôles
constexpr int IDC_LISTVIEW = 1001;
constexpr int IDC_BTN_PARSE = 1002;
constexpr int IDC_BTN_SORT = 1003;
constexpr int IDC_BTN_FILTER = 1004;
constexpr int IDC_BTN_EXPORT = 1005;
constexpr int IDC_STATUS = 1006;

// Structure d'entrée BAM/DAM
struct BamDamEntry {
    std::wstring timestamp;
    std::wstring sid;
    std::wstring username;
    std::wstring executablePath;
    std::wstring source;  // "BAM" ou "DAM"
    std::wstring notes;
    ULONGLONG fileTimeRaw;
};

// RAII pour clé registry
class RegKey {
    HKEY h;
public:
    explicit RegKey(HKEY handle) : h(handle) {}
    ~RegKey() { if (h) RegCloseKey(h); }
    operator HKEY() const { return h; }
    bool valid() const { return h != nullptr; }
};

// Classe principale
class BamDamForensics {
private:
    HWND hwndMain, hwndList, hwndStatus;
    std::vector<BamDamEntry> entries;
    std::wofstream logFile;
    HANDLE hWorkerThread;
    volatile bool stopProcessing;

    void Log(const std::wstring& message) {
        if (logFile.is_open()) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            wchar_t timeStr[64];
            swprintf_s(timeStr, L"[%02d/%02d/%04d %02d:%02d:%02d] ",
                      st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
            logFile << timeStr << message << std::endl;
            logFile.flush();
        }
    }

    void UpdateStatus(const std::wstring& text) {
        SetWindowTextW(hwndStatus, text.c_str());
        Log(text);
    }

    std::wstring FileTimeToStringPrecise(ULONGLONG fileTime) {
        if (fileTime == 0) {
            return L"N/A";
        }

        FILETIME ft;
        ft.dwLowDateTime = static_cast<DWORD>(fileTime & 0xFFFFFFFF);
        ft.dwHighDateTime = static_cast<DWORD>(fileTime >> 32);

        SYSTEMTIME st;
        if (FileTimeToSystemTime(&ft, &st)) {
            wchar_t buf[128];
            swprintf_s(buf, L"%02d/%02d/%04d %02d:%02d:%02d.%03d",
                      st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            return buf;
        }
        return L"Invalide";
    }

    std::wstring SidToUsername(const std::wstring& sidString) {
        PSID pSid = nullptr;
        if (!ConvertStringSidToSidW(sidString.c_str(), &pSid)) {
            return L"<SID inconnu>";
        }

        wchar_t name[256] = {};
        wchar_t domain[256] = {};
        DWORD nameSize = 256;
        DWORD domainSize = 256;
        SID_NAME_USE sidType;

        if (LookupAccountSidW(nullptr, pSid, name, &nameSize, domain, &domainSize, &sidType)) {
            LocalFree(pSid);
            if (wcslen(domain) > 0) {
                return std::wstring(domain) + L"\\" + name;
            }
            return name;
        }

        LocalFree(pSid);
        return L"<Inconnu>";
    }

    bool ParseBamDamKey(const wchar_t* service, const wchar_t* sid) {
        wchar_t subkey[512];
        swprintf_s(subkey, L"SYSTEM\\CurrentControlSet\\Services\\%s\\State\\UserSettings\\%s", service, sid);

        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return false;
        }

        RegKey key(hKey);

        // Résolution SID → Username une seule fois
        std::wstring username = SidToUsername(sid);

        DWORD index = 0;
        wchar_t valueName[16384];
        DWORD valueNameSize;
        BYTE data[1024];
        DWORD dataSize;
        DWORD type;

        int count = 0;

        while (true) {
            valueNameSize = 16384;
            dataSize = sizeof(data);

            LONG result = RegEnumValueW(hKey, index, valueName, &valueNameSize, nullptr, &type, data, &dataSize);

            if (result == ERROR_NO_MORE_ITEMS) {
                break;
            }

            if (result != ERROR_SUCCESS) {
                index++;
                continue;
            }

            // Filtrer la valeur "Version" (présente mais non pertinente)
            if (wcscmp(valueName, L"Version") == 0) {
                index++;
                continue;
            }

            BamDamEntry entry;
            entry.sid = sid;
            entry.username = username;
            entry.executablePath = valueName;
            entry.source = service;

            // Parse FILETIME (8 bytes)
            if (dataSize >= 8 && type == REG_BINARY) {
                entry.fileTimeRaw = *reinterpret_cast<ULONGLONG*>(data);
                entry.timestamp = FileTimeToStringPrecise(entry.fileTimeRaw);
            } else {
                entry.fileTimeRaw = 0;
                entry.timestamp = L"Données invalides";
            }

            // Notes : ajouter des observations
            if (entry.executablePath.find(L"\\Temp\\") != std::wstring::npos ||
                entry.executablePath.find(L"\\Downloads\\") != std::wstring::npos) {
                entry.notes = L"Emplacement suspect";
            } else {
                entry.notes = L"";
            }

            entries.push_back(entry);
            count++;
            index++;
        }

        return count > 0;
    }

    bool ParseBamDam() {
        entries.clear();

        // Énumérer tous les SIDs dans BAM et DAM
        const wchar_t* services[] = { L"bam", L"dam" };

        for (int svcIdx = 0; svcIdx < 2; svcIdx++) {
            const wchar_t* service = services[svcIdx];

            wchar_t basePath[256];
            swprintf_s(basePath, L"SYSTEM\\CurrentControlSet\\Services\\%s\\State\\UserSettings", service);

            HKEY hKeyBase = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, basePath, 0, KEY_READ, &hKeyBase) != ERROR_SUCCESS) {
                // BAM ou DAM peut ne pas exister (DAM seulement sur Desktop Windows 10)
                continue;
            }

            RegKey keyBase(hKeyBase);

            // Énumérer les sous-clés (SIDs)
            DWORD index = 0;
            wchar_t sidName[256];
            DWORD sidNameSize;

            while (true) {
                sidNameSize = 256;
                LONG result = RegEnumKeyExW(hKeyBase, index, sidName, &sidNameSize, nullptr, nullptr, nullptr, nullptr);

                if (result == ERROR_NO_MORE_ITEMS) {
                    break;
                }

                if (result != ERROR_SUCCESS) {
                    index++;
                    continue;
                }

                // Parser ce SID
                ParseBamDamKey(service, sidName);

                index++;
            }
        }

        UpdateStatus(L"Parsing terminé : " + std::to_wstring(entries.size()) + L" entrées trouvées");
        return !entries.empty();
    }

    void PopulateListView() {
        ListView_DeleteAllItems(hwndList);

        for (size_t i = 0; i < entries.size(); i++) {
            LVITEMW lvi = {};
            lvi.mask = LVIF_TEXT;
            lvi.iItem = static_cast<int>(i);

            lvi.iSubItem = 0;
            lvi.pszText = const_cast<LPWSTR>(entries[i].timestamp.c_str());
            ListView_InsertItem(hwndList, &lvi);

            ListView_SetItemText(hwndList, i, 1, const_cast<LPWSTR>(entries[i].sid.c_str()));
            ListView_SetItemText(hwndList, i, 2, const_cast<LPWSTR>(entries[i].username.c_str()));
            ListView_SetItemText(hwndList, i, 3, const_cast<LPWSTR>(entries[i].executablePath.c_str()));
            ListView_SetItemText(hwndList, i, 4, const_cast<LPWSTR>(entries[i].source.c_str()));
            ListView_SetItemText(hwndList, i, 5, const_cast<LPWSTR>(entries[i].notes.c_str()));
        }
    }

    static DWORD WINAPI ParseThreadProc(LPVOID param) {
        auto* pThis = static_cast<BamDamForensics*>(param);

        pThis->UpdateStatus(L"Parsing BAM/DAM en cours...");

        if (pThis->ParseBamDam()) {
            PostMessage(pThis->hwndMain, WM_USER + 1, 0, 0);
        } else {
            pThis->UpdateStatus(L"Aucune donnée BAM/DAM trouvée");
        }

        return 0;
    }

    void OnParse() {
        stopProcessing = false;
        hWorkerThread = CreateThread(nullptr, 0, ParseThreadProc, this, 0, nullptr);

        if (hWorkerThread) {
            EnableWindow(GetDlgItem(hwndMain, IDC_BTN_PARSE), FALSE);
        }
    }

    void OnSort() {
        if (entries.empty()) {
            MessageBoxW(hwndMain, L"Aucune donnée à trier", L"Information", MB_ICONINFORMATION);
            return;
        }

        // Trier par timestamp (plus récent en premier)
        std::sort(entries.begin(), entries.end(), [](const BamDamEntry& a, const BamDamEntry& b) {
            return a.fileTimeRaw > b.fileTimeRaw;
        });

        PopulateListView();
        UpdateStatus(L"Trié par date (plus récent en premier)");
        Log(L"Tri chronologique effectué");
    }

    void OnFilter() {
        if (entries.empty()) {
            MessageBoxW(hwndMain, L"Parsez d'abord BAM/DAM", L"Information", MB_ICONINFORMATION);
            return;
        }

        // Filtrer par utilisateur (simple démo : compter par user)
        std::map<std::wstring, int> userCounts;

        for (const auto& entry : entries) {
            userCounts[entry.username]++;
        }

        std::wstringstream report;
        report << L"=== Statistiques par Utilisateur ===\n\n";

        for (const auto& pair : userCounts) {
            report << pair.first << L" : " << pair.second << L" exécutions\n";
        }

        MessageBoxW(hwndMain, report.str().c_str(), L"Filtrage par Utilisateur", MB_ICONINFORMATION);
        Log(L"Statistiques par utilisateur affichées");
    }

    void OnExport() {
        if (entries.empty()) {
            MessageBoxW(hwndMain, L"Aucune donnée à exporter", L"Information", MB_ICONINFORMATION);
            return;
        }

        OPENFILENAMEW ofn = {};
        wchar_t fileName[MAX_PATH] = L"bamdamforensics.csv";

        ofn.lStructSize = sizeof(OPENFILENAMEW);
        ofn.hwndOwner = hwndMain;
        ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrTitle = L"Exporter BAM/DAM";
        ofn.Flags = OFN_OVERWRITEPROMPT;
        ofn.lpstrDefExt = L"csv";

        if (GetSaveFileNameW(&ofn)) {
            std::wofstream csv(fileName, std::ios::binary);
            if (!csv.is_open()) {
                MessageBoxW(hwndMain, L"Impossible de créer le fichier CSV", L"Erreur", MB_ICONERROR);
                return;
            }

            // BOM UTF-8
            unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            csv.write(reinterpret_cast<wchar_t*>(bom), sizeof(bom) / sizeof(wchar_t));

            csv << L"Timestamp,SID,Username,CheminExec,Source,Notes\n";

            for (const auto& entry : entries) {
                csv << L"\"" << entry.timestamp << L"\",\""
                    << entry.sid << L"\",\""
                    << entry.username << L"\",\""
                    << entry.executablePath << L"\",\""
                    << entry.source << L"\",\""
                    << entry.notes << L"\"\n";
            }

            csv.close();
            UpdateStatus(L"Export réussi : " + std::wstring(fileName));
            Log(L"Export CSV : " + std::wstring(fileName));
            MessageBoxW(hwndMain, L"Export CSV réussi !", L"Succès", MB_ICONINFORMATION);
        }
    }

    void CreateControls(HWND hwnd) {
        // Boutons
        int btnY = MARGIN;
        CreateWindowW(L"BUTTON", L"Parser BAM/DAM", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     MARGIN, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd, (HMENU)IDC_BTN_PARSE, nullptr, nullptr);

        CreateWindowW(L"BUTTON", L"Trier par Date", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     MARGIN + BUTTON_WIDTH + 10, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd,
                     (HMENU)IDC_BTN_SORT, nullptr, nullptr);

        CreateWindowW(L"BUTTON", L"Filtrer par User", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     MARGIN + (BUTTON_WIDTH + 10) * 2, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd,
                     (HMENU)IDC_BTN_FILTER, nullptr, nullptr);

        CreateWindowW(L"BUTTON", L"Exporter CSV", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     MARGIN + (BUTTON_WIDTH + 10) * 3, btnY, BUTTON_WIDTH, BUTTON_HEIGHT, hwnd,
                     (HMENU)IDC_BTN_EXPORT, nullptr, nullptr);

        // ListView
        hwndList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                                  MARGIN, btnY + BUTTON_HEIGHT + 10,
                                  WINDOW_WIDTH - MARGIN * 2 - 20,
                                  WINDOW_HEIGHT - btnY - BUTTON_HEIGHT - 80,
                                  hwnd, (HMENU)IDC_LISTVIEW, nullptr, nullptr);

        ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        // Colonnes
        LVCOLUMNW lvc = {};
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;

        lvc.cx = 180; lvc.pszText = const_cast<LPWSTR>(L"Timestamp");
        ListView_InsertColumn(hwndList, 0, &lvc);

        lvc.cx = 150; lvc.pszText = const_cast<LPWSTR>(L"SID");
        ListView_InsertColumn(hwndList, 1, &lvc);

        lvc.cx = 150; lvc.pszText = const_cast<LPWSTR>(L"Username");
        ListView_InsertColumn(hwndList, 2, &lvc);

        lvc.cx = 500; lvc.pszText = const_cast<LPWSTR>(L"Chemin Exec");
        ListView_InsertColumn(hwndList, 3, &lvc);

        lvc.cx = 80; lvc.pszText = const_cast<LPWSTR>(L"Source");
        ListView_InsertColumn(hwndList, 4, &lvc);

        lvc.cx = 180; lvc.pszText = const_cast<LPWSTR>(L"Notes");
        ListView_InsertColumn(hwndList, 5, &lvc);

        // Status bar
        hwndStatus = CreateWindowExW(0, L"STATIC",
                                     L"Prêt - Cliquez sur 'Parser BAM/DAM' (nécessite admin)",
                                     WS_CHILD | WS_VISIBLE | SS_SUNKEN | SS_LEFT,
                                     0, WINDOW_HEIGHT - 50, WINDOW_WIDTH - 20, 25,
                                     hwnd, (HMENU)IDC_STATUS, nullptr, nullptr);
    }

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        BamDamForensics* pThis = nullptr;

        if (uMsg == WM_NCCREATE) {
            CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
            pThis = static_cast<BamDamForensics*>(pCreate->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
            pThis->hwndMain = hwnd;
        } else {
            pThis = reinterpret_cast<BamDamForensics*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }

        if (pThis) {
            switch (uMsg) {
                case WM_CREATE:
                    pThis->CreateControls(hwnd);
                    return 0;

                case WM_COMMAND:
                    switch (LOWORD(wParam)) {
                        case IDC_BTN_PARSE: pThis->OnParse(); break;
                        case IDC_BTN_SORT: pThis->OnSort(); break;
                        case IDC_BTN_FILTER: pThis->OnFilter(); break;
                        case IDC_BTN_EXPORT: pThis->OnExport(); break;
                    }
                    return 0;

                case WM_USER + 1: // Parsing terminé
                    pThis->PopulateListView();
                    EnableWindow(GetDlgItem(hwnd, IDC_BTN_PARSE), TRUE);
                    if (pThis->hWorkerThread) {
                        CloseHandle(pThis->hWorkerThread);
                        pThis->hWorkerThread = nullptr;
                    }
                    return 0;

                case WM_DESTROY:
                    pThis->stopProcessing = true;
                    if (pThis->hWorkerThread) {
                        WaitForSingleObject(pThis->hWorkerThread, 2000);
                        CloseHandle(pThis->hWorkerThread);
                    }
                    PostQuitMessage(0);
                    return 0;
            }
        }

        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }

public:
    BamDamForensics() : hwndMain(nullptr), hwndList(nullptr), hwndStatus(nullptr),
                        hWorkerThread(nullptr), stopProcessing(false) {
        wchar_t logPath[MAX_PATH];
        GetModuleFileNameW(nullptr, logPath, MAX_PATH);
        PathRemoveFileSpecW(logPath);
        PathAppendW(logPath, L"BamDamForensics.log");

        logFile.open(logPath, std::ios::app);
        logFile.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
        Log(L"=== BamDamForensics démarré ===");
    }

    ~BamDamForensics() {
        Log(L"=== BamDamForensics terminé ===");
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    int Run(HINSTANCE hInstance, int nCmdShow) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"BamDamForensicsClass";
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

        if (!RegisterClassExW(&wc)) {
            MessageBoxW(nullptr, L"Échec de l'enregistrement de la classe", L"Erreur", MB_ICONERROR);
            return 1;
        }

        hwndMain = CreateWindowExW(0, L"BamDamForensicsClass",
                                   L"BAM/DAM Forensics - WinToolsSuite",
                                   WS_OVERLAPPEDWINDOW,
                                   CW_USEDEFAULT, CW_USEDEFAULT, WINDOW_WIDTH, WINDOW_HEIGHT,
                                   nullptr, nullptr, hInstance, this);

        if (!hwndMain) {
            MessageBoxW(nullptr, L"Échec de la création de la fenêtre", L"Erreur", MB_ICONERROR);
            return 1;
        }

        ShowWindow(hwndMain, nCmdShow);
        UpdateWindow(hwndMain);

        MSG msg = {};
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        return static_cast<int>(msg.wParam);
    }
};

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    BamDamForensics app;
    return app.Run(hInstance, nCmdShow);
}
