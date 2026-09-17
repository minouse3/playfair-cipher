// ============================================================================
//  Playfair Breaker -- a self-contained Playfair cryptanalysis GUI for Windows.
//
//  Implements the classic simulated-annealing Playfair attack (the same move
//  set and schedule Colossus uses) over a 5x5 keyed grid, scored by an embedded
//  quadgram table. No external solver or data file is needed: the quadgram
//  table is linked into the executable (see tools/gen_ngram_bin.py + the
//  build script), so this is a single program.
//
//  Features
//    * Load a .txt ciphertext and break it with one click.
//    * Fixed merged letter J -> I for the 5x5 square.
//    * Configurable padding letter for doubled letters (default X).
//    * Shows ciphertext, recovered plaintext, the recovered grid and key.
//    * Reports elapsed time; save the plaintext to a .txt file.
//
//  The attack is a port of the Playfair solver from Colossus by Samuel Thomas
//  Blake (stblake): https://github.com/stblake/colossus
//
//  Console smoke test:  PlayfairTest.exe --test <cipher.txt> [merge] [target] [pad]
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <cctype>
#include <string>
#include <vector>
#include <algorithm>

// ---------------------------------------------------------------------------
//  Embedded quadgram table (16-byte header: double floor, double scale; then
//  26^4 little-endian uint16 quantized log10 probabilities).
// ---------------------------------------------------------------------------
extern "C" const unsigned char _binary_ngram_quad_bin_start[];
extern "C" const unsigned char _binary_ngram_quad_bin_end[];

static const unsigned char *g_ngdata = nullptr;
static const uint16_t *g_ng = nullptr;   // 26^4 quantized values
static int g_ng_count = 0;
static double g_ng_floor = 0.0;
static double g_ng_scale = 0.0;
static float g_lut[65536];               // quantized byte -> log10 probability

static const int SIDE = 5;
static const int CELLS = 25;
static const int ALPHA = 26;
static const int NG_TOTAL = ALPHA * ALPHA * ALPHA * ALPHA;   // 456976

static void init_ngram() {
    g_ngdata = _binary_ngram_quad_bin_start;
    size_t bytes = (size_t)(_binary_ngram_quad_bin_end - _binary_ngram_quad_bin_start);
    if (bytes >= 16) {
        memcpy(&g_ng_floor, g_ngdata, 8);
        memcpy(&g_ng_scale, g_ngdata + 8, 8);
        g_ng = (const uint16_t *)(g_ngdata + 16);
        g_ng_count = (int)((bytes - 16) / 2);
    }
    for (int i = 0; i < 65536; i++)
        g_lut[i] = (float)(g_ng_floor + (double)i * g_ng_scale);
}

// ---------------------------------------------------------------------------
//  Active alphabet: one letter is merged away so 25 letters fit the square.
// ---------------------------------------------------------------------------
struct Alphabet {
    int removeLetter;   // letter dropped from the square (0..25)
    int targetLetter;   // letter it merges into (0..25), != removeLetter
    int symOf[26];      // letter -> 0..24 symbol (or -1 if merged away)
    int letterOf[25];   // symbol -> letter

    Alphabet(int rm, int tg) : removeLetter(rm), targetLetter(tg) { build(); }

    void build() {
        int s = 0;
        for (int l = 0; l < 26; l++) {
            if (l == removeLetter) { symOf[l] = -1; continue; }
            symOf[l] = s;
            letterOf[s] = l;
            s++;
        }
    }
};

// ---------------------------------------------------------------------------
//  RNG (xorshift64* style)
// ---------------------------------------------------------------------------
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;

static inline uint32_t xrand() {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 32);
}
static inline double rnd() { return (double)(xrand() >> 8) * (1.0 / 16777216.0); }
static inline int rbelow(int n) { return (int)(xrand() % (uint32_t)n); }

// ---------------------------------------------------------------------------
//  Playfair core
// ---------------------------------------------------------------------------
static inline void build_inverse(const int grid[CELLS], int pos[CELLS]) {
    for (int p = 0; p < CELLS; p++) pos[grid[p]] = p;
}

// Decrypt the ciphertext (0..24 symbols) with grid and write the plaintext as
// 26-letter codes into buf, then return the mean quadgram log-probability.
static double score_grid(const int grid[CELLS], const int *ct, int n,
                         const Alphabet &A, int *buf) {
    int pos[CELLS];
    build_inverse(grid, pos);
    int i = 0;
    for (; i + 1 < n; i += 2) {
        int a = ct[i], b = ct[i + 1];
        int pa = pos[a], pb = pos[b];
        int ra = pa / SIDE, ca = pa % SIDE;
        int rb = pb / SIDE, cb = pb % SIDE;
        int oa, ob;
        if (ra == rb) {
            oa = grid[ra * SIDE + (ca + SIDE - 1) % SIDE];
            ob = grid[rb * SIDE + (cb + SIDE - 1) % SIDE];
        } else if (ca == cb) {
            oa = grid[((ra + SIDE - 1) % SIDE) * SIDE + ca];
            ob = grid[((rb + SIDE - 1) % SIDE) * SIDE + cb];
        } else {
            oa = grid[ra * SIDE + cb];
            ob = grid[rb * SIDE + ca];
        }
        buf[i] = A.letterOf[oa];
        buf[i + 1] = A.letterOf[ob];
    }
    if (i < n) buf[i] = A.letterOf[ct[i]];

    if (n < 4) return 0.0;
    double s = 0.0;
    for (int j = 0; j + 3 < n; j++) {
        int idx = ((buf[j] * ALPHA + buf[j + 1]) * ALPHA + buf[j + 2]) * ALPHA + buf[j + 3];
        s += g_lut[g_ng[idx]];
    }
    return s / (double)(n - 4);
}

static void perturb(int g[CELLS]) {
    double r = rnd();
    if (r < 0.80) {
        int a = rbelow(CELLS), b = rbelow(CELLS);
        std::swap(g[a], g[b]);
    } else if (r < 0.88) {
        int r1 = rbelow(SIDE), r2 = rbelow(SIDE);
        for (int c = 0; c < SIDE; c++) std::swap(g[r1 * SIDE + c], g[r2 * SIDE + c]);
    } else if (r < 0.96) {
        int c1 = rbelow(SIDE), c2 = rbelow(SIDE);
        for (int rr = 0; rr < SIDE; rr++) std::swap(g[rr * SIDE + c1], g[rr * SIDE + c2]);
    } else if (r < 0.98) {
        for (int i = 0, j = CELLS - 1; i < j; i++, j--) std::swap(g[i], g[j]);
    } else if (r < 0.99) {
        for (int r1 = 0, r2 = SIDE - 1; r1 < r2; r1++, r2--)
            for (int c = 0; c < SIDE; c++) std::swap(g[r1 * SIDE + c], g[r2 * SIDE + c]);
    } else {
        for (int c1 = 0, c2 = SIDE - 1; c1 < c2; c1++, c2--)
            for (int rr = 0; rr < SIDE; rr++) std::swap(g[rr * SIDE + c1], g[rr * SIDE + c2]);
    }
}

struct SolveParams {
    int restarts = 6;
    int climbs = 400000;
    double init_temp = 0.08;
    double min_temp = 0.001;
    double backtrack = 0.30;
};

struct ProgressState {
    volatile LONG restart = 0;
    volatile LONG iteration = 0;
    volatile LONG running = 0;
};

struct SolveResult {
    int grid[CELLS];
    std::vector<int> plainCodes;
    double score = 0.0;
    double seconds = 0.0;
    int restarts_done = 0;
};

static SolveResult solve_playfair(const std::vector<int> &ct, const Alphabet &A,
                                  const SolveParams &P, ProgressState *prog,
                                  volatile bool *cancel) {
    SolveResult res;
    int n = (int)ct.size();
    if (n < 4) return res;

    std::vector<int> buf(n);
    int best[CELLS];
    double bestScore = -1e300;
    bool haveBest = false;

    double cooling = 1.0;
    if (P.climbs > 1)
        cooling = pow(P.min_temp / P.init_temp, 1.0 / (double)(P.climbs - 1));

    int cur[CELLS];

    for (int rs = 0; rs < P.restarts; rs++) {
        if (cancel && *cancel) break;
        if (prog) InterlockedExchange(&prog->restart, rs);

        if (haveBest && rnd() < P.backtrack) {
            memcpy(cur, best, sizeof(cur));
        } else {
            for (int i = 0; i < CELLS; i++) cur[i] = i;
            for (int i = CELLS - 1; i > 0; i--) {
                int j = rbelow(i + 1);
                std::swap(cur[i], cur[j]);
            }
        }
        double curScore = score_grid(cur, ct.data(), n, A, buf.data());

        double temp = P.init_temp;
        for (int it = 0; it < P.climbs; it++) {
            if ((it & 1023) == 0) {
                if (prog) InterlockedExchange(&prog->iteration, it);
                if (cancel && *cancel) break;
            }
            int loc[CELLS];
            memcpy(loc, cur, sizeof(loc));
            perturb(loc);
            double locScore = score_grid(loc, ct.data(), n, A, buf.data());

            bool accept;
            if (locScore > curScore) accept = true;
            else accept = (rnd() < exp((locScore - curScore) / temp));

            if (accept) {
                memcpy(cur, loc, sizeof(cur));
                curScore = locScore;
            }
            temp *= cooling;

            if (!haveBest || curScore > bestScore) {
                bestScore = curScore;
                memcpy(best, cur, sizeof(best));
                haveBest = true;
            }
        }
        res.restarts_done = rs + 1;
    }

    if (haveBest) {
        memcpy(res.grid, best, sizeof(best));
        res.plainCodes.resize(n);
        // final decrypt for the returned plaintext
        int pos[CELLS];
        build_inverse(best, pos);
        int i = 0;
        for (; i + 1 < n; i += 2) {
            int a = ct[i], b = ct[i + 1];
            int pa = pos[a], pb = pos[b];
            int ra = pa / SIDE, ca = pa % SIDE;
            int rb = pb / SIDE, cb = pb % SIDE;
            int oa, ob;
            if (ra == rb) {
                oa = best[ra * SIDE + (ca + SIDE - 1) % SIDE];
                ob = best[rb * SIDE + (cb + SIDE - 1) % SIDE];
            } else if (ca == cb) {
                oa = best[((ra + SIDE - 1) % SIDE) * SIDE + ca];
                ob = best[((rb + SIDE - 1) % SIDE) * SIDE + cb];
            } else {
                oa = best[ra * SIDE + cb];
                ob = best[rb * SIDE + ca];
            }
            res.plainCodes[i] = A.letterOf[oa];
            res.plainCodes[i + 1] = A.letterOf[ob];
        }
        if (i < n) res.plainCodes[i] = A.letterOf[ct[i]];
        res.score = bestScore;
    }
    return res;
}

// ---------------------------------------------------------------------------
//  Text helpers
// ---------------------------------------------------------------------------
static std::vector<int> parse_cipher(const std::string &raw, const Alphabet &A) {
    std::vector<int> v;
    v.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); i++) {
        unsigned char c = (unsigned char)toupper((unsigned char)raw[i]);
        if (c < 'A' || c > 'Z') continue;
        int l = c - 'A';
        if (l == A.removeLetter) l = A.targetLetter;
        v.push_back(A.symOf[l]);
    }
    return v;
}

// Turn decrypted 26-letter codes into a display string. With `stripPad`, remove
// padding letters inserted between doubled letters (A P A) and a trailing pad.
static std::string codes_to_display(const std::vector<int> &codes, int padLetter, bool stripPad) {
    std::string out;
    out.reserve(codes.size());
    int n = (int)codes.size();
    for (int i = 0; i < n; i++) {
        int c = codes[i];
        if (stripPad && c == padLetter) {
            if (i == n - 1) continue;                       // trailing padding
            if (!out.empty() && codes[i + 1] == out.back() - 'A') continue;  // between doubles
        }
        out.push_back((char)('A' + c));
    }
    return out;
}

static std::string wrap60(const std::string &s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        out.push_back(s[i]);
        if ((i + 1) % 60 == 0 && i + 1 < s.size()) out.push_back('\n');
    }
    return out;
}

// ---------------------------------------------------------------------------
//  Fixed merge letter: J -> I (the classic Playfair convention).
// ---------------------------------------------------------------------------
static const int MERGE_REMOVE = 9;   // J
static const int MERGE_TARGET = 8;   // I

// ===========================================================================
//  Windows GUI
// ===========================================================================
#define IDC_EDIT_CIPHER   1001
#define IDC_EDIT_PLAIN    1002
#define IDC_BTN_OPEN      1003
#define IDC_BTN_BREAK     1004
#define IDC_BTN_SAVE      1005
#define IDC_BTN_CLEAR     1006
#define IDC_EDIT_KEY      1007
#define IDC_COMBO_PAD     1008
#define IDC_GRID          1009
#define IDC_STATUS        1010
#define IDC_LBL_SCORE     1011
#define IDC_LBL_TIME      1012
#define IDC_CHK_STRIP     1013
#define IDC_PROGRESS      1014
#define IDC_LBL_PAD       1015
#define IDC_LBL_KEYCAP    1018
#define IDC_BTN_COPY      1019

#define WM_APP_SOLVED (WM_APP + 1)
#define WM_APP_PROGRESS (WM_APP + 2)

// ---------------------------------------------------------------------------
//  Palette
// ---------------------------------------------------------------------------
#define C_BG        RGB(238, 242, 248)
#define C_CARD      RGB(255, 255, 255)
#define C_BORDER    RGB(219, 227, 238)
#define C_TEXT      RGB(30, 41, 59)
#define C_SUBTEXT   RGB(100, 116, 139)
#define C_ACCENT    RGB(37, 99, 235)
#define C_ACCENT_H  RGB(59, 130, 246)
#define C_ACCENT_P  RGB(29, 78, 216)
#define C_SEC_BD    RGB(203, 213, 225)
#define C_SEC_H     RGB(241, 245, 249)
#define C_DIS_BG    RGB(229, 234, 242)
#define C_DIS_TX    RGB(148, 163, 184)

static HWND g_hwnd = nullptr;
static HWND g_hEditCipher = nullptr;
static HWND g_hEditPlain = nullptr;
static HWND g_hEditKey = nullptr;
static HWND g_hBtnOpen = nullptr;
static HWND g_hBtnBreak = nullptr;
static HWND g_hBtnSave = nullptr;
static HWND g_hBtnClear = nullptr;
static HWND g_hBtnCopy = nullptr;
static HWND g_hComboPad = nullptr;
static HWND g_hGrid = nullptr;
static HWND g_hStatus = nullptr;
static HWND g_hLblScore = nullptr;
static HWND g_hLblTime = nullptr;
static HWND g_hChkStrip = nullptr;
static HWND g_hProgress = nullptr;
static HWND g_hLblPad = nullptr;
static HWND g_hLblKeyCap = nullptr;

static HWND g_buttons[5];
static int  g_nButtons = 0;
static HWND g_hotButton = nullptr;

static RECT g_rcCardGrid = {0, 0, 0, 0};
static RECT g_rcCardCipher = {0, 0, 0, 0};
static RECT g_rcCardPlain = {0, 0, 0, 0};

static HFONT g_fontTitle = nullptr;
static HFONT g_fontSub = nullptr;
static HFONT g_fontCard = nullptr;
static HFONT g_fontUI = nullptr;
static HFONT g_fontBold = nullptr;
static HFONT g_fontMono = nullptr;
static HFONT g_fontKey = nullptr;
static HBRUSH g_bgBrush = nullptr;
static HBRUSH g_cardBrush = nullptr;

static int g_gridDisplay[CELLS];
static bool g_hasGrid = false;
static std::string g_displayPlain;   // cleaned plaintext (for save)
static std::string g_rawPlain;
static volatile LONG g_solving = 0;
static volatile bool g_cancel = false;
static ProgressState g_progress;
static SolveResult g_result;
static HANDLE g_thread = nullptr;
static int g_lastPad = 23;
static std::string g_cipherRaw;
static std::wstring g_cipherPath;
static std::wstring g_savePath;

static void set_status(const wchar_t *msg) {
    SetWindowTextW(g_hStatus, msg);
}

static std::string read_file_utf8(const std::wstring &path) {
    FILE *f = _wfopen(path.c_str(), L"rb");
    if (!f) return std::string();
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::string data;
    if (sz > 0) {
        data.resize((size_t)sz);
        size_t rd = fread(&data[0], 1, (size_t)sz, f);
        data.resize(rd);
    }
    fclose(f);
    return data;
}

static bool write_file_utf8(const std::wstring &path, const std::string &data) {
    FILE *f = _wfopen(path.c_str(), L"wb");
    if (!f) return false;
    fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return true;
}

static void set_edit_text(HWND edit, const std::string &text) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0);
    std::wstring w(wlen, L'\0');
    if (wlen > 0)
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &w[0], wlen);
    SetWindowTextW(edit, w.c_str());
}

static std::string get_edit_text(HWND edit) {
    int len = GetWindowTextLengthW(edit);
    std::wstring w(len, L'\0');
    GetWindowTextW(edit, &w[0], len + 1);
    if (len == 0) return std::string();
    int blen = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), len, nullptr, 0, nullptr, nullptr);
    std::string s(blen, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), len, &s[0], blen, nullptr, nullptr);
    return s;
}

// --- Worker thread ---------------------------------------------------------
static DWORD WINAPI solver_thread(LPVOID) {
    int padIdx = (int)SendMessageW(g_hComboPad, CB_GETCURSEL, 0, 0);
    if (padIdx < 0 || padIdx > 25) padIdx = 23;
    g_lastPad = padIdx;

    Alphabet A(MERGE_REMOVE, MERGE_TARGET);
    std::vector<int> ct = parse_cipher(g_cipherRaw, A);

    if (ct.size() < 4) {
        g_result = SolveResult();
        PostMessageW(g_hwnd, WM_APP_SOLVED, 0, 0);
        return 0;
    }

    // Use the ciphertext itself to seed the RNG for variety across runs.
    uint64_t seed = 0x9E3779B97F4A7C15ULL ^ (uint64_t)GetTickCount64();
    seed ^= (uint64_t)ct.size() * 0x100000001B3ULL;
    g_rng = seed ? seed : 1;

    SolveParams P;   // Colossus Playfair defaults
    DWORD t0 = GetTickCount();
    g_result = solve_playfair(ct, A, P, &g_progress, &g_cancel);
    g_result.seconds = (GetTickCount() - t0) / 1000.0;
    PostMessageW(g_hwnd, WM_APP_SOLVED, 0, 0);
    return 0;
}

static void start_break() {
    if (InterlockedCompareExchange(&g_solving, 1, 0) != 0)
        return;   // already running
    g_cipherRaw = get_edit_text(g_hEditCipher);
    if (g_cipherRaw.empty()) {
        InterlockedExchange(&g_solving, 0);
        MessageBoxW(g_hwnd, L"Please load a ciphertext first.", L"No ciphertext",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    g_cancel = false;
    g_progress.restart = 0;
    g_progress.iteration = 0;
    g_hasGrid = false;
    set_edit_text(g_hEditPlain, "");
    set_status(L"Breaking cipher...");
    EnableWindow(g_hBtnBreak, FALSE);
    SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
    ShowWindow(g_hProgress, SW_SHOW);

    DWORD tid;
    g_thread = CreateThread(nullptr, 0, solver_thread, nullptr, 0, &tid);
    if (!g_thread) {
        InterlockedExchange(&g_solving, 0);
        EnableWindow(g_hBtnBreak, TRUE);
    }
}

static void on_solved() {
    InterlockedExchange(&g_solving, 0);
    EnableWindow(g_hBtnBreak, TRUE);
    ShowWindow(g_hProgress, SW_HIDE);

    if (g_result.plainCodes.empty()) {
        set_status(L"Could not recover plaintext (ciphertext too short).");
        return;
    }

    // Rebuild the alphabet that was used so the grid can be shown as letters.
    Alphabet A(MERGE_REMOVE, MERGE_TARGET);

    memcpy(g_gridDisplay, g_result.grid, sizeof(g_gridDisplay));
    g_hasGrid = true;
    InvalidateRect(g_hGrid, nullptr, TRUE);

    // Recovered key: the 25 grid letters on a single line (copyable).
    {
        wchar_t key[128];
        int kp = 0;
        for (int i = 0; i < CELLS; i++) {
            if (i > 0 && i % SIDE == 0) key[kp++] = L' ';
            key[kp++] = (wchar_t)(L'A' + A.letterOf[g_gridDisplay[i]]);
        }
        key[kp] = 0;
        SetWindowTextW(g_hEditKey, key);
    }

    // Recovered plaintext is shown exactly as decrypted (padding included).
    // The padding-removal checkbox then strips the selected padding letter.
    SendMessageW(g_hChkStrip, BM_SETCHECK, BST_UNCHECKED, 0);
    g_rawPlain = codes_to_display(g_result.plainCodes, g_lastPad, false);
    g_displayPlain = g_rawPlain;
    set_edit_text(g_hEditPlain, wrap60(g_displayPlain));

    wchar_t buf[256];
    swprintf(buf, 256, L"Score: %.2f", g_result.score);
    SetWindowTextW(g_hLblScore, buf);
    swprintf(buf, 256, L"Time: %.2f s", g_result.seconds);
    SetWindowTextW(g_hLblTime, buf);
    swprintf(buf, 256, L"Solved in %.2f s  (score %.2f)", g_result.seconds, g_result.score);
    set_status(buf);
}

// --- Grid rendering (SS_OWNERDRAW static) ----------------------------------
static void draw_grid(DRAWITEMSTRUCT *dis) {
    HDC dc = dis->hDC;
    RECT rc = dis->rcItem;
    FillRect(dc, &rc, g_cardBrush);

    const int margin = 4;
    int availW = (rc.right - rc.left) - 2 * margin;
    int availH = (rc.bottom - rc.top) - 2 * margin;
    int cell = std::min(availW, availH) / SIDE;
    if (cell < 4) cell = 4;
    int gridW = cell * SIDE;
    int x0 = rc.left + margin + (availW - gridW) / 2;
    int y0 = rc.top + margin + (availH - gridW) / 2;

    HPEN pen = CreatePen(PS_SOLID, 1, C_BORDER);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, g_fontBold);
    SetTextColor(dc, C_TEXT);

    Alphabet A(MERGE_REMOVE, MERGE_TARGET);

    HBRUSH cellBr = CreateSolidBrush(RGB(248, 250, 252));
    for (int r = 0; r < SIDE; r++) {
        for (int c = 0; c < SIDE; c++) {
            RECT cr = { x0 + c * cell, y0 + r * cell, x0 + (c + 1) * cell, y0 + (r + 1) * cell };
            FillRect(dc, &cr, cellBr);
            Rectangle(dc, cr.left, cr.top, cr.right, cr.bottom);

            wchar_t ch[2] = { L'?', 0 };
            if (g_hasGrid) {
                int sym = g_gridDisplay[r * SIDE + c];
                ch[0] = (wchar_t)(L'A' + A.letterOf[sym]);
            }
            DrawTextW(dc, ch, 1, &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
    }
    DeleteObject(cellBr);
    SelectObject(dc, oldPen);
    DeleteObject(pen);
}

// --- Drawing helpers -------------------------------------------------------
static void round_fill(HDC dc, RECT r, int rad, COLORREF fill, COLORREF border) {
    HRGN rgn = CreateRoundRectRgn(r.left, r.top, r.right + 1, r.bottom + 1, rad, rad);
    HBRUSH b = CreateSolidBrush(fill);
    FillRgn(dc, rgn, b);
    DeleteObject(b);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ op = SelectObject(dc, pen);
    HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, r.left, r.top, r.right - 1, r.bottom - 1, rad, rad);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(pen);
    DeleteObject(rgn);
}

static void draw_card(HDC dc, RECT rc, const wchar_t *title) {
    round_fill(dc, rc, 14, C_CARD, C_BORDER);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, C_TEXT);
    HFONT of = (HFONT)SelectObject(dc, g_fontCard);
    RECT tr = { rc.left + 20, rc.top + 13, rc.right - 16, rc.top + 38 };
    DrawTextW(dc, title, -1, &tr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SelectObject(dc, of);
}

static void paint_window(HDC dc, int W, int H) {
    RECT full = { 0, 0, W, H };
    FillRect(dc, &full, g_bgBrush);

    // Header: vertical gradient (deep navy -> blue).
    const int HH = 62;
    for (int y = 0; y < HH; y++) {
        int t = (HH > 1) ? y * 255 / (HH - 1) : 0;
        int r = 15 + (37 - 15) * t / 255;
        int g = 23 + (99 - 23) * t / 255;
        int b = 42 + (235 - 42) * t / 255;
        RECT lr = { 0, y, W, y + 1 };
        HBRUSH br = CreateSolidBrush(RGB(r, g, b));
        FillRect(dc, &lr, br);
        DeleteObject(br);
    }
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fontTitle);
    SetTextColor(dc, RGB(255, 255, 255));
    RECT tr = { 24, 9, W - 24, 40 };
    DrawTextW(dc, L"Playfair Cipher Breaker", -1, &tr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SelectObject(dc, g_fontSub);
    SetTextColor(dc, RGB(191, 219, 254));
    RECT sr = { 26, 37, W - 24, 58 };
    DrawTextW(dc, L"Simulated-annealing cryptanalysis  \xB7  embedded quadgram scoring",
              -1, &sr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SelectObject(dc, of);

    draw_card(dc, g_rcCardGrid, L"Recovered 5x5 Grid");
    draw_card(dc, g_rcCardCipher, L"Ciphertext");
    draw_card(dc, g_rcCardPlain, L"Recovered Plaintext");
}

static void draw_button(DRAWITEMSTRUCT *dis) {
    HDC dc = dis->hDC;
    RECT rc = dis->rcItem;
    bool primary = (dis->CtlID == IDC_BTN_BREAK || dis->CtlID == IDC_BTN_COPY);
    bool disabled = (dis->itemState & ODS_DISABLED) != 0;
    bool pressed = (dis->itemState & ODS_SELECTED) != 0;
    bool hot = (dis->hwndItem == g_hotButton);

    COLORREF fill, border, text;
    if (disabled) {
        fill = C_DIS_BG; border = C_SEC_BD; text = C_DIS_TX;
    } else if (primary) {
        fill = pressed ? C_ACCENT_P : (hot ? C_ACCENT_H : C_ACCENT);
        border = fill;
        text = RGB(255, 255, 255);
    } else {
        fill = pressed ? RGB(226, 232, 240) : (hot ? C_SEC_H : RGB(255, 255, 255));
        border = C_SEC_BD;
        text = C_TEXT;
    }

    HBRUSH pbg = CreateSolidBrush(dis->CtlID == IDC_BTN_COPY ? C_CARD : C_BG);
    FillRect(dc, &rc, pbg);
    DeleteObject(pbg);

    RECT r = rc;
    InflateRect(&r, -1, -1);
    round_fill(dc, r, 8, fill, border);

    wchar_t txt[64];
    GetWindowTextW(dis->hwndItem, txt, 64);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, text);
    HFONT of = (HFONT)SelectObject(dc, g_fontBold);
    DrawTextW(dc, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, of);

    if (dis->itemState & ODS_FOCUS) {
        RECT f = r;
        InflateRect(&f, -4, -4);
        DrawFocusRect(dc, &f);
    }
}

static void update_hover() {
    if (g_nButtons == 0) return;
    POINT p;
    GetCursorPos(&p);
    ScreenToClient(g_hwnd, &p);
    HWND hot = nullptr;
    for (int i = 0; i < g_nButtons; i++) {
        RECT r;
        GetWindowRect(g_buttons[i], &r);
        MapWindowPoints(HWND_DESKTOP, g_hwnd, (POINT *)&r, 2);
        if (PtInRect(&r, p)) { hot = g_buttons[i]; break; }
    }
    if (hot != g_hotButton) {
        if (g_hotButton) InvalidateRect(g_hotButton, nullptr, TRUE);
        g_hotButton = hot;
        if (hot) InvalidateRect(hot, nullptr, TRUE);
    }
}

// --- Layout ----------------------------------------------------------------
static void layout(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int W = rc.right - rc.left;
    int H = rc.bottom - rc.top;

    const int pad = 14;
    const int headerH = 62;
    const int toolbarH = 52;
    const int statusH = 30;

    // Toolbar buttons (right aligned, below the header).
    int bw = 130, bh = 34, gap = 10;
    int bx = W - pad - (bw * 4 + gap * 3);
    if (bx < 300) bx = 300;
    int by = headerH + (toolbarH - bh) / 2;
    MoveWindow(g_hBtnOpen, bx, by, bw, bh, TRUE);
    MoveWindow(g_hBtnBreak, bx + (bw + gap), by, bw, bh, TRUE);
    MoveWindow(g_hBtnSave, bx + 2 * (bw + gap), by, bw, bh, TRUE);
    MoveWindow(g_hBtnClear, bx + 3 * (bw + gap), by, bw, bh, TRUE);

    int top = headerH + toolbarH;
    int bottom = H - statusH - 8;

    // Left card: recovered grid + copyable key.
    int cardW = 270;
    g_rcCardGrid = { pad, top, pad + cardW, bottom };
    int gx = pad + 22;
    int gs = cardW - 44;              // square grid
    int gy = top + 44;
    MoveWindow(g_hGrid, gx, gy, gs, gs, TRUE);
    int ky = gy + gs + 14;
    MoveWindow(g_hLblKeyCap, gx, ky, cardW - 44, 18, TRUE);
    MoveWindow(g_hEditKey, gx, ky + 22, cardW - 44, 28, TRUE);
    int btnY = ky + 22 + 28 + 10;
    MoveWindow(g_hBtnCopy, gx, btnY, 118, 30, TRUE);
    int statY = btnY + 30 + 18;
    MoveWindow(g_hLblScore, gx, statY, cardW - 44, 18, TRUE);
    MoveWindow(g_hLblTime, gx, statY + 22, cardW - 44, 18, TRUE);

    // Right column: ciphertext card, padding strip, plaintext card, padding-removal strip.
    int rx = pad + cardW + 16;
    int rw = W - rx - pad;
    if (rw < 320) rw = 320;
    int colH = bottom - top;
    int stripH = 48;
    int footH = 40;
    int avail = colH - stripH - footH;
    if (avail < 200) avail = 200;
    int cipherH = avail * 44 / 100;

    g_rcCardCipher = { rx, top, rx + rw, top + cipherH };
    MoveWindow(g_hEditCipher, rx + 20, top + 44, rw - 40, cipherH - 64, TRUE);

    int sy = top + cipherH + 6;
    MoveWindow(g_hLblPad, rx + 6, sy + 12, 120, 20, TRUE);
    MoveWindow(g_hComboPad, rx + 132, sy + 8, 66, 220, TRUE);

    int py = sy + stripH;
    int plainBottom = bottom - footH;
    g_rcCardPlain = { rx, py, rx + rw, plainBottom };
    MoveWindow(g_hEditPlain, rx + 20, py + 44, rw - 40, (plainBottom - py) - 64, TRUE);

    MoveWindow(g_hChkStrip, rx + 8, bottom - footH + 9, 300, 22, TRUE);

    MoveWindow(g_hProgress, 0, H - statusH, W, 4, TRUE);
    MoveWindow(g_hStatus, pad, H - statusH + 6, W - 2 * pad, statusH - 6, TRUE);

    InvalidateRect(hwnd, nullptr, TRUE);
}

static void setup_fonts() {
    g_fontTitle = CreateFontW(-26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_fontSub = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_fontCard = CreateFontW(-16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_fontUI = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_fontBold = CreateFontW(-15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_fontMono = CreateFontW(-16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    g_fontKey = CreateFontW(-14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
}

static void apply_font(HWND h, HFONT f) {
    SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE);
}

// ===========================================================================
//  Console smoke-test mode
// ===========================================================================
static int console_test(const char *path, int rm, int tg, int pad) {
    init_ngram();
    FILE *f = fopen(path, "rb");
    if (!f) { printf("cannot open %s\n", path); return 1; }
    std::string raw;
    char tmp[4096];
    size_t rd;
    while ((rd = fread(tmp, 1, sizeof(tmp), f)) > 0) raw.append(tmp, rd);
    fclose(f);

    Alphabet A(rm, tg);
    std::vector<int> ct = parse_cipher(raw, A);
    printf("ciphertext: %d letters\n", (int)ct.size());
    if (ct.size() < 4) { printf("too short\n"); return 1; }

    g_rng = 0x123456789ABCDEFULL;
    SolveParams P;
    ProgressState prog;
    volatile bool cancel = false;
    DWORD t0 = GetTickCount();
    SolveResult r = solve_playfair(ct, A, P, &prog, &cancel);
    double secs = (GetTickCount() - t0) / 1000.0;

    printf("score %.2f  time %.2f s\n", r.score, secs);
    printf("grid: ");
    for (int i = 0; i < CELLS; i++) putchar('A' + A.letterOf[r.grid[i]]);
    printf("\n");
    std::string disp = codes_to_display(r.plainCodes, pad, true);
    printf("%s\n", wrap60(disp).c_str());
    return 0;
}

// ===========================================================================
//  Window procedure
// ===========================================================================
static HWND mk(const wchar_t *cls, const wchar_t *text, DWORD style, DWORD exStyle,
               int id) {
    return CreateWindowExW(exStyle, cls, text, style | WS_CHILD | WS_VISIBLE,
                           0, 0, 10, 10, g_hwnd, (HMENU)(INT_PTR)id,
                           GetModuleHandleW(nullptr), nullptr);
}

static void create_controls(HWND hwnd) {
    g_hEditCipher = mk(L"EDIT", L"", WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL |
                       WS_VSCROLL | ES_WANTRETURN, WS_EX_CLIENTEDGE, IDC_EDIT_CIPHER);
    g_hEditPlain = mk(L"EDIT", L"", WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL |
                      WS_VSCROLL | ES_READONLY, WS_EX_CLIENTEDGE, IDC_EDIT_PLAIN);
    g_hEditKey = mk(L"EDIT", L"", WS_TABSTOP | ES_READONLY | ES_AUTOHSCROLL,
                    WS_EX_STATICEDGE, IDC_EDIT_KEY);

    g_hGrid = mk(L"STATIC", L"", SS_OWNERDRAW, 0, IDC_GRID);

    g_hBtnOpen  = mk(L"BUTTON", L"Open Ciphertext", WS_TABSTOP | BS_OWNERDRAW, 0, IDC_BTN_OPEN);
    g_hBtnBreak = mk(L"BUTTON", L"Break Cipher",    WS_TABSTOP | BS_OWNERDRAW, 0, IDC_BTN_BREAK);
    g_hBtnSave  = mk(L"BUTTON", L"Save Plaintext",  WS_TABSTOP | BS_OWNERDRAW, 0, IDC_BTN_SAVE);
    g_hBtnClear = mk(L"BUTTON", L"Clear",           WS_TABSTOP | BS_OWNERDRAW, 0, IDC_BTN_CLEAR);
    g_hBtnCopy  = mk(L"BUTTON", L"Copy Key",        WS_TABSTOP | BS_OWNERDRAW, 0, IDC_BTN_COPY);

    g_hComboPad = mk(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL,
                     0, IDC_COMBO_PAD);
    g_hChkStrip = mk(L"BUTTON", L"Remove padding letters",
                     BS_AUTOCHECKBOX | WS_TABSTOP, 0, IDC_CHK_STRIP);

    g_hLblPad = mk(L"STATIC", L"Padding letter:", SS_LEFT | SS_CENTERIMAGE, 0, IDC_LBL_PAD);
    g_hLblScore = mk(L"STATIC", L"Score: --", SS_LEFT, 0, IDC_LBL_SCORE);
    g_hLblTime = mk(L"STATIC", L"Time: --", SS_LEFT, 0, IDC_LBL_TIME);
    g_hLblKeyCap = mk(L"STATIC", L"Recovered Key", SS_LEFT, 0, IDC_LBL_KEYCAP);

    g_hStatus = mk(L"STATIC", L"Ready. Open a ciphertext file, then click Break Cipher.",
                   SS_LEFT | SS_CENTERIMAGE, 0, IDC_STATUS);
    g_hProgress = mk(PROGRESS_CLASSW, L"", PBS_SMOOTH, 0, IDC_PROGRESS);
    SendMessageW(g_hProgress, PBM_SETBARCOLOR, 0, (LPARAM)C_ACCENT);
    SendMessageW(g_hProgress, PBM_SETBKCOLOR, 0, (LPARAM)RGB(226, 232, 240));
    ShowWindow(g_hProgress, SW_HIDE);

    for (int l = 0; l < 26; l++) {
        wchar_t s[2] = { (wchar_t)(L'A' + l), 0 };
        SendMessageW(g_hComboPad, CB_ADDSTRING, 0, (LPARAM)s);
    }
    SendMessageW(g_hComboPad, CB_SETCURSEL, 23, 0);   // X
    SendMessageW(g_hChkStrip, BM_SETCHECK, BST_UNCHECKED, 0);

    g_buttons[0] = g_hBtnOpen;
    g_buttons[1] = g_hBtnBreak;
    g_buttons[2] = g_hBtnSave;
    g_buttons[3] = g_hBtnClear;
    g_buttons[4] = g_hBtnCopy;
    g_nButtons = 5;

    HWND ui[] = { g_hBtnOpen, g_hBtnBreak, g_hBtnSave, g_hBtnClear, g_hBtnCopy,
                  g_hComboPad, g_hChkStrip, g_hStatus, g_hLblPad };
    for (HWND h : ui) apply_font(h, g_fontUI);
    apply_font(g_hComboPad, g_fontBold);
    apply_font(g_hEditCipher, g_fontMono);
    apply_font(g_hEditPlain, g_fontMono);
    apply_font(g_hEditKey, g_fontKey);
    apply_font(g_hLblScore, g_fontBold);
    apply_font(g_hLblTime, g_fontBold);
    apply_font(g_hLblPad, g_fontBold);
    apply_font(g_hLblKeyCap, g_fontBold);
}

static void on_open_file() {
    wchar_t path[MAX_PATH] = L"";
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"Open Ciphertext";
    if (!GetOpenFileNameW(&ofn)) return;

    std::string data = read_file_utf8(path);
    if (data.empty()) {
        MessageBoxW(g_hwnd, L"Failed to read the file (or it is empty).", L"Error",
                    MB_OK | MB_ICONERROR);
        return;
    }
    g_cipherPath = path;
    g_cipherRaw = data;
    // Show the raw ciphertext trimmed for display.
    std::string show;
    for (size_t i = 0; i < data.size(); i++) {
        unsigned char c = (unsigned char)toupper((unsigned char)data[i]);
        if (c >= 'A' && c <= 'Z') show.push_back((char)c);
    }
    set_edit_text(g_hEditCipher, wrap60(show));
    set_status(L"Ciphertext loaded. Click Break Cipher.");
}

static void on_save_file() {
    if (g_displayPlain.empty()) {
        MessageBoxW(g_hwnd, L"Nothing to save. Break a cipher first.", L"Info",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    wchar_t path[MAX_PATH] = L"plaintext.txt";
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"txt";
    ofn.lpstrTitle = L"Save Plaintext";
    if (!GetSaveFileNameW(&ofn)) return;

    bool ok = write_file_utf8(path, g_displayPlain);
    if (!ok) {
        MessageBoxW(g_hwnd, L"Failed to write the file.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    g_savePath = path;
    set_status(L"Plaintext saved.");
}

static void on_copy_key() {
    int len = GetWindowTextLengthW(g_hEditKey);
    if (len <= 0) {
        set_status(L"No key to copy yet.");
        return;
    }
    std::wstring t(len, L'\0');
    GetWindowTextW(g_hEditKey, &t[0], len + 1);
    if (!OpenClipboard(g_hwnd)) return;
    EmptyClipboard();
    size_t bytes = (t.size() + 1) * sizeof(wchar_t);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h) {
        void *p = GlobalLock(h);
        if (p) { memcpy(p, t.c_str(), bytes); GlobalUnlock(h); }
        SetClipboardData(CF_UNICODETEXT, h);
    }
    CloseClipboard();
    set_status(L"Recovered key copied to clipboard.");
}

static void on_clear() {
    if (InterlockedCompareExchange(&g_solving, 0, 0) != 0) return;
    SetWindowTextW(g_hEditCipher, L"");
    SetWindowTextW(g_hEditPlain, L"");
    SetWindowTextW(g_hEditKey, L"");
    SetWindowTextW(g_hLblScore, L"Score: --");
    SetWindowTextW(g_hLblTime, L"Time: --");
    g_hasGrid = false;
    g_displayPlain.clear();
    g_rawPlain.clear();
    g_cipherRaw.clear();
    InvalidateRect(g_hGrid, nullptr, TRUE);
    set_status(L"Cleared.");
}

static void on_strip_toggle() {
    int padIdx = (int)SendMessageW(g_hComboPad, CB_GETCURSEL, 0, 0);
    if (padIdx >= 0 && padIdx <= 25) g_lastPad = padIdx;
    if (g_result.plainCodes.empty()) return;
    bool strip = SendMessageW(g_hChkStrip, BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::string disp = codes_to_display(g_result.plainCodes, g_lastPad, strip);
    g_displayPlain = disp;
    set_edit_text(g_hEditPlain, wrap60(disp));
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        init_ngram();
        setup_fonts();
        g_bgBrush = CreateSolidBrush(C_BG);
        g_cardBrush = CreateSolidBrush(C_CARD);
        create_controls(hwnd);
        layout(hwnd);
        return 0;

    case WM_SIZE:
        layout(hwnd);
        return 0;

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_BTN_OPEN) on_open_file();
        else if (id == IDC_BTN_BREAK) start_break();
        else if (id == IDC_BTN_SAVE) on_save_file();
        else if (id == IDC_BTN_CLEAR) on_clear();
        else if (id == IDC_BTN_COPY) on_copy_key();
        else if (id == IDC_CHK_STRIP) on_strip_toggle();
        else if (id == IDC_COMBO_PAD && HIWORD(wp) == CBN_SELCHANGE) on_strip_toggle();
        return 0;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lp;
        if (wp == IDC_GRID) { draw_grid(dis); return TRUE; }
        if (dis->CtlType == ODT_BUTTON) { draw_button(dis); return TRUE; }
        break;
    }

    case WM_APP_SOLVED:
        on_solved();
        return 0;

    case WM_APP_PROGRESS:
        return 0;

    case WM_TIMER:
        if (wp == 2) { update_hover(); return 0; }
        if (InterlockedCompareExchange(&g_solving, 0, 0) != 0) {
            int rs = g_progress.restart;
            SendMessageW(g_hProgress, PBM_SETPOS, (WPARAM)((rs + 1) * 100 / 6), 0);
            wchar_t b[64];
            swprintf(b, 64, L"Breaking cipher...  pass %d/6", rs + 1);
            SetWindowTextW(g_hStatus, b);
        }
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lp;
        mmi->ptMinTrackSize.x = 1020;
        mmi->ptMinTrackSize.y = 680;
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        int W = rc.right, H = rc.bottom;
        HDC mem = CreateCompatibleDC(dc);
        HBITMAP bmp = CreateCompatibleBitmap(dc, W, H);
        HBITMAP ob = (HBITMAP)SelectObject(mem, bmp);
        paint_window(mem, W, H);
        BitBlt(dc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
        SelectObject(mem, ob);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        HWND hctl = (HWND)lp;
        SetBkMode(dc, TRANSPARENT);
        bool onCard = (hctl == g_hLblScore || hctl == g_hLblTime ||
                       hctl == g_hLblKeyCap || hctl == g_hEditKey ||
                       hctl == g_hEditPlain);
        if (hctl == g_hEditPlain) {
            SetBkMode(dc, OPAQUE);
            SetBkColor(dc, C_CARD);
        } else {
            SetBkMode(dc, TRANSPARENT);
        }
        SetTextColor(dc, onCard ? C_TEXT : C_SUBTEXT);
        return (LRESULT)(onCard ? g_cardBrush : g_bgBrush);
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        SetBkMode(dc, OPAQUE);
        SetBkColor(dc, C_CARD);
        SetTextColor(dc, C_TEXT);
        return (LRESULT)g_cardBrush;
    }
    case WM_ERASEBKGND:
        return 1;

    case WM_CLOSE:
        if (InterlockedCompareExchange(&g_solving, 0, 0) != 0) {
            int r = MessageBoxW(hwnd, L"A solve is running. Quit anyway?", L"Playfair Breaker",
                                MB_YESNO | MB_ICONQUESTION);
            if (r != IDYES) return 0;
            g_cancel = true;
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        if (g_fontTitle) DeleteObject(g_fontTitle);
        if (g_fontSub) DeleteObject(g_fontSub);
        if (g_fontCard) DeleteObject(g_fontCard);
        if (g_fontUI) DeleteObject(g_fontUI);
        if (g_fontBold) DeleteObject(g_fontBold);
        if (g_fontMono) DeleteObject(g_fontMono);
        if (g_fontKey) DeleteObject(g_fontKey);
        if (g_bgBrush) DeleteObject(g_bgBrush);
        if (g_cardBrush) DeleteObject(g_cardBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

#ifndef PF_CONSOLE_TEST
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"PlayfairBreakerWnd";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, L"PlayfairBreakerWnd",
                                L"Playfair Cipher Breaker",
                                WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, 1160, 800,
                                nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    SetTimer(hwnd, 1, 400, nullptr);   // progress refresh
    SetTimer(hwnd, 2, 60, nullptr);    // button hover tracking

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return 0;
}
#endif  // PF_CONSOLE_TEST

#ifdef PF_CONSOLE_TEST
int wmain(int argc, wchar_t **argv) {
    if (argc >= 3 && _wcsicmp(argv[1], L"--test") == 0) {
        char path[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, argv[2], -1, path, MAX_PATH, nullptr, nullptr);
        int rm = 9, tg = 8, pad = 23;
        if (argc >= 4) rm = argv[3][0] ? (argv[3][0] - L'A') : 9;
        if (argc >= 5) tg = argv[4][0] ? (argv[4][0] - L'A') : 8;
        if (argc >= 6) pad = argv[5][0] ? (argv[5][0] - L'A') : 23;
        return console_test(path, rm, tg, pad);
    }
    printf("usage: --test <cipher.txt> [merge] [target] [pad]\n");
    return 0;
}
#endif