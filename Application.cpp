#include "Application.h"
#include "imgui.h"
#include <iostream>
#include <string>
#include <tchar.h>
#include <vector>
#include <cctype>
#include <map>
#include <string>
#include <sstream>     
#include <windows.h>
#include <random>   
#include <fstream>
#include <commdlg.h>      
#include <filesystem>

namespace fs = std::filesystem;
namespace CipherP
{
    /*─────────────────────  forward decls  ─────────────────────*/
    void Caeser_Cipher(const char*, int);
    void DES_Cipher(const char* text,
        const char* hexKey,   // 16 hex chars (64‑bit key)
        bool decrypt);

    void MorseCode_Cipher(const char*, bool = false);

    /*─────────────────────  globals / helpers  ─────────────────*/
    static bool         g_CopyOnEncrypt = false;
    static std::mt19937 rng{ static_cast<unsigned>(::time(nullptr)) };
    static std::string  output;
    static std::string fileOutput;
   
    enum class IO_Mode2 { IO_TEXT = 0, IO_HEX, IO_BIN };
    static IO_Mode2 g_DES_InMode = IO_Mode2::IO_TEXT;
    static IO_Mode2 g_DES_OutMode = IO_Mode2::IO_HEX;

    // safe, non-throwing atoi
    static bool ParseShiftSafe(const char* txt, int& outVal)
    {
        if (!txt || *txt == '\0') return false;
        char* end = nullptr;
        long v = strtol(txt, &end, 10);
        if (*end != '\0' || v<INT_MIN || v>INT_MAX) return false;
        outVal = static_cast<int>(v);
        return true;
    }

    /*─────────────────────  Tooltip helper  ────────────────────*/
    static void HelpMarker(const char* d) {
        ImGui::TextDisabled("(?)");
        if (ImGui::BeginItemTooltip()) {
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.f);
            ImGui::TextUnformatted(d); ImGui::PopTextWrapPos(); ImGui::EndTooltip();
        }
    }

    template<int N>  // N = 8 or 10
    static inline int bitL(unsigned int v, int i)
    {
        return (v >> (N - 1 - i)) & 1;
    }

    /*─────────────────────  File-dialog helpers  ───────────────*/
    static bool OpenFileDialog(char* p, DWORD sz) {
        OPENFILENAMEA o{ sizeof(o) };
        o.lpstrFilter = "Text\0*.txt\0All\0*.*\0"; o.lpstrFile = p; o.nMaxFile = sz;
        o.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST; return GetOpenFileNameA(&o);
    }
    static bool SaveFileDialog(char* p, DWORD sz) {
        OPENFILENAMEA o{ sizeof(o) };
        o.lpstrFilter = "Text\0*.txt\0All\0*.*\0"; o.lpstrFile = p; o.nMaxFile = sz;
        o.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST; return GetSaveFileNameA(&o);
    }

    /*─────────────────────  small pane helpers  ───────────────*/
    static void BeginFixedPane(const char* id, float w)
    {
        ImGui::BeginChild(id, ImVec2(w, 0), true);
    }
    static void EndPane() { ImGui::EndChild(); }

    // ─── 1. helper: auto-wrap callback ──────────────────────────────
    static int AutoWrapCallback(ImGuiInputTextCallbackData* data)
    {
        const int  kCols = 50;                         // ≈ characters per line
        if (data->EventFlag == ImGuiInputTextFlags_CallbackEdit)
        {
            // find start of current line
            int lineStart = data->CursorPos;
            while (lineStart > 0 && data->Buf[lineStart - 1] != '\n')
                --lineStart;

            int col = data->CursorPos - lineStart;
            if (col >= kCols)                         // end reached → insert '\n'
            {
                data->InsertChars(data->CursorPos, "\n");
            }
        }
        return 0;
    }
    // ╔══════════════════════════════════════════════════════════╗
    //  R e n d e r U I
    // ╚══════════════════════════════════════════════════════════╝
    void RenderUI()
    {
        /*──────── persistent ui vars ───────*/
        static char Input[256]{}, SKey[64]{}, EKey[64]{};
        static bool doDecrypt = false, showRes = false, fileLoaded = false, fileDone = false;
        static int  cipher = -1;                       // -1 none | 0 Cae | 1 DES | 2 Morse
        static char inPath[MAX_PATH]{}, outPath[MAX_PATH]{};
        static std::string fileBuf;
        static bool wantErr = false; static std::string err;

        /*──────── window + dock ────────────*/
        ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
        ImGui::SetNextWindowSize(ImVec2(1000, 640), ImGuiCond_FirstUseEver);
        ImGui::Begin("Encryption Algorithm", nullptr,
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_MenuBar);

        /*──────── menu bar ───────*/
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("Settings")) {
                ImGui::Checkbox("Copy result to clipboard", &g_CopyOnEncrypt);
                ImGui::EndMenu(); // correct
            }

            if (ImGui::BeginMenu("Help"))
            {
                if (ImGui::MenuItem("Documentation"))
                {
                    ShellExecuteA(0, 0, "https://github.com/ocornut/imgui", 0, 0, SW_SHOW);
                }

                if (ImGui::MenuItem("About"))
                {
                    ShellExecuteA(0, 0, "https://www.taibahu.edu.sa/Pages/EN/Sector/SectorPage.aspx?ID=155&PageId=30", 0, 0, SW_SHOW);
                }
                ImGui::EndMenu();
            }

            ImGui::EndMenuBar();
        }
        /*──────── main scrollable area ─────*/
        ImGui::BeginChild("##MainContent", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), true, ImGuiWindowFlags_NoResize);
        //center pop up error messages
        ImVec2 center = ImGui::GetMainViewport()->GetCenter();
        ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        /*================  (A) TEXT PANE  ================*/
        BeginFixedPane("##TextPane", 380.f);

        ImGuiInputTextFlags wrapFlags = ImGuiInputTextFlags_CallbackEdit | ImGuiInputTextFlags_AllowTabInput;

        /* ----------------------- input box ---------------------------- */
        ImGui::Text("Plain / cipher text");
        ImGui::InputTextMultiline("##txt",
            Input, IM_ARRAYSIZE(Input),
            ImVec2(-FLT_MIN, 140),
            wrapFlags, AutoWrapCallback);

        ImGui::Checkbox("Decrypt mode", &doDecrypt);
        ImGui::Separator();

        /* ----------‑‑ cipher–specific widgets (always visible) -------- */
        if (cipher == 0)                       /* Caesar */
        {
            ImGui::InputText("Shift", SKey, IM_ARRAYSIZE(SKey),
                ImGuiInputTextFlags_CharsDecimal);

            if (ImGui::SmallButton("Randomize key##C"))
            {
                int r = (rng() % 25) + 1; _itoa_s(r, SKey, 10);
            }
        }
        else if (cipher == 1)                  /* DES */
        {
            ImGui::InputText("16 hex key", EKey, IM_ARRAYSIZE(EKey),
                ImGuiInputTextFlags_CharsHexadecimal |
                ImGuiInputTextFlags_CharsUppercase);

            if (ImGui::SmallButton("Randomize key##D"))
            {
                for (int i = 0; i < 16; ++i)
                    EKey[i] = "0123456789ABCDEF"[rng() & 0xF];
                EKey[16] = '\0';
            }

            static const char* inModes[] = { "ASCII", "Hex", "Binary" };
            static const char* outModes[] = { "Hex",   "Binary" };

            ImGui::Combo("Input is",
                (int*)&g_DES_InMode, inModes, IM_ARRAYSIZE(inModes));

            int outIdx = (g_DES_OutMode == IO_Mode2::IO_BIN) ? 1 : 0;
            if (ImGui::Combo("Output as", &outIdx,
                outModes, IM_ARRAYSIZE(outModes)))
                g_DES_OutMode = (outIdx == 1) ? IO_Mode2::IO_BIN
                : IO_Mode2::IO_HEX;
        }
       
        /* ----------------------- run button --------------------------- */
        if (ImGui::Button("Run on text"))
        {
            err.clear();

            if (cipher == -1)              err = "Choose a cipher first.";
            else if (*Input == '\0')       err = "Input text is empty.";
            else if (cipher == 0)          // Caesar validation
            {
                int dummy;
                if (!ParseShiftSafe(SKey, dummy)) err = "Shift must be integer.";
            }
            else if (cipher == 1)          // DES validation
            {
                if (strlen(EKey) != 16)          err = "Key must be 16 hex chars.";
                else if (std::string(EKey).find_first_not_of(
                    "0123456789ABCDEFabcdef") != std::string::npos)
                    err = "Key may contain only 0‑9 / A‑F.";

                // you could also validate ASCII/hex/binary text here if you wish
            }

            /* ----‑‑ dispatch cipher only when there is no error ---- */
            if (!err.empty())
                wantErr = true;
            else
            {
                output.clear();
                switch (cipher)
                {
                case 0:
                {
                    int sh; ParseShiftSafe(SKey, sh);
                    if (doDecrypt) sh = -sh;
                    Caeser_Cipher(Input, sh);
                    break;
                } 

                case 1:
                    DES_Cipher(Input, EKey, doDecrypt);
                    break;

                case 2:
                    MorseCode_Cipher(Input, doDecrypt);
                    break;
                }
                showRes = true;
                if (g_CopyOnEncrypt) ImGui::SetClipboardText(output.c_str());
            }
        }

        /* ----------------------- result box --------------------------- */
        if (showRes)
        {
            ImGui::SeparatorText("Result");
            ImGui::InputTextMultiline("##out",
                output.data(), output.size() + 1,
                ImVec2(-FLT_MIN, 120),
                wrapFlags | ImGuiInputTextFlags_ReadOnly,
                AutoWrapCallback);
        }
        EndPane(); ImGui::SameLine();

        /*================  (B) CHOICE PANE  ================*/
        BeginFixedPane("##ChoicePane", 240.f);
        ImGui::Text("Select cipher"); ImGui::Separator();
        if (ImGui::RadioButton("Caesar", cipher == 0)) cipher = 0;
        ImGui::SameLine(); HelpMarker("A substitution cipher that shifts each letter in the text by a fixed number of positions in the alphabet. Only alphabetic characters are affected.");
        if (ImGui::RadioButton("DES", cipher == 1)) cipher = 1;
        ImGui::SameLine(); HelpMarker("Classic DES  64 bit blocks, 16 rounds. Key: 16 hex chars (64‑bit, parity ignored).");
        if (ImGui::RadioButton("Morse", cipher == 2))  cipher = 2;
        ImGui::SameLine(); HelpMarker("Encodes letters and numbers into sequences of dots and dashes. Originally used in telegraph communication. Supports both encoding and decoding.");
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::SeparatorText("Quick quide");

        ImGui::TextWrapped(
            "Use the left panel to encrypt or decrypt individual text inputs.\n"
            "Use the right panel to work with entire text files.\n\n"
            "First, select a cipher from the center panel. Then proceed to encrypt or decrypt "
            "your content using either the left (text input) or right (file processing) panel."
        );
        EndPane(); ImGui::SameLine();
        /*================  (C) FILE PANE  ================*/
        ImGui::BeginChild("##FilePane", ImVec2(0, 0), true);
        ImGui::Text("File encryption");

        if (ImGui::Button("Load text file…")) {
            if (OpenFileDialog(inPath, MAX_PATH)) {
                std::ifstream f(inPath, std::ios::binary);
                fileBuf.assign((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
                fileLoaded = true;
                fileDone = false;
            }
        }
        ImGui::SameLine();
        ImGui::TextDisabled("%s", fileLoaded ? inPath : "no file");
        /*───────────── RUN ON FILE ─────────────*/
        if (ImGui::Button("Run on file"))
        {
            err.clear();

            /* --- validate -------------------------------------------------------- */
            if (!fileLoaded)
                err = "No file loaded.";
            else if (cipher == -1)
                err = "Choose a cipher first.";
            else if (cipher == 0)                     // Caesar
            {
                int v;
                if (!ParseShiftSafe(SKey, v))
                    err = "Shift must be an integer.";
            }
            else if (cipher == 1)                     // DES
            {
                if (strlen(EKey) != 16)
                    err = "DES key must be 16 hex chars.";
                else if (std::string(EKey).find_first_not_of(
                    "0123456789ABCDEFabcdef") != std::string::npos)
                    err = "Key may contain only 0‑9 A‑F.";
            }

            /* --- abort on validation error --------------------------------------- */
            if (!err.empty()) {
                wantErr = true;          // show the popup later
            }
            else {


                /*── 1.  preserve current text‑pane contents ─────────────────────────── */
                std::string prevOutput = output;
                bool        prevShow = showRes;

                /*── 2.  run cipher on the loaded buffer ─────────────────────────────── */
                output.clear();

                switch (cipher)
                {
                case 0: {                                // Caesar
                    int sh; ParseShiftSafe(SKey, sh);
                    if (doDecrypt) sh = -sh;
                    Caeser_Cipher(fileBuf.c_str(), sh);
                    break;                               // <-- needed!
                }
                case 1:                                  // DES
                    DES_Cipher(fileBuf.c_str(), EKey, doDecrypt);
                    break;

                case 2:                                  // Morse
                    MorseCode_Cipher(fileBuf.c_str(), doDecrypt);
                    break;
                }

                fileOutput = output;                     // copy for disk

                /*── 3.  write to disk & clipboard ───────────────────────────────────── */
                fs::path p(inPath);
                std::string suf = doDecrypt ? "_dec" : "_enc";
                fs::path out = p.parent_path()
                    / (p.stem().string() + suf + p.extension().string());

                strncpy(outPath, out.string().c_str(), MAX_PATH - 1);
                outPath[MAX_PATH - 1] = '\0';

                std::ofstream(out, std::ios::binary) << fileOutput;
                if (g_CopyOnEncrypt) ImGui::SetClipboardText(fileOutput.c_str());
                fileDone = true;

                /*── 4.  restore text‑pane so screen doesn’t change ──────────────────── */
                output = std::move(prevOutput);
                showRes = prevShow;
            }
        }


        /*──────── done message + open button ───────*/
        if (fileDone) {
            ImGui::Separator();
            ImGui::TextDisabled("Saved → %s", outPath);
            if (ImGui::SmallButton("Open output"))
                ShellExecuteA(0, 0, outPath, 0, 0, SW_SHOW);
        }

        ImGui::EndChild();   // ##FilePane
        ImGui::EndChild();   // ##MainContent

        /*──────── show modal AFTER child is closed ─────*/
        if (wantErr) { ImGui::OpenPopup("Input Error"); wantErr = false; }
        if (ImGui::BeginPopupModal("Input Error", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::TextWrapped("%s", err.c_str());
            ImGui::Separator();
            if (ImGui::Button("OK", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }

        /*──────── footer ─────────*/
        ImGuiIO& io = ImGui::GetIO();
        ImGui::Separator();
        ImGui::Text("avg %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
        ImGui::SameLine(); ImGui::TextDisabled("| made by Zain Alamry - Ahmad Alahmadi - Hussam alshehri - Mohammad Almogathawi - Mohammad Aljohani");
        ImGui::End();  // main window
    }

    // ------------------------------------------------------------------------------------
    // Caesar Cipher
    // ------------------------------------------------------------------------------------
    void Caeser_Cipher(const char* text, int shift)
    {
        output.clear();

        for (int i = 0; text[i] != '\0'; i++)
        {
            char c = text[i];
            if (std::isalpha(static_cast<unsigned char>(c)))
            {
                bool isUpper = (c >= 'A' && c <= 'Z');
                char base = isUpper ? 'A' : 'a';

                int alphaIndex = c - base;
                int shifted = (alphaIndex + shift) % 26;
                if (shifted < 0) shifted += 26;
                c = static_cast<char>(base + shifted);
            }
            output.push_back(c);
        }
    }

    // ------------------------------------------------------------------------------------
  // Morse Code Cipher  (encode & decode)
  // ------------------------------------------------------------------------------------
    void MorseCode_Cipher(const char* text, bool decrypt)
    {
        output.clear();

        /* ------------ MORSE tables ----------------- */
        static const std::map<char, std::string> morseMap = {
            {'A',".-"},{'B',"-..."},{'C',"-.-."},{'D',"-.."},
            {'E',"."}, {'F',"..-."},{'G',"--."}, {'H',"...."},
            {'I',".."},{'J',".---"},{'K',"-.-"}, {'L',".-.."},
            {'M',"--"},{'N',"-."}, {'O',"---"}, {'P',".--."},
            {'Q',"--.-"},{'R',".-."},{'S',"..."}, {'T',"-"},
            {'U',"..-"},{'V',"...-"},{'W',".--"}, {'X',"-..-"},
            {'Y',"-.--"},{'Z',"--.."}
        };
        static std::map<std::string, char> rev;
        if (rev.empty())
            for (auto& kv : morseMap) rev[kv.second] = kv.first;

        /* ============== ENCRYPT ===================== */
        if (!decrypt)
        {
            bool firstToken = true;
            for (const char* p = text; *p; ++p)
            {
                char c = *p;
                if (std::isalpha((unsigned char)c))
                {
                    if (!firstToken) output.push_back(' ');
                    output += morseMap.at((char)std::toupper((unsigned char)c));
                    firstToken = false;
                }
                else if (c == ' ')
                {
                    if (!firstToken) output += " /";
                    firstToken = false;                  // next letter still needs blank
                }
                else        // punctuation → copy verbatim with a preceding space
                {
                    if (!firstToken) output.push_back(' ');
                    output.push_back(c);
                    firstToken = false;
                }
            }
        }
        /* ============== DECRYPT ===================== */
        else
        {
            std::string current;               // collect ".-.-" etc.
            auto flushToken = [&]()            // helper → emit one token
                {
                    if (current.empty()) return;
                    if (current == "/")
                        output.push_back(' ');
                    else
                    {
                        auto it = rev.find(current);
                        output.push_back(it != rev.end() ? it->second : '?');
                    }
                    current.clear();
                };

            for (const char* p = text; *p; ++p)
            {
                char c = *p;
                if (c == '.' || c == '-')          // still inside a code
                {
                    current.push_back(c);
                }
                else if (c == '/')                // explicit word break
                {
                    flushToken();
                    current = "/";                // will be converted to space
                }
                else if (std::isspace((unsigned char)c))   // token separator
                {
                    flushToken();
                }
                else                              // punctuation → copy verbatim
                {
                    flushToken();
                    output.push_back(c);
                }
            }
            flushToken();                         // last token (if any)
        }
    }



    // ⇩⇩==============================================================⇩⇩
//                        DES IMPLEMENTATION
//               64‑bit ECB, 16 Feistel rounds (FIPS‑46‑3)
// -----------------------------------------------------------------
//  • Key  : 16 hex chars  (64 bits – parity bits ignored)
//  • Input: blocks given as ASCII / Hex / Binary   (chosen in UI)
//  • Output: Hex or Binary (chosen in UI)
//  • Global controls: g_DES_InMode  ,  g_DES_OutMode   (IO_Mode2)
// ================================================================⇩⇩


// ───── helper enum comes from your header ─────
// enum class IO_Mode2 { IO_TEXT = 0, IO_HEX , IO_BIN };

    namespace {

        /* ─────────────── DES tables (FIPS‑46‑3) ─────────────── */
        const int IP[64] = {
         57,49,41,33,25,17, 9, 1, 59,51,43,35,27,19,11, 3,
         61,53,45,37,29,21,13, 5, 63,55,47,39,31,23,15, 7,
         56,48,40,32,24,16, 8, 0, 58,50,42,34,26,18,10, 2,
         60,52,44,36,28,20,12, 4, 62,54,46,38,30,22,14, 6 };

        const int FP[64] = {
         39, 7,47,15,55,23,63,31, 38, 6,46,14,54,22,62,30,
         37, 5,45,13,53,21,61,29, 36, 4,44,12,52,20,60,28,
         35, 3,43,11,51,19,59,27, 34, 2,42,10,50,18,58,26,
         33, 1,41, 9,49,17,57,25, 32, 0,40, 8,48,16,56,24 };

        const int E[48] = {
         31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8,
          7, 8, 9,10,11,12,11,12,13,14,15,16,
         15,16,17,18,19,20,19,20,21,22,23,24,
         23,24,25,26,27,28,27,28,29,30,31, 0 };

        const int P[32] = { 15, 6,19,20,28,11,27,16, 0,14,22,25,4,17,30, 9,
                             1, 7,23,13,31,26, 2, 8,18,12,29, 5,21,10, 3,24 };

        const int PC1[56] = {
         56,48,40,32,24,16, 8, 0,57,49,41,33,25,17,
          9, 1,58,50,42,34,26,18,10, 2,59,51,43,35,
         62,54,46,38,30,22,14, 6,61,53,45,37,29,21,
         13, 5,60,52,44,36,28,20,12, 4,27,19,11, 3 };

        const int PC2[48] = {
         13,16,10,23, 0, 4, 2,27,14, 5,20, 9,
         22,18,11, 3,25, 7,15, 6,26,19,12, 1,
         40,51,30,36,46,54,29,39,50,44,32,47,
         43,48,38,55,33,52,45,41,49,35,28,31 };

        const int SHIFTS[16] = { 1,1,2,2,2,2,2,2, 1,2,2,2,2,2,2,1 };

        const int SBOX[8][4][16] = {
            /* S1 */{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                     {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
                     /* S2 */{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                              {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                              {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                              {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
                              /* S3 */{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                                       {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                                       {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                                       {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
                                       /* S4 */{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                                                {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                                                {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                                                {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
                                                /* S5 */{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                                                         {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                                                         {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                                                         {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
                                                         /* S6 */{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                                                                  {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                                                                  {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                                                                  {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
                                                                  /* S7 */{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                                                                           {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                                                                           {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                                                                           {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
                                                                           /* S8 */{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                                                                                    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                                                                                    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                                                                                    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
        };

        /* -------------------------------------------------------------- */
        inline int  getBit64(uint64_t v, int pos) { return (v >> (63 - pos)) & 1ULL; }
        inline void setBit64(uint64_t& v, int pos) { v |= 1ULL << (63 - pos); }

        /* generic permutation Nout←Nin */
        template<int Nout, int Nin>
        uint64_t permute(uint64_t in, const int* tbl)
        {
            uint64_t out = 0;
            for (int i = 0; i < Nout; ++i)
                if (getBit64(in, tbl[i])) setBit64(out, i);
            return out;
        }

        /* rotate 28‑bit value left by s */
        uint32_t rot28(uint32_t x, int s) { return ((x << s) | (x >> (28 - s))) & 0x0FFFFFFF; }

        /* Feistel f(R,Ki)  – R:32, Ki:48 → 32 */
        uint32_t feistel(uint32_t R, uint64_t Ki)
        {
            /* E expansion */
            uint64_t E48 = 0;
            for (int i = 0; i < 48; ++i)
                if ((R >> (32 - 1 - E[i])) & 1) E48 |= 1ULL << (47 - i);

            E48 ^= Ki;                              // XOR with sub‑key

            /* S‑boxes */
            uint32_t out32 = 0;
            for (int b = 0; b < 8; ++b)
            {
                uint8_t chunk = (E48 >> (42 - 6 * b)) & 0x3F;
                int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
                int col = (chunk >> 1) & 0x0F;
                uint8_t s = SBOX[b][row][col];
                out32 |= uint32_t(s) << (28 - 4 * b);
            }

            /* P permutation */
            uint32_t P32 = 0;
            for (int i = 0; i < 32; ++i)
                if ((out32 >> (32 - 1 - P[i])) & 1) P32 |= 1u << (31 - i);
            return P32;
        }

        /* produce 16 sub‑keys (48 bits each) */
        void makeSubKeys(const char* hexKey, uint64_t sub[16])
        {
            uint64_t k64 = std::strtoull(hexKey, nullptr, 16);
            uint64_t k56 = permute<56, 64>(k64, PC1);

            uint32_t C = uint32_t(k56 >> 28);
            uint32_t D = uint32_t(k56 & 0x0FFFFFFF);

            for (int r = 0; r < 16; ++r)
            {
                C = rot28(C, SHIFTS[r]);
                D = rot28(D, SHIFTS[r]);
                uint64_t CD = (uint64_t(C) << 28) | D;
                sub[r] = permute<48, 56>(CD, PC2);
            }
        }

        /* -------- helpers: parse / format blocks -------- */
        std::vector<uint64_t> parseBlocks(const char* txt, IO_Mode2 mode)
        {
            std::vector<uint64_t> v;
            std::istringstream iss(txt);
            std::string tok;
            while (iss >> tok)
            {
                if (mode == IO_Mode2::IO_TEXT)
                {
                    for (const char* p = txt; *p; ++p)
                        v.push_back(static_cast<uint64_t>(static_cast<unsigned char>(*p)) << 56); // pad to 64‑bit
                }
                else if (mode == IO_Mode2::IO_BIN)
                {
                    if (tok.size() != 64) continue;
                    uint64_t b = 0;
                    for (char c : tok) { b <<= 1; if (c == '1') b |= 1; }
                    v.push_back(b);
                }
                else                    // hex
                {
                    uint64_t b = std::stoull(tok, nullptr, 16);
                    v.push_back(b);
                }
            }
            return v;
        }
        std::string fmtBlocks(const std::vector<uint64_t>& v, IO_Mode2 mode)
        {
            std::ostringstream oss;
            for (size_t i = 0; i < v.size(); ++i)
            {
                if (mode == IO_Mode2::IO_BIN)
                {
                    for (int b = 63; b >= 0; --b) oss << (((v[i] >> b) & 1) ? '1' : '0');
                }
                else
                {
                    oss << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << v[i];
                }
                if (i + 1 != v.size()) oss << ' ';
            }
            return oss.str();
        }

    } //‑‑ anon namespace



    /*────────────────────  PUBLIC API  ───────────────────*/
    void DES_Cipher(const char* text, const char* hexKey, bool decrypt)
    {
        output.clear();

        /* 1. sub‑keys */
        uint64_t sub[16]; makeSubKeys(hexKey, sub);

        /* 2. parse input */
        IO_Mode2 parseMode = g_DES_InMode;

        std::vector<uint64_t> blocks = parseBlocks(text, parseMode);
        if (blocks.empty()) { output = "(no valid blocks)"; return; }

        /* 3. process each block */
        std::vector<uint64_t> res; res.reserve(blocks.size());

        for (uint64_t blk : blocks)
        {
            uint64_t B = permute<64, 64>(blk, IP);          // IP
            uint32_t L = uint32_t(B >> 32);
            uint32_t R = uint32_t(B & 0xFFFFFFFF);

            for (int r = 0; r < 16; ++r)
            {
                uint32_t tmp = R;
                uint64_t k = decrypt ? sub[15 - r] : sub[r];
                R = L ^ feistel(R, k);
                L = tmp;
            }
            uint64_t preFP = (uint64_t)L << 32 | R;         
            uint64_t C = permute<64, 64>(preFP, FP);    // FP
            res.push_back(C);
        }

        /* 4. format output */
        output = fmtBlocks(res, g_DES_OutMode);
    }
   
} 
