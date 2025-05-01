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
    void SDES_Cipher(const char*, const char*, bool);
    void MorseCode_Cipher(const char*, bool = false);

    /*─────────────────────  globals / helpers  ─────────────────*/
    static bool         g_CopyOnEncrypt = false;
    static std::mt19937 rng{ static_cast<unsigned>(::time(nullptr)) };
    static std::string  output;
    static std::string fileOutput;
    enum IO_Mode { IO_LETTERS = 0, IO_DEC = 1, IO_BIN = 2 };

    static IO_Mode g_SDES_InMode = IO_BIN;   // default binary 
    static IO_Mode g_SDES_OutMode = IO_BIN;   // default binary

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
        ImGui::BeginChild("##MainContent", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), true);
        //center pop up error messages
        ImVec2 center = ImGui::GetMainViewport()->GetCenter();
        ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        /*================  (A) TEXT PANE  ================*/
        BeginFixedPane("##TextPane", 380.f);

        ImGuiInputTextFlags wrapFlags = ImGuiInputTextFlags_CallbackEdit | ImGuiInputTextFlags_AllowTabInput ;

        ImGui::Text("Plain / cipher text");
        ImGui::InputTextMultiline("##txt",                 
            Input, IM_ARRAYSIZE(Input),
            ImVec2(-FLT_MIN, 140),
            wrapFlags, AutoWrapCallback);                    

        ImGui::Checkbox("Decrypt mode", &doDecrypt);
        ImGui::Separator();

        if (cipher == 0) {                                // Caesar
            ImGui::InputText("Shift", SKey, IM_ARRAYSIZE(SKey), ImGuiInputTextFlags_CharsDecimal);
            
            if (ImGui::SmallButton("Randomize key##C")) {
                int r = (rng() % 25) + 1; _itoa_s(r, SKey, 10);
            }
        }
        else if (cipher == 1) {                          // S-DES
            ImGui::InputText("10-bit key", EKey, IM_ARRAYSIZE(EKey));
            
            if (ImGui::SmallButton("Randomize key##S")) {
                for (int i = 0; i < 10; ++i) EKey[i] = (rng() & 1) ? '1' : '0';
                EKey[10] = '\0';
            }
            // ── input   (Letters / Decimal / Binary) ───────────────────────
            static const char* inModes[] = { "Letters", "Decimal", "Binary" };
            ImGui::Combo("Input is", (int*)&g_SDES_InMode,
                inModes, IM_ARRAYSIZE(inModes));

            // ── output  (Decimal / Binary   *ONLY* ) ───────────────────────
            static const char* outModes[] = { "Decimal", "Binary" };
            int outIdx = (g_SDES_OutMode == IO_BIN) ? 1 : 0;
            if (ImGui::Combo("Output as", &outIdx, outModes, IM_ARRAYSIZE(outModes)))
                g_SDES_OutMode = (outIdx == 1) ? IO_BIN : IO_DEC;
        }

        /*---- run on text --------------------------------------------------*/
        if (ImGui::Button("Run on text")) {
            err.clear();
            if (cipher == -1)              err = "Choose a cipher first.";
            else if (*Input == '\0')       err = "Input text is empty.";
            else if (cipher == 0) { int d; if (!ParseShiftSafe(SKey, d)) err = "Shift must be integer."; }
            else if (cipher == 1) {
                if (strlen(EKey) != 10) err = "S-DES key must be 10 bits.";
                else if (std::string(EKey).find_first_not_of("01") != std::string::npos)
                    err = "S-DES key can contain only 0 or 1.";
            }

            if (!err.empty()) wantErr = true;
            else {
                output.clear();
                switch (cipher) {
                case 0: {
                    int sh; ParseShiftSafe(SKey, sh); if (doDecrypt) sh = -sh;
                    Caeser_Cipher(Input, sh);
                } break;
                case 1: SDES_Cipher(Input, EKey, doDecrypt); break;
                case 2: MorseCode_Cipher(Input, doDecrypt); break;
                }
                showRes = true;
                if (g_CopyOnEncrypt) ImGui::SetClipboardText(output.c_str());
            }
        }

        if (showRes) {
            ImGui::SeparatorText("Result");
            ImGui::InputTextMultiline("##out",                
                output.data(), output.size() + 1,
                ImVec2(-FLT_MIN, 120),
                wrapFlags | ImGuiInputTextFlags_ReadOnly         // read-only
                ,
                AutoWrapCallback);                            
        }
        EndPane(); ImGui::SameLine();

        /*================  (B) CHOICE PANE  ================*/
        BeginFixedPane("##ChoicePane", 240.f);
        ImGui::Text("Select cipher"); ImGui::Separator();
        if (ImGui::RadioButton("Caesar", cipher == 0)) cipher = 0;
        ImGui::SameLine(); HelpMarker("A substitution cipher that shifts each letter in the text by a fixed number of positions in the alphabet. Only alphabetic characters are affected.");
        if (ImGui::RadioButton("S-DES", cipher == 1))  cipher = 1;
        ImGui::SameLine(); HelpMarker("A teaching version of the DES algorithm. Uses a 10-bit key to encrypt 8-bit blocks through two Feistel rounds with permutations.");
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

       /*───────────── RUN ON FILE ─────────────*/
        if (ImGui::Button("Run on file"))
        {
            err.clear();
          

            if (!err.empty())  wantErr = true;
            else {
                /*── 1.  preserve whatever is currently displayed in the text pane ──*/
                std::string  prevOutput = output;   // make a copy
                bool         prevShow = showRes;

                /*── 2.  run cipher → output   (re-using existing functions) ───────*/
                output.clear();
                switch (cipher)
                {
                case 0: {
                    int sh; ParseShiftSafe(SKey, sh); if (doDecrypt) sh = -sh;
                    Caeser_Cipher(fileBuf.c_str(), sh);
                }                break;
                case 1:   SDES_Cipher(fileBuf.c_str(), EKey, doDecrypt);      break;
                case 2:   MorseCode_Cipher(fileBuf.c_str(), doDecrypt);        break;
                }
                fileOutput = output;           // keep a *separate* copy for the file

                /*── 3.  write to disk & clipboard ─────────────────────────────────*/
                fs::path p(inPath);
                std::string suf = doDecrypt ? "_dec" : "_enc";
                fs::path out = p.parent_path() /
                    (p.stem().string() + suf + p.extension().string());
                strcpy(outPath, out.string().c_str());
                std::ofstream(out, std::ios::binary) << fileOutput;
                if (g_CopyOnEncrypt) ImGui::SetClipboardText(fileOutput.c_str());
                fileDone = true;

                /*── 4.  restore text-pane data so it does NOT show file result ───*/
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



    // ------------------------------------------------------------------------------------
    // S-DES (Simplified DES) Implementation
    // ------------------------------------------------------------------------------------
    // This is a *teaching cipher* that uses a 10-bit key and 8-bit blocks,
    // performing 2 Feistel rounds. We can do encryption or decryption by reversing subkey order.
    //
    // Steps:
    // 1. Key schedule: produce two 8-bit subkeys from the 10-bit key
    // 2. Initial Permutation (IP)
    // 3. Round 1 (fK) with subkey1, then swap halves
    // 4. Round 2 (fK) with subkey2
    // 5. Final Permutation (IP^-1)
    // For decryption, just swap the order of subkey1, subkey2.
    //
    // If the input text is >1 byte, we process each byte in turn (ECB-like).
    //
    // IMPORTANT: Real DES is 64 bits + 56-bit key + 16 rounds + more complexity.
    // This code is purely for demonstration, not secure.
    // ------------------------------------------------------------------------------------

    // ---------- 8-bit permutation ---------------------------------
    static unsigned char permute8(unsigned char in, const int* tbl, int n)
    {
        unsigned char out = 0;
        for (int i = 0; i < n; ++i)
            out |= bitL<8>(in, tbl[i]) << (n - 1 - i);
        return out;
    }

    // ---------- 10-bit permutation --------------------------------
    static unsigned short permute10(unsigned short in, const int* tbl, int n)
    {
        unsigned short out = 0;
        for (int i = 0; i < n; ++i)
            out |= bitL<10>(in, tbl[i]) << (n - 1 - i);
        return out;
    }


    // Left shift for 5 bits (half of 10-bit key)
    static unsigned short leftShift5bits(unsigned short val, int shifts)
    {
        // We only want the lower 5 bits
        // e.g. if val=abcde in binary, shifting by 1 => bcdea
        unsigned short mask = 0x1F; // 5 bits (0001 1111)
        unsigned short out = ((val << shifts) & mask) | (val >> (5 - shifts));
        return out;
    }

    // Key schedule (2 subkeys)
    // P10, split into left/right 5 bits, shift, P8 => subkey1
    // shift again, P8 => subkey2
    void generateSubKeys(unsigned short key10, unsigned char& subkey1, unsigned char& subkey2)
    {
        // P10 table (bit indices, right->left in typical references),
        // but we’ll label in ascending order for code. 
        // This is standard for S-DES:
        const int P10[10] = { 2, 4, 1, 6, 3, 9, 0, 8, 7, 5 };

        // P8 table (we pick 8 bits out of the 10)
        const int P8[8] = { 5, 2, 6, 3, 7, 4, 9, 8 };

        // Step 1: permute by P10
        unsigned short p10_out = permute10(key10, P10, 10);

        // Step 2: split into left 5 bits, right 5 bits
        unsigned short left5 = (p10_out >> 5) & 0x1F;   // top 5 bits
        unsigned short right5 = p10_out & 0x1F;         // bottom 5 bits

        // Step 3: left shift by 1 to get subkey1
        left5 = leftShift5bits(left5, 1);
        right5 = leftShift5bits(right5, 1);

        // Combine
        unsigned short combined = (left5 << 5) | (right5);

        // Step 4: apply P8 => subkey1
        // We'll store subkey as 8 bits
        unsigned char sk1 = 0;
        for (int i = 0; i < 8; ++i)
        {
            int b = bitL<10>(combined, P8[i]);   // MSB-first read
            sk1 |= b << (7 - i);                   // MSB-first write
        }


        // Next shift by 2 (from original 1 shift or from the new state?)
        left5 = leftShift5bits(left5, 2);
        right5 = leftShift5bits(right5, 2);
        combined = (left5 << 5) | (right5);

        // Apply P8 => subkey2
        unsigned char sk2 = 0;
        for (int i = 0; i < 8; ++i)
        {
            int b = bitL<10>(combined, P8[i]);
            sk2 |= b << (7 - i);
        }

        subkey1 = sk1;
        subkey2 = sk2;
    }

    // The fK function for each round:
    //   split 8 bits => left (4 bits), right (4 bits)
    //   F(right, subkey) => 4 bits
    //   left XOR F => new left
    //   right => new right
    // so out = (newLeft << 4) | newRight
    // We'll define F() separately
    static unsigned char sdesRound(unsigned char in, unsigned char subkey)
    {
        // Split
        unsigned char left4 = (in >> 4) & 0x0F;
        unsigned char right4 = in & 0x0F;

        // Feistel
        unsigned char fOut = 0; // F(right4, subkey)

        // E/P (expand 4 bits to 8 bits)
        static const int EP[8] = { 3,0,1,2, 1,2,3,0 };
        unsigned char epVal = 0;
        for (int i = 0; i < 8; ++i)
        {
            int bit = bitL<4>(right4, EP[i]);      // ← use MSB-indexed helper
            epVal |= bit << (7 - i);                 // keep table order
        }

        // XOR with subkey
        epVal ^= subkey;

        // Now epVal is 8 bits: left half => s0, right half => s1
        unsigned char leftHalf = (epVal >> 4) & 0x0F;
        unsigned char rightHalf = epVal & 0x0F;

        // S-boxes (S0, S1) for S-DES
        // Each is 4x4, indexing with [row, col]
        // row = (b2 << 1) | b3, col = (b1 << 1) | b0
        static const unsigned char S0[4][4] = {
            {1, 0, 3, 2},
            {3, 2, 1, 0},
            {0, 2, 1, 3},
            {3, 1, 3, 2}
        };
        static const unsigned char S1[4][4] = {
            {0, 1, 2, 3},
            {2, 0, 1, 3},
            {3, 0, 1, 0},
            {2, 1, 0, 3}
        };

        // leftHalf => bits (b3 b2 b1 b0). We interpret (b3,b0) as row, (b2,b1) as col
        auto sboxLookup = [&](unsigned char half, const unsigned char box[4][4]) {
            unsigned char row = ((half & 0b1000) >> 2) | (half & 0b0001);
            unsigned char col = (half & 0b0110) >> 1;
            return box[row][col];
            };

        unsigned char s0Val = sboxLookup(leftHalf, S0); // 2 bits
        unsigned char s1Val = sboxLookup(rightHalf, S1); // 2 bits

        // Combine s0Val, s1Val into 4 bits
        unsigned char combinedS = (unsigned char)((s0Val << 2) | s1Val);

        // P4
        static const int P4[4] = { 1,3,2,0 };
        unsigned char p4Val = 0;
        for (int i = 0; i < 4; ++i)
        {
            int bit = bitL<4>(combinedS, P4[i]);   // ← ditto
            p4Val |= bit << (3 - i);
        }
        fOut = p4Val;

        // Now XOR with left4
        unsigned char newLeft = left4 ^ fOut;
        // Right stays the same
        unsigned char newRight = right4;

        // Combine back
        unsigned char outVal = (newLeft << 4) | newRight;
        return outVal;
    }

    // Initial Permutation
    static const int IP[8] = { 1, 5, 2, 0, 3, 7, 4, 6 };
    // Final Permutation
    static const int IP_1[8] = { 3, 0, 2, 4, 6, 1, 7, 5 };

    // S-DES main routine (encrypt or decrypt a single 8-bit block)
    static unsigned char sdesEncryptByte(unsigned char block, unsigned char sk1, unsigned char sk2, bool decrypt)
    {
        // 1) IP
        block = permute8(block, IP, 8);

        // 2) Round 1
        if (!decrypt)
        {
            block = sdesRound(block, sk1);
        }
        else
        {
            block = sdesRound(block, sk2); // reverse order if decrypt
        }

        // 3) Swap left, right
        //   left = block >> 4, right = block & 0xF
        //   out = (right << 4) | left
        unsigned char left4 = (block >> 4) & 0x0F;
        unsigned char right4 = block & 0x0F;
        block = (right4 << 4) | left4;

        // 4) Round 2
        if (!decrypt)
        {
            block = sdesRound(block, sk2);
        }
        else
        {
            block = sdesRound(block, sk1);
        }

        // 5) FP
        block = permute8(block, IP_1, 8);

        return block;
    }

    // The public function that processes an entire string, one byte at a time
    void SDES_Cipher(const char* text, const char* key, bool decrypt)
    {
        output.clear();

        // ---- parse 10‑bit key -------------------------------------------------
        unsigned short key10 = 0;
        {
            int len = (int)strlen(key);
            for (int i = 0; i < 10; ++i) {
                key10 <<= 1;
                if (i < len && key[i] == '1') key10 |= 1;
            }
        }

        // ---- build the two round keys ----------------------------------------
        unsigned char sk1 = 0, sk2 = 0;
        generateSubKeys(key10, sk1, sk2);

        // ---- ENCRYPT ----------------------------------------------------------
        if (!decrypt)
        {
            /*──────── 1.  convert INPUT to raw bytes vector ―────*/
            std::vector<unsigned char> bytes;

            if (g_SDES_InMode == IO_LETTERS)
            {
                for (const char* p = text; *p; ++p) bytes.push_back((unsigned char)*p);
            }
            else
            {
                std::istringstream iss(text);
                std::string token;
                while (iss >> token)
                {
                    if (g_SDES_InMode == IO_DEC)           // decimal byte
                    {
                        int v = std::stoi(token);
                        bytes.push_back((unsigned char)(v & 0xFF));
                    }
                    else                                   // binary “01001100”
                    {
                        if (token.size() != 8) continue;
                        unsigned char v = 0;
                        for (char c : token) { v <<= 1; if (c == '1') v |= 1; }
                        bytes.push_back(v);
                    }
                }
            }

            /*──────── 2.  run S-DES on each byte ―──────────────*/
            std::vector<unsigned char> encBytes;
            encBytes.reserve(bytes.size());
            for (unsigned char b : bytes)
                encBytes.push_back(sdesEncryptByte(b, sk1, sk2, false));

            /*──────── 3.  format OUTPUT according to OutMode ―─*/
            std::ostringstream oss;
            for (size_t i = 0; i < encBytes.size(); ++i)
            {
                unsigned char v = encBytes[i];
                if (g_SDES_OutMode == IO_LETTERS)
                    oss << (char)v;
                else if (g_SDES_OutMode == IO_DEC)
                    oss << (int)v;
                else /* binary */
                {
                    for (int b = 7; b >= 0; --b) oss << (((v >> b) & 1) ? '1' : '0');
                }
                if (i + 1 != encBytes.size()) oss << ' ';   // separator
            }
            output = oss.str();
        }

        // ---- DECRYPT ----------------------------------------------------------
        else
        {
            /*──────── 1.  parse INPUT into cipher-bytes vector ―*/
            std::vector<unsigned char> cBytes;

            if (g_SDES_InMode == IO_LETTERS)
            {
                for (const char* p = text; *p; ++p) cBytes.push_back((unsigned char)*p);
            }
            else
            {
                std::istringstream iss(text);
                std::string token;
                while (iss >> token)
                {
                    if (g_SDES_InMode == IO_DEC)
                    {
                        int v = std::stoi(token);
                        cBytes.push_back((unsigned char)(v & 0xFF));
                    }
                    else
                    {
                        if (token.size() != 8) continue;
                        unsigned char v = 0;
                        for (char c : token) { v <<= 1; if (c == '1') v |= 1; }
                        cBytes.push_back(v);
                    }
                }
            }

            /*──────── 2.  decrypt each byte ―──────────────────*/
            std::ostringstream oss;
            for (size_t i = 0; i < cBytes.size(); ++i)
            {
                unsigned char dec = sdesEncryptByte(cBytes[i], sk1, sk2, true);

                if (g_SDES_OutMode == IO_LETTERS)
                    oss << (char)dec;
                else if (g_SDES_OutMode == IO_DEC)
                    oss << (int)dec;
                else
                {
                    for (int b = 7; b >= 0; --b) oss << (((dec >> b) & 1) ? '1' : '0');
                }
                if (i + 1 != cBytes.size()) oss << ' ';
            }
            output = oss.str();
        }
    }


} 
