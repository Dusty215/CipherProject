#include "Application.h"
#include "imgui.h"
#include <iostream>
#include <string>
#include <tchar.h>
#include <windows.h>
#include <vector>
#include <cctype>
#include <map>
#include <string>
#include <cctype>
#include <iostream>
#include <sstream>     
#include <windows.h>
#include <fstream>
#include <commdlg.h>      // common file dialogs
#include <filesystem>
#include <filesystem>
#include <fstream> // for automatic “*_enc.txt” naming (C++17)

namespace fs = std::filesystem;

// ----------------------------------------------------------------------------------------
// NAMESPACE: CipherP
// ----------------------------------------------------------------------------------------
namespace CipherP {

    // Forward declarations of all ciphers
    void Ceaser_Cipher(const char* text, int shift);
    void SDES_Cipher(const char* text, const char* key, bool decrypt); // "amply simplified DES"
    void MorseCode_Cipher(const char* text);

    // Helper for tooltips in ImGui
    static void HelpMarker(const char* desc)
    {
        ImGui::TextDisabled("(?)");
        if (ImGui::BeginItemTooltip())
        {
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
            ImGui::TextUnformatted(desc);
            ImGui::PopTextWrapPos();
            ImGui::EndTooltip();
        }
    }
    static bool OpenFileDialog(char* outPath, DWORD size)
    {
        OPENFILENAMEA ofn{ 0 };
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = nullptr;
        ofn.lpstrFilter = "Text Files\0*.txt\0All Files\0*.*\0";
        ofn.lpstrFile = outPath;
        ofn.nMaxFile = size;
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        return GetOpenFileNameA(&ofn);
    }

    static bool SaveFileDialog(char* outPath, DWORD size)
    {
        OPENFILENAMEA ofn{ 0 };
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = nullptr;
        ofn.lpstrFilter = "Text Files\0*.txt\0All Files\0*.*\0";
        ofn.lpstrFile = outPath;
        ofn.nMaxFile = size;
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        return GetSaveFileNameA(&ofn);
    }


    // If Docking is disabled
    static void ShowDockingDisabledMessage()
    {
        ImGuiIO& io = ImGui::GetIO();
        ImGui::Text("ERROR: Docking is not enabled! See Demo > Configuration.");
        ImGui::Text("Set io.ConfigFlags |= ImGuiConfigFlags_DockingEnable in your code, or ");
        ImGui::SameLine(0.0f, 0.0f);
        if (ImGui::SmallButton("click here"))
            io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    }

    // We'll store the ciphered output here
    static std::string output;

    // ------------------------------------------------------------------------------------
    // RenderUI: the main ImGui function
    // ------------------------------------------------------------------------------------
    void RenderUI()
    {
        ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
        ImGuiStyle& style = ImGui::GetStyle();

        // Buffers for user input
        static char Input[256] = "";  // Plain/cipher text
        static char SKey[256] = "";  // Single key (for Caesar, Morse)
        static char EKey[256] = "";  // 10-bit key for S-DES
        static char DKey[256] = "";  // Could be same as EKey if you want
        static bool ShowResults = false;
        static int selectedCipher = -1;  // 0=Caesar, 1=S-DES, 2=Morse
        // We also add a toggle for encrypt/decrypt if you want
        static bool doDecrypt = false;

        bool cipherCaesar = (selectedCipher == 0);
        bool cipherSDES = (selectedCipher == 1);
        bool cipherMorse = (selectedCipher == 2);
        static bool showSettings = false;
        static bool showAbout = false;
        static bool confirmExit = false;

        static char inputFilePath[MAX_PATH] = "";
        static char outputFilePath[MAX_PATH] = "";
        static std::string fileContent;          // raw bytes read from file
        static bool fileLoaded = false;
        static bool fileProcessed = false;

        // Main window
        ImGui::SetNextWindowSize(ImVec2(800, 600));
        ImGui::Begin("Encryption Algorithm", nullptr,
            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

        // Main menu bar
        if (ImGui::BeginMainMenuBar())
        {
            if (ImGui::BeginMenu("Options"))
            {
                if (ImGui::MenuItem("Settings")) showSettings = true;
                if (ImGui::MenuItem("Exit"))     confirmExit = true;
                ImGui::EndMenu();
            }

            if (ImGui::BeginMenu("Help"))
            {
                if (ImGui::MenuItem("Documentation"))
                {
                    // Directly open ImGui documentation
                    ShellExecuteA(0, 0, "https://github.com/ocornut/imgui", 0, 0, SW_SHOW);
                }

                if (ImGui::MenuItem("About"))
                {
                    // Directly open your site
                    ShellExecuteA(0, 0, "https://zainalamri.dev", 0, 0, SW_SHOW);
                }

                ImGui::EndMenu();
            }

            ImGui::EndMainMenuBar();
        }


        if (showSettings)
        {
            ImGui::Begin("Settings", &showSettings);

            static bool showBinary = true;
            static bool copyOnEncrypt = false;

            ImGui::Text("Preferences:");
            ImGui::Checkbox("Show binary format for S-DES", &showBinary);
            ImGui::Checkbox("Auto-copy result on Encrypt", &copyOnEncrypt);
            ImGui::Spacing();
            ImGui::TextDisabled("Note: These are placeholder settings.");

            ImGui::End();
        }
        if (confirmExit)
        {
            ImGui::OpenPopup("Confirm Exit?");
            confirmExit = false;
        }

        if (ImGui::BeginPopupModal("Confirm Exit?", NULL, ImGuiWindowFlags_AlwaysAutoResize))
        {
            ImGui::Text("Are you sure you want to exit?");
            ImGui::Separator();

            if (ImGui::Button("Yes", ImVec2(120, 0))) {
                exit(0);  // or use PostQuitMessage(0); on Windows
            }
            ImGui::SameLine();
            if (ImGui::Button("No", ImVec2(120, 0))) {
                ImGui::CloseCurrentPopup();
            }

            ImGui::EndPopup();
        }
        if (ImGui::BeginPopup("OpenDocumentation"))
        {
            ImGui::Text("Open ImGui Documentation?");
            if (ImGui::Button("Open")) {
                ShellExecuteA(0, 0, "https://github.com/ocornut/imgui", 0, 0, SW_SHOW);
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) {
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }

        // About
        if (showAbout)
        {
            ImGui::Begin("About", &showAbout, ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::Text("Encryption UI Project");
            ImGui::Text("Made by Zain Alamri");
            ImGui::Text("For more info, visit:");
            if (ImGui::Button("zainalamri.dev")) {
                ShellExecuteA(0, 0, "https://zainalamri.dev", 0, 0, SW_SHOW);
            }
            ImGui::End();
        }
        // Cipher selection
        if (ImGui::TreeNodeEx("Choose preferred cipher algorithm", ImGuiTreeNodeFlags_DefaultOpen))
        {
            ImGui::Spacing();
            ImGui::SeparatorText("Substitution Ciphers");

            // Caesar
            if (ImGui::Checkbox("Caesar Cipher", &cipherCaesar))
                selectedCipher = cipherCaesar ? 0 : -1;

            ImGui::SameLine();
            HelpMarker("Classic Caesar cipher, shifting letters by a fixed integer.");

            // Morse
            ImGui::SameLine();
            if (ImGui::Checkbox("Morse Code Cipher", &cipherMorse))
                selectedCipher = cipherMorse ? 2 : -1;

            ImGui::SameLine();
            HelpMarker("Morse code encodes letters as dots/dashes. Example only (encode-only).");

            ImGui::SeparatorText("Symmetric-Key Ciphers (Simplified)");

            // S-DES
            if (ImGui::Checkbox("S-DES (Simplified DES)", &cipherSDES))
                selectedCipher = cipherSDES ? 1 : -1;

            ImGui::SameLine();
            HelpMarker("A teaching cipher illustrating DES steps on 8-bit blocks with a 10-bit key.");

            ImGui::SeparatorText("Asymmetric-Key Ciphers");
            // Placeholder for RSA or others

            ImGui::TreePop();
        }

        // Text input
        ImGui::Text("Enter plain/cipher text:");
        ImGui::SetNextItemWidth(400);
        ImGui::InputText("##enter_text", Input, IM_ARRAYSIZE(Input));

        // A toggle for encrypt vs decrypt (especially for S-DES)
        ImGui::Checkbox("Decrypt Mode?", &doDecrypt);

        // Key inputs
        if (selectedCipher == 0)
        {
            // Caesar
            ImGui::Text("Enter numeric key (shift):");
            ImGui::SetNextItemWidth(150);
            ImGui::InputText("##caesar_key", SKey, IM_ARRAYSIZE(SKey));
        }
        else if (selectedCipher == 1)
        {
            // S-DES
            ImGui::Text("Enter 10-bit key (binary, e.g. '1010000010')");
            ImGui::SetNextItemWidth(150);
            ImGui::InputText("##sdes_key1", EKey, IM_ARRAYSIZE(EKey));

            
            
        }
        else if (selectedCipher == 2)
        {
            // Morse
         
        }

        // Button to run
        if (ImGui::Button("Encrypt/Decrypt"))
        {
            ShowResults = true;
            output.clear();

            if (selectedCipher == 0)
            {
                // Caesar
                int shift = 0;
                if (strlen(SKey) > 0)
                {
                    try { shift = std::stoi(SKey); }
                    catch (...) { shift = 0; }
                }
                // If decrypt mode, we can just do negative shift
                if (doDecrypt) shift = -shift;
                Ceaser_Cipher(Input, shift);
            }
            else if (selectedCipher == 1)
            {
                // S-DES
                // If no key provided, default to something
                if (strlen(EKey) == 0) strcpy(EKey, "1010000010");
                // For simplicity, we ignore DKey or unify them 
                // But let's use EKey if DKey is empty
                if (strlen(DKey) == 0) strcpy(DKey, EKey);

                // We'll run S-DES with EKey (or DKey). 
                // Typically they are the same for real S-DES. 
                // 'doDecrypt' changes subkey order inside the function.
                SDES_Cipher(Input, EKey, doDecrypt);
            }
            else if (selectedCipher == 2)
            {
                // Morse
                MorseCode_Cipher(Input, doDecrypt);
            }
        }

        ImGui::SeparatorText("File mode");

        if (ImGui::Button("Load text file…"))
        {
            if (OpenFileDialog(inputFilePath, MAX_PATH))
            {
                std::ifstream fin(inputFilePath, std::ios::binary);
                fileContent.assign((std::istreambuf_iterator<char>(fin)),
                    std::istreambuf_iterator<char>());
                fin.close();
                fileLoaded = true;
                fileProcessed = false;
            }
        }

        ImGui::SameLine();
        ImGui::TextDisabled("%s", fileLoaded ? inputFilePath : "no file");

        if (fileLoaded)
        {
            if (ImGui::Button("Encrypt / Decrypt file"))
            {
                output.clear();

                // --- run the selected cipher on fileContent ----------------------
                switch (selectedCipher)
                {
                case 0: {  // Caesar
                    int shift = 0;
                    try { shift = std::stoi(SKey); }
                    catch (...) {}
                    if (doDecrypt) shift = -shift;
                    Ceaser_Cipher(fileContent.c_str(), shift);
                } break;

                case 1: {  // S‑DES
                    if (strlen(EKey) == 0) strcpy(EKey, "1010000010");
                    SDES_Cipher(fileContent.c_str(), EKey, doDecrypt);
                } break;

                case 2: {  // Morse
                    MorseCode_Cipher(fileContent.c_str(), doDecrypt);
                } break;
                }

                // --- auto‑build output path  -------------------------------------
                namespace fs = std::filesystem;
                fs::path inPath(inputFilePath);
                std::string suffix = doDecrypt ? "_dec" : "_enc";
                fs::path outPath = inPath.parent_path() /
                    (inPath.stem().string() + suffix + inPath.extension().string());

                strcpy(outputFilePath, outPath.string().c_str());

                // --- write file ---------------------------------------------------
                std::ofstream fout(outPath, std::ios::binary);
                fout << output;
                fout.close();

                fileProcessed = true;
            }
        }

        if (fileProcessed)
        {
            if (ImGui::Button("Open output file"))
                ShellExecuteA(0, 0, outputFilePath, 0, 0, SW_SHOW);

            ImGui::SameLine();
            ImGui::TextDisabled("%s", outputFilePath);
        }

        // Show result
        if (ShowResults)
        {
            ImGui::Text("Result: %s", output.c_str());
        }

        // Performance stats
        ImGuiIO& io = ImGui::GetIO();
        ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
            ImGui::Spacing();
            ImGui::Text("Made by the best programmer in the world \n\nZain Alamri");

           

         ImGui::End();
    }

    // ------------------------------------------------------------------------------------
    // Caesar Cipher
    // ------------------------------------------------------------------------------------
    void Ceaser_Cipher(const char* text, int shift)
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

        // --- A‑Z → morse -------------------------------------------------------
        static const std::map<char, std::string> morseMap = {
            {'A', ".-"},   {'B', "-..."}, {'C', "-.-."}, {'D', "-.."},
            {'E', "."},    {'F', "..-."}, {'G', "--."},  {'H', "...."},
            {'I', ".."},   {'J', ".---"}, {'K', "-.-"},  {'L', ".-.."},
            {'M', "--"},   {'N', "-."},   {'O', "---"},  {'P', ".--."},
            {'Q', "--.-"}, {'R', ".-."},  {'S', "..."},  {'T', "-"},
            {'U', "..-"},  {'V', "...-"}, {'W', ".--"},  {'X', "-..-"},
            {'Y', "-.--"}, {'Z', "--.."}
        };

        // --- build reverse map once (morse → A‑Z) -----------------------------
        static std::map<std::string, char> reverseMap;
        if (reverseMap.empty())
            for (auto& kv : morseMap) reverseMap[kv.second] = kv.first;

        //-----------------------------------------------------------------------
        if (!decrypt)                // ---------- ENCRYPT ----------
        {
            for (int i = 0; text[i] != '\0'; ++i)
            {
                char c = text[i];
                if (std::isalpha(static_cast<unsigned char>(c)))
                {
                    char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                    output += morseMap.at(upper);
                    output += ' ';                    // letter separator
                }
                else if (c == ' ')                    // word break → "/"
                {
                    output += "/ ";
                }
                else
                {
                    // keep any other symbol unchanged
                    output.push_back(c);
                }
            }
        }
        else                         // ---------- DECRYPT ----------
        {
            std::istringstream iss(text);
            std::string token;

            while (iss >> token)                     // read next code
            {
                if (token == "/")                    // word break
                {
                    output += ' ';
                    continue;
                }
                auto it = reverseMap.find(token);
                if (it != reverseMap.end())
                    output.push_back(it->second);    // valid code
                else
                    output.push_back('?');           // unknown chunk
            }
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

    // Permutation functions
    static unsigned char permute8(unsigned char in, const int* table, int n)
    {
        // `in` is 8 bits, we produce 8 bits
        unsigned char out = 0;
        for (int i = 0; i < n; i++)
        {
            int bitPosition = table[i];
            unsigned char bit = (in >> bitPosition) & 1;
            out |= (bit << i);
        }
        return out;
    }

    // S-DES uses 10-bit key manipulation. We'll store it in a 16-bit to have space.
    static unsigned short permute10(unsigned short in, const int* table, int n)
    {
        unsigned short out = 0;
        for (int i = 0; i < n; i++)
        {
            int bitPosition = table[i];
            unsigned short bit = (in >> bitPosition) & 1;
            out |= (bit << i);
        }
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
        for (int i = 0; i < 8; i++)
        {
            int bitPos = P8[i];
            unsigned char bit = (combined >> bitPos) & 1;
            sk1 |= (bit << i);
        }

        // Next shift by 2 (from original 1 shift or from the new state?)
        left5 = leftShift5bits(left5, 2);
        right5 = leftShift5bits(right5, 2);
        combined = (left5 << 5) | (right5);

        // Apply P8 => subkey2
        unsigned char sk2 = 0;
        for (int i = 0; i < 8; i++)
        {
            int bitPos = P8[i];
            unsigned char bit = (combined >> bitPos) & 1;
            sk2 |= (bit << i);
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
        static const int EP[8] = { 3, 0, 1, 2, 1, 2, 3, 0 };
        unsigned char epVal = 0;
        for (int i = 0; i < 8; i++)
        {
            int bitPos = EP[i];
            unsigned char bit = (right4 >> bitPos) & 1;
            epVal |= (bit << i);
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
        static const int P4[4] = { 1, 3, 2, 0 };
        unsigned char p4Val = 0;
        for (int i = 0; i < 4; i++)
        {
            int bitPos = P4[i];
            unsigned char bit = (combinedS >> bitPos) & 1;
            p4Val |= (bit << i);
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
            for (int i = 0; text[i] != '\0'; ++i)
            {
                unsigned char plain = static_cast<unsigned char>(text[i]);
                unsigned char enc = sdesEncryptByte(plain, sk1, sk2, false);

                /* convert byte → “01010101” */
                char bin[9];
                for (int b = 7; b >= 0; --b)
                    bin[7 - b] = ((enc >> b) & 1) ? '1' : '0';
                bin[8] = '\0';

                output += bin;
                output += ' ';                 // visual separator
            }
        }
        // ---- DECRYPT ----------------------------------------------------------
        else
        {
            std::istringstream iss(text);      // expect “01010101 11100011 …”
            std::string token;

            while (iss >> token)               // grab next 8‑bit chunk
            {
                if (token.size() != 8) continue;

                unsigned char byte = 0;
                for (char c : token)
                {
                    byte <<= 1;
                    if (c == '1') byte |= 1;
                }
                unsigned char dec = sdesEncryptByte(byte, sk1, sk2, true);
                output.push_back(static_cast<char>(dec));
            }
        }
    }


} // namespace CipherP
