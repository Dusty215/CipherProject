#pragma once
namespace CipherP {

    void RenderUI();

    void Ceaser_Cipher(int text, int key);
    void DES_Cipher(int Text, int key);
    void MorseCode_Cipher(const char* text, bool decrypt);

}
