/*
    Network Next. Copyright © 2017 - 2024 Network Next, Inc.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following 
    conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions 
       and the following disclaimer in the documentation and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote 
       products derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
    IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
    OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

//#include "networknext/next.h"
//#include "networknext/next_tests.h"
#include "sodium/sodium.h"
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <vector>

int main()
{
    //next_quiet( true );
    //next_config_t config;
    //next_default_config(&config);
    //config.disable_autodetect = true;
    //config.disable_network_next = true;
    //if ( next_init( NULL, &config ) != NEXT_OK )
    //{
    //    printf( "error: failed to initialize network next\n" );
    //}
    //
    //printf( "\nRunning SDK tests:\n\n" );
    //
    //next_run_tests();
    //
    //next_term();
    //
    //printf( "\n" );
    //
    //fflush( stdout );
    unsigned char key[crypto_secretbox_KEYBYTES];
    crypto_secretbox_keygen(key);

    // Store this key securely (e.g., in a configuration file or key management service).
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    const unsigned char* plaintext = reinterpret_cast<const unsigned char*>("your save data here");
    size_t plaintext_len = strlen(reinterpret_cast<const char*>(plaintext));
    
    std::vector<uint8_t> cipherText(plaintext_len + crypto_secretbox_MACBYTES);

    if (crypto_secretbox_easy(cipherText.data(), plaintext, plaintext_len, nonce, key) != 0)
    {
        std::printf("error: failed to encrypt data\n");
		return 1;
    }

    {
        // Save `nonce` and `ciphertext` to the save file
        std::ofstream saveFile("savefile.dat", std::ios::binary);
        saveFile.write(reinterpret_cast<const char*>(nonce), sizeof nonce);
        saveFile.write(reinterpret_cast<const char*>(cipherText.data()), cipherText.size());
    }
   
    unsigned char stored_nonce[crypto_secretbox_NONCEBYTES];
    std::vector<uint8_t> stored_ciphertext(cipherText.size());
    std::ifstream saveFile("savefile.dat", std::ios::binary);
    saveFile.read(reinterpret_cast<char*>(stored_nonce), sizeof stored_nonce);
    saveFile.read(reinterpret_cast<char*>(stored_ciphertext.data()), stored_ciphertext.size());

    std::vector<uint8_t> decrypted(cipherText.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(decrypted.data(), stored_ciphertext.data(), cipherText.size(), stored_nonce, key) != 0)
    {
        std::printf("error: failed to decrypt data\n");
		return 2;
    }

    return 0;
}
