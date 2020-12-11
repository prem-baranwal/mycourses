#include <iostream>
#include <iomanip>
#include <cstdio>

#include "cryptopp/rijndael.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/hrtimer.h"
#include "cryptopp/osrng.h"
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"


using namespace std;
using namespace CryptoPP;

std::string HexToBytes(const std::string& hex);

int main(int argc, char const *argv[])
{
    // Key and IV setup
    // AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
    // bit). This key is secretly exchanged between two parties before communication begins. 
    // DEFAULT_KEYLENGTH= 16 bytes
    CryptoPP::byte iv[ CryptoPP::AES::BLOCKSIZE ] = 
        //{0x4c, 0xa0, 0x0f, 0xf4, 0xc8, 0x98, 0xd6, 0x1e, 0x1e, 0xdb, 0xf1, 0x80, 0x06, 0x18, 0xfb, 0x28};
        {0x5b, 0x68, 0x62, 0x9f, 0xeb, 0x86, 0x06, 0xf9, 0xa6, 0x66, 0x76, 0x70, 0xb7, 0x5b, 0x38, 0xa5};
    CryptoPP::byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ] = 
        {0x14, 0x0b, 0x41, 0xb2, 0x2a, 0x29, 0xbe, 0xb4, 0x06, 0x1b, 0xda, 0x66, 0xb6, 0x74, 0x7e, 0x14};
    
    // String and Sink setup
    std::string plaintext = "Now is the time for all the races of men, dwarves and elves to come to the aide...";
    std::string ciphertext;
    std::string decryptedtext;
    std::cout << std::endl << std::endl;

    // Create Cipher Text
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() );
    stfEncryptor.MessageEnd(); 

    //std::string ciphertext2 = "28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
    std::string ciphertext2 = "b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
    
    ciphertext = HexToBytes(ciphertext2);
    // Dump Cipher Text
    // std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
    // for( int i = 0; i < ciphertext.size(); i++ ) {
    //     std::cout << "0x" << std::hex << (0xFF & static_cast<CryptoPP::byte>(ciphertext[i])) << " ";
    // }
    // std::cout << std::endl << std::endl;


    // Decrypt
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    stfDecryptor.MessageEnd();

	// Dump Decrypted Text
    const char *ptr = decryptedtext.c_str();
    printf("Decrypted Text: %d %d %d %d \n", (int)ptr[0], (int)ptr[1], (int)ptr[2], (int)ptr[3]);
    std::cout << "Decrypted Text (" << strlen(decryptedtext.c_str()) << "): " << std::endl;
    std::cout << decryptedtext;
    std::cout << std::endl;

    for( int i = 0; i < 16; i++ ) {
        std::cout << "0x" << std::hex << (0xFF & static_cast<CryptoPP::byte>(decryptedtext[i])) << " ";
    }
    std::cout << std::endl;
    return 0;
}


std::string HexToBytes(const std::string& hex) {
  std::string bytes;
  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    char byte = (char) strtol(byteString.c_str(), NULL, 16);
    bytes.append(1, byte);
  }
  return bytes;
}
