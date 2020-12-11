#include <iostream>
#include <iomanip>
#include <cstdio>

#include "cryptopp/rijndael.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/hrtimer.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"


using namespace std;
using namespace CryptoPP;

std::string HexToBytes(const std::string& hex);
std::string DecryptUsingAesCTRMode(CryptoPP::byte key[], int keySize, CryptoPP::byte iv[], std::string cipher);

int main(int argc, char const *argv[])
{
    // Key and IV setup
    // AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
    // bit). This key is secretly exchanged between two parties before communication begins. 
    // DEFAULT_KEYLENGTH= 16 bytes
    CryptoPP::byte iv[ CryptoPP::AES::BLOCKSIZE ] = 
        //{0x69, 0xdd, 0xa8, 0x45, 0x5c, 0x7d, 0xd4, 0x25, 0x4b, 0xf3, 0x53, 0xb7, 0x73, 0x30, 0x4e, 0xec};
        {0x77, 0x0b, 0x80, 0x25, 0x9e, 0xc3, 0x3b, 0xeb, 0x25, 0x61, 0x35, 0x8a, 0x9f, 0x2d, 0xc6, 0x17};
    CryptoPP::byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ] = 
        {0x36, 0xf1, 0x83, 0x57, 0xbe, 0x4d, 0xbd, 0x77, 0xf0, 0x50, 0x51, 0x5c, 0x73, 0xfc, 0xf9, 0xf2};

    // String and Sink setup
    std::string plaintext = "Now is the time for all the races of men, dwarves and elves to unite...";
    std::string ciphertext;
    std::string decryptedtext;
    std::cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
    std::cout << plaintext << std::endl << std::endl;

    // Create Cipher Text
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CTR_Mode_ExternalCipher::Encryption ctrEncryption(aesEncryption, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(ctrEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() );
    stfEncryptor.MessageEnd(); 
    // Pretty print cipher text
    // string encodedCiphertextO;
    // CryptoPP::StringSource ssO( ciphertext, true, new CryptoPP::HexEncoder(new StringSink( encodedCiphertextO )) // HexEncoder
    //     ); 
    // cout << "Original Hex-Encoded Cipher Text: " << endl << encodedCiphertextO << endl;
    // std::cout << std::endl;

    string inputCiphertext;
    std::string encodedCiphertextInput = "e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";
    CryptoPP::StringSource ssInput( encodedCiphertextInput, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink( inputCiphertext )) // HexDecoder
        ); 

    // CryptoPP::AES::Encryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    // CTR_Mode_ExternalCipher::Decryption ctrDecryption(aesDecryption, iv);
    // CryptoPP::StreamTransformationFilter stfDecryptor(ctrDecryption, new CryptoPP::StringSink( decryptedtext ) );
    // //stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    // stfDecryptor.MessageEnd();
    decryptedtext = DecryptUsingAesCTRMode(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv, inputCiphertext);

	// Dump Decrypted Text
    std::cout << "Decrypted Input Text (" << strlen(decryptedtext.c_str()) << "): " << std::endl;
    std::cout << decryptedtext << std::endl << std::endl;
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

std::string DecryptUsingAesCTRMode(CryptoPP::byte key[], int keySize, CryptoPP::byte iv[], std::string cipher){
    string plaintext;
    try{
		CTR_Mode<AES>::Decryption d;
		d.SetKeyWithIV(key, keySize, iv);

		// The StreamTransformationFilter removes padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(plaintext)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e){
		cerr << e.what() << endl;
		exit(1);
	}

    return plaintext;
}