#include <iostream>
#include <iomanip>

#include "cryptopp/cryptlib.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"


using namespace std;
using namespace CryptoPP;

std::string HexToBytes(const std::string& hex);
CryptoPP::HexEncoder encoder(new FileSink(std::cout));

int main(int argc, char const *argv[])
{
    SHA256 hash;	
    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash.DigestSize() << std::endl;
    std::cout << "Block size: " << hash.BlockSize() << std::endl;
    std::string msg = "Yoda said Luke, Do or do not. There is no try. "
                    "You must unlearn what you have learned. "
                    "Named must be your fear before banish it you can."
                    "Fear is the path to the dark side."
                    "The greatest teacher, failure is."
                    "Pass on what you have learned.";
    std::string digest;
    hash.Update((const CryptoPP::byte *)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte *)&digest[0]);

    std::cout << "Message: " << msg << std::endl;
    std::cout << "Digest (" << hash.DigestSize() << "): ";
    StringSource(digest, true, new Redirector(encoder));
    std::cout << std::endl;


    // string decryptedtext="A0109XBC3365A7DDDD";
    // for( int i = 0; i < 16; i++ ) {
    //     std::cout << "0x" << std::hex << (0xFF & static_cast<CryptoPP::byte>(decryptedtext[i])) << " ";
    // }
    // std::cout << std::endl;
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
