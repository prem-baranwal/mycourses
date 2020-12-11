#include <iostream>

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
    string filename = "6.2.birthday.mp4_download";
    string str;
    ifstream fstream(filename.c_str(), ios::in | ios::binary);
    FileSource file(fstream, false, new StringSink(str));
    //std::cout<<str;
    int i = 0;
    while(!file.GetStream()->eof() && !file.SourceExhausted())
    {
        file.Pump(1024);
        std::cout<<"Block "<< i++ << ": " 
        //<< str 
            <<std::endl;
        str.clear();
    }
    return 0;
}