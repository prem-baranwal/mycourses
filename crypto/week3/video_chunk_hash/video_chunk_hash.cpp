#include <iostream>
#include <cstdio>
#include <sys/stat.h>
#include <fcntl.h> 
#include <errno.h>

#include "cryptopp/cryptlib.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"


using namespace std;
using namespace CryptoPP;

const int BLOCK_SIZE = 1024;
std::string HexToBytes(const std::string& hex);
CryptoPP::HexEncoder encoder(new FileSink(std::cout));

int main(int argc, char const *argv[])
{
    string filename = "6.1.intro.mp4_download";
    //string filename = "sample_file";
    std::filesystem::path p = std::filesystem::current_path();
    p /= filename;
    int fileSize = std::filesystem::file_size(p);
    std::cout << "File size = " << fileSize << '\n';
    int no1KBlocks = int(fileSize/BLOCK_SIZE), lastblockSize = fileSize%BLOCK_SIZE;
    if(lastblockSize == 0) 
        lastblockSize = BLOCK_SIZE;
    std::cout<< no1KBlocks << ", "<< lastblockSize <<endl;

    ifstream fstream(filename.c_str(), ios::in | ios::binary);
    int currPos = fileSize - lastblockSize;
    fstream.seekg(currPos, ios::beg);

    std::string strToHash;
    FileSource fs(fstream, false, new StringSink(strToHash));
    fs.Pump(lastblockSize);
    //no need to do strToHash.append(prevDigest)

    SHA256 hash;
    std::string digest;
    while(!strToHash.empty())
    {
        //fs.Pump(BLOCK_SIZE);
        hash.Update((const CryptoPP::byte *)strToHash.data(), strToHash.size());
        digest.resize(hash.DigestSize());
        hash.Final((CryptoPP::byte *)&digest[0]);
        
        std::cout<<"Hash of Block at Pos "<< currPos << " is : \n";
        StringSource(digest, true, new Redirector(encoder));
        std::cout << std::endl;
        //std::cout<<"Hash: "<< digest <<std::endl;
        //prevDigest.assign(digest);

        strToHash.clear();
        hash.Restart();

        if(currPos >= BLOCK_SIZE){
            currPos -= BLOCK_SIZE;
            fstream.seekg(currPos, ios::beg);
            fs.Pump(BLOCK_SIZE);
            strToHash.append(digest);
            digest.clear();
        }
        else{
            break;
        }
    }

    std::cout << "Final Hash : \n";
    StringSource(digest, true, new Redirector(encoder));
    std::cout << std::endl;
    return 0;
}