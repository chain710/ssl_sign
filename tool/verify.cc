#include <fstream>
#include <string>
#include <stdio.h>
#include "ssl_sign.h"

using namespace std;

int main(int argc, char** argv)
{
    // cmd privatekey input output
    if (argc < 4)
    {
        printf("usage: %s pubkeyfile input sigfile\n", argv[0]);
        return 0;
    }

    InitSSL();

    // read input file
    fstream fin(argv[2], ios_base::in|ios_base::binary);
    if (!fin.is_open())
    {
        printf("input file %s not found!\n", argv[2]);
        return 0;
    }

    string strin((istreambuf_iterator<char>(fin)), istreambuf_iterator<char>());
    fin.close();

    // read sig
    fstream fsig(argv[3], ios_base::in|ios_base::binary);
    if (!fsig.is_open())
    {
        printf("sigfile file %s not found!\n", argv[2]);
        return 0;
    }

    string strsig((istreambuf_iterator<char>(fsig)), istreambuf_iterator<char>());
    fsig.close();

    SSLSignature sig;
    try
    {
        sig.load_from_bytes(strsig.c_str(), strsig.size());

        SSLPublicKey pubkey;
        pubkey.load_from_keyfile(argv[1]);

        bool succ = sig.verify(pubkey, strin.c_str(), strin.length());
        printf("verify %s\n", succ? "succ": "fail");
    }
    catch (exception& e)
    {
        printf("sign error %s\n", e.what());
        return -1;
    }

    return 0;
}


