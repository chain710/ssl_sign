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
        printf("usage: %s privatekeyfile input output\n", argv[0]);
        return 0;
    }

    InitSSL();

    fstream fin(argv[2], ios_base::in|ios_base::binary);
    if (!fin.is_open())
    {
        printf("input file %s not found!\n", argv[2]);
        return 0;
    }

    // read all data
    string strin((istreambuf_iterator<char>(fin)), istreambuf_iterator<char>());
    fin.close();

    SSLSignature sig;
    try
    {
        SSLPrivateKey privkey;
        privkey.load_from_keyfile(argv[1]);

        sig.build_from(privkey, strin.c_str(), strin.length());
    }
    catch (exception& e)
    {
    	printf("sign error %s\n", e.what());
        return -1;
    }

    // write sig to file
    fstream fout(argv[3], ios_base::binary|ios_base::trunc|ios_base::out);
    if (!fout.is_open())
    {
        printf("output file open failed\n");
        return -1;
    }
    fout.write((const char*)sig.sig_buf(), sig.sig_size());
    fout.close();
    return 0;
}


