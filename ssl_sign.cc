#include "ssl_sign.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <string.h>

using namespace std;

template<typename T>
struct Deleter
{
    void operator() (T* d)
    {
        delete d;
    }
};

template<>
struct Deleter<BIO>
{
    void operator() (BIO* d)
    {
        BIO_free_all(d);
    }
};

template<>
struct Deleter<EVP_PKEY>
{
    void operator() (EVP_PKEY* d)
    {
        EVP_PKEY_free(d);
    }
};

template<>
struct Deleter<X509>
{
    void operator() (X509* d)
    {
        X509_free(d);
    }
};

template<>
struct Deleter<EVP_MD_CTX>
{
    void operator() (EVP_MD_CTX* d)
    {
        EVP_MD_CTX_cleanup(d);
    }
};

// simple unique ptr, not support [] yet, no assign, no copy-cons
template <typename T, typename D = Deleter<T> >
class simple_ptr
{
public:
    simple_ptr(T* d):
        ptr_(d)
    {

    }
    ~simple_ptr()
    {
        reset(NULL);
    }

    // Releases the ownership of the managed object
    T* release()
    {
        T* ret = ptr_;
        ptr_ = NULL;
        return ret;
    }

    // Replaces the managed object.
    void reset(T* d)
    {
        if (d == ptr_)
        {
            // same object, do nothing
            return;
        }

        T* old = ptr_;
        ptr_ = d;
        if (old)
        {
            D()(old);
        }
    }

    T* get()
    {
        return ptr_;
    }

    operator T*()
    {
        return ptr_;
    }

private:
    simple_ptr(const simple_ptr&) {}
    simple_ptr& operator = (const simple_ptr&) {}

    T* ptr_;
};

SSLKey::SSLKey():key_(NULL)
{
}

SSLKey::~SSLKey()
{
    if (key_)
    {
        EVP_PKEY_free(key_);
        key_ = NULL;
    }
}


void SSLPublicKey::load_from_keyfile( const std::string& keyfile_path )
{
    simple_ptr<BIO> bio(BIO_new(BIO_s_file()));
    if (NULL == bio)
    {
        throw SSLException();
    }

    int ret = BIO_read_filename(bio, keyfile_path.c_str());
    if (0 == ret)
    {
        throw SSLException();
    }

    key_ = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (NULL == key_)
    {
        throw SSLException();
    }
}

void SSLPublicKey::load_from_cert( const std::string& cert_path )
{
    simple_ptr<BIO> bio(BIO_new(BIO_s_file()));
    if (NULL == bio)
    {
        throw SSLException();
    }

    int ret = BIO_read_filename(bio, cert_path.c_str());
    if (0 == ret)
    {
        throw SSLException();
    }

    simple_ptr<X509> cert(PEM_read_bio_X509(bio, NULL, 0, NULL));
    if (NULL == cert) 
    {
        throw SSLException();
    }

    key_ = X509_get_pubkey(cert);
    if (NULL == key_)
    {
        throw SSLException();
    }
}

void InitSSL()
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

void SSLPrivateKey::load_from_keyfile( const std::string& cert_path )
{
    simple_ptr<BIO> bio(BIO_new(BIO_s_file()));
    if (NULL == bio)
    {
        throw SSLException();
    }

    int ret = BIO_read_filename(bio, cert_path.c_str());
    if (0 == ret)
    {
        throw SSLException();
    }

    key_ = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (NULL == key_)
    {
        throw SSLException();
    }
}

SSLSignature::SSLSignature():
    digest_type_(EVP_sha1()), 
    sig_(NULL), 
    sig_len_(0),
    used_len_(0)
{

}

SSLSignature::~SSLSignature()
{
    delete_sigbuf();
}

void SSLSignature::set_digest_type( const std::string& name )
{
    digest_type_ = EVP_get_digestbyname(name.c_str());
    if (NULL == digest_type_)
    {
        digest_type_ = EVP_sha1();
    }
}

void SSLSignature::build_from( SSLPrivateKey& privkey, const void* data, size_t data_len )
{
    EVP_MD_CTX ctx;
    simple_ptr<EVP_MD_CTX> ctx_wrapper(&ctx);
    int ret;

    size_t max_sig_len = EVP_PKEY_size(privkey.get_key());
    if (sig_len_ < max_sig_len)
    {
        delete_sigbuf();
        // create new sig buf
        sig_ = new unsigned char[max_sig_len];
        if (NULL == sig_)
        {
            throw SSLException("alloc sig buf failed");
        }

        sig_len_ = max_sig_len;
    }

    EVP_MD_CTX_init(&ctx);
    EVP_SignInit(&ctx, digest_type_);
    ret = EVP_SignUpdate(&ctx, data, data_len);
    if (0 == ret)
    {
        throw SSLException();
    }

    used_len_ = 0;
    ret = EVP_SignFinal(&ctx, sig_, &used_len_, privkey.get_key());
    if (0 == ret)
    {
        throw SSLException();
    }
}

bool SSLSignature::verify( SSLPublicKey& pubkey, const void* data, size_t data_len )
{
    EVP_MD_CTX ctx;
    simple_ptr<EVP_MD_CTX> ctx_wrapper(&ctx);
    int ret;

    if (NULL == sig_)
    {
        throw SSLException("null signature");
    }

    EVP_MD_CTX_init(&ctx);
    ret = EVP_VerifyInit(&ctx, digest_type_);
    if (0 == ret)
    {
        throw SSLException();
    }
    
    ret = EVP_VerifyUpdate(&ctx, data, data_len);
    if (0 == ret)
    {
        throw SSLException();
    }

    ret = EVP_VerifyFinal(&ctx, sig_, used_len_, pubkey.get_key());
    if (ret < 0)
    {
        throw SSLException();
    }

    return 1 == ret;
}

void SSLSignature::delete_sigbuf()
{
    if (sig_)
    {
        delete []sig_;
        sig_ = NULL;
    }

    sig_len_ = 0;
}

void SSLSignature::load_from_bytes( const void* sig, size_t sig_len )
{
    sig_ = new unsigned char[sig_len];
    if (NULL == sig_)
    {
        throw SSLException("alloc sig buf failed");
    }

    sig_len_ = sig_len;
    used_len_ = sig_len;
    memcpy(sig_, sig, used_len_);
}

SSLException::SSLException(int err_code) throw()
{
    if (err_code < 0)
    {
        // get lastest errorcode
        err_code = ERR_peek_last_error();
    }

    char tmp_msg[512];
    ERR_error_string_n(err_code, tmp_msg, sizeof(tmp_msg));
    errmsg_ = tmp_msg;
}
