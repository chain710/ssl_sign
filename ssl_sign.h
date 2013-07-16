#include <string>
#include <openssl/evp.h>
#include <exception>

class SSLException: public std::exception
{
public:
    SSLException(int err_code = -1) throw();
    SSLException(const char* msg) throw() { errmsg_ = msg; }
    ~SSLException() throw() {}
    const char* what() const throw() { return errmsg_.c_str(); }
private:
    std::string errmsg_;
};

class SSLKey
{
public:
    SSLKey();
    virtual ~SSLKey();
    
    // load from pem key
    virtual void load_from_keyfile(const std::string& cert_path) = 0;
    const EVP_PKEY* get_key() const { return key_; }
    EVP_PKEY* get_key() { return key_; }
protected:
    EVP_PKEY* key_;
private:
    SSLKey(const SSLKey& c) {}
};

class SSLPublicKey: public SSLKey
{
public:
    SSLPublicKey():SSLKey() {}
    // load from pem cert
    void load_from_keyfile(const std::string& keyfile_path);
    void load_from_cert(const std::string& cert_path);
private:
    SSLPublicKey(const SSLPublicKey& c) {}
};

class SSLPrivateKey: public SSLKey
{
public:
    SSLPrivateKey():SSLKey() {}
    void load_from_keyfile(const std::string& cert_path);
private:
    SSLPrivateKey(const SSLPrivateKey& c) {}
};

class SSLSignature
{
public:
    SSLSignature();
    ~SSLSignature();
    // set digest type, default sha1 (md5|-md4|-md2|-sha1|-sha|-mdc2|-ripemd160|-dss1)
    void set_digest_type(const std::string& name);
    // build from data
    void build_from(SSLPrivateKey& privkey, const void* data, size_t data_len);
    void load_from_bytes(const void* sig, size_t sig_len);
    // verify signature with data, throw exception if error
    bool verify(SSLPublicKey& pubkey, const void* data, size_t data_len);
    const unsigned char* sig_buf() const { return sig_; }
    unsigned int sig_size() const { return used_len_; }
private:
    SSLSignature(const SSLSignature& c) {}
    void delete_sigbuf();
    const EVP_MD* digest_type_;
    unsigned char* sig_;
    size_t sig_len_;
    unsigned int used_len_;
};

void InitSSL();
