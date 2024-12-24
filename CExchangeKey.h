#include <iostream>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdh.h>
#include <openssl/x509.h>

class ECKeyExchange {
public:
    ECKeyExchange(const std::string &ca_cert_path);
    ~ECKeyExchange();

    void generateKeys();
    std::string getPublicKey();
    bool validatePublicKey(const std::string &other_public_key);
    std::string computeSharedSecret(const std::string &other_public_key);
    void printKeys();                  // Вывод ключей субъекта
    void printCertificateDetails();   // Вывод данных сертификата

private:
    EC_GROUP *curve = nullptr;
    EC_KEY *private_key = nullptr;
    EC_POINT *public_key = nullptr;
    X509 *ca_cert = nullptr; // Сертификат CA
};
