 #include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <memory>
#include <cstring>

// ===================================================================
// 1) Генерация корневого (CA) сертификата (самоподписанного)
// ===================================================================
std::pair<X509*, EVP_PKEY*> generateCA()
{
    // 1. Генерируем ключ CA (RSA или EC).
    //   Для демонстрации — пусть будет RSA (часто УЦ используют RSA).
    //   Можно при желании сделать EC_KEY для CA, но RSA — привычнее.

    EVP_PKEY* caKey = EVP_PKEY_new();
    if(!caKey) {
        throw std::runtime_error("EVP_PKEY_new() failed");
    }

    // Сгенерируем RSA 2048
    RSA* r = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if(!r) {
        EVP_PKEY_free(caKey);
        throw std::runtime_error("RSA_generate_key failed");
    }
    if(!EVP_PKEY_assign_RSA(caKey, r)) {
        // EVP_PKEY_assign_RSA берет на себя r при успехе
        RSA_free(r);
        EVP_PKEY_free(caKey);
        throw std::runtime_error("EVP_PKEY_assign_RSA failed");
    }

    // 2. Создаём самоподписанный X.509
    X509* caCert = X509_new();
    if(!caCert) {
        EVP_PKEY_free(caKey);
        throw std::runtime_error("X509_new() failed");
    }

    // Сериал
    ASN1_INTEGER_set(X509_get_serialNumber(caCert), 1);

    // Срок действия (1 год)
    X509_gmtime_adj(X509_get_notBefore(caCert), 0);
    X509_gmtime_adj(X509_get_notAfter(caCert), 31536000L);

    // Устанавливаем публичный ключ CA
    X509_set_pubkey(caCert, caKey);

    // subject/issuer name
    X509_NAME* name = X509_get_subject_name(caCert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (unsigned char*)"RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (unsigned char*)"Test Root CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)"RootCA", -1, -1, 0);

    // issuer = subject (самоподписанный)
    X509_set_issuer_name(caCert, name);

    // Подписываем сертификат CA
    if(!X509_sign(caCert, caKey, EVP_sha256())) {
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        throw std::runtime_error("X509_sign(CA) failed");
    }

    return std::make_pair(caCert, caKey);
}

// ===================================================================
// 2) Генерация ECC-ключа для субъекта (A или B)
// ===================================================================
EVP_PKEY* generateECKey(int nid = NID_X9_62_prime256v1)
{
    // Создаём ключ
    EVP_PKEY* pkey = EVP_PKEY_new();
    if(!pkey) {
        throw std::runtime_error("EVP_PKEY_new failed");
    }

    EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
    if(!ec) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    }
    if(!EC_KEY_generate_key(ec)) {
        EC_KEY_free(ec);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EC_KEY_generate_key failed");
    }

    if(!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
        EC_KEY_free(ec);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_assign_EC_KEY failed");
    }

    return pkey;
}

// ===================================================================
// 3) Выпуск X.509-сертификата для субъекта, подписанный УЦ
// ===================================================================
X509* generateCertSignedByCA(EVP_PKEY* subjectKey,
                             X509* caCert, EVP_PKEY* caKey,
                             const char* subjectCN)
{
    // 1. Создаём "пустой" X.509
    X509* cert = X509_new();
    if(!cert) throw std::runtime_error("X509_new failed");

    // серийный номер, срок действия
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 100); // условно
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    // Записываем публичный ключ субъекта
    X509_set_pubkey(cert, subjectKey);

    // Имя субъекта
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (unsigned char*)"RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (unsigned char*)"Test Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)subjectCN, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);

    // Имя издателя => берем из CA
    X509_set_issuer_name(cert, X509_get_subject_name(caCert));

    // Подписываем сертификат приватным ключом CA
    if(!X509_sign(cert, caKey, EVP_sha256())) {
        X509_free(cert);
        throw std::runtime_error("X509_sign(subject) failed");
    }

    return cert;
}

// ===================================================================
// 4) Проверка сертификата `cert` против корневого `caCert`
// ===================================================================
bool verifyCertificate(X509* cert, X509* caCert)
{
    // Создаём X509_STORE, добавляем туда caCert
    X509_STORE* store = X509_STORE_new();
    if(!store) return false;
    if(1 != X509_STORE_add_cert(store, caCert)) {
        X509_STORE_free(store);
        return false;
    }

    // Создаём контекст, «загружаем» туда cert
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if(!ctx) {
        X509_STORE_free(store);
        return false;
    }

    if(1 != X509_STORE_CTX_init(ctx, store, cert, nullptr)) {
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return false;
    }

    // Запускаем проверку
    int rc = X509_verify_cert(ctx);

    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);

    return (rc == 1); // 1 => верификация OK
}

// ===================================================================
// 5) Извлечь EC_KEY из X.509
// ===================================================================
EC_KEY* getECKeyFromCert(X509* cert)
{
    EVP_PKEY* pk = X509_get_pubkey(cert);
    if(!pk) return nullptr;

    EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pk);
    // Не освобождаем pk, т.к. X509_get_pubkey() возвращает новый объект EVP_PKEY,
    // но он связан с cert. (В новых версиях OpenSSL нужно аккуратно.)
    // Если нужно, делаем EVP_PKEY_free(pk), но тогда ec будет висеть в воздухе.
    // Для демонстрации оставим так.
    return ec;
}

// ===================================================================
// 6) Функция ECDH: вычислить общий секрет (static ECDH)
//    subjectPrivKey = ключ участника (приватный)
//    peerPubKey     = публичный ключ собеседника
// ===================================================================
std::vector<unsigned char> computeECDH(EVP_PKEY* subjectPrivKey, EVP_PKEY* peerPubKey)
{
    // Получаем EC_KEY участника
    EC_KEY* ecSubj = EVP_PKEY_get0_EC_KEY(subjectPrivKey);
    if(!ecSubj) {
        throw std::runtime_error("computeECDH: no EC_KEY for subject");
    }

    // Получаем EC_KEY собеседника (только публичная часть)
    EC_KEY* ecPeer = EVP_PKEY_get0_EC_KEY(peerPubKey);
    if(!ecPeer) {
        throw std::runtime_error("computeECDH: no EC_KEY for peer");
    }

    const EC_POINT* peerPoint = EC_KEY_get0_public_key(ecPeer);
    if(!peerPoint) {
        throw std::runtime_error("computeECDH: peerPoint is null");
    }

    // Вычисляем общий секрет: ECDH_compute_key
    // Нужно знать размер в байтах: размер = (field_bits + 7)/8.
    const EC_GROUP* grp = EC_KEY_get0_group(ecSubj);
    int fieldSize = EC_GROUP_get_degree(grp);
    int secretSize = (fieldSize+7)/8;

    std::vector<unsigned char> secret(secretSize);

    int ret = ECDH_compute_key(secret.data(), secretSize, peerPoint, ecSubj, nullptr);
    if(ret <= 0) {
        throw std::runtime_error("ECDH_compute_key failed");
    }
    // ret = реальное число байт
    secret.resize(ret);

    return secret;
}

// ===================================================================
// 6) Утилита для вывода PEM-сертификата (или ключа) в stdout
// ===================================================================
inline void printCertificatePEM(X509* cert, const char* title)
{
    std::cout << "=== " << title << " ===\n";
    PEM_write_X509(stdout, cert);
    std::cout << "========================\n\n";
}

inline void printPublicKeyPEM(EVP_PKEY* pkey, const char* title)
{
    std::cout << "=== " << title << " ===\n";
    PEM_write_PUBKEY(stdout, pkey);
    std::cout << "========================\n\n";
}

inline void printPrivateKeyPEM(EVP_PKEY* pkey, const char* title)
{
    std::cout << "=== " << title << " ===\n";
    // Без шифрования (nullptr), ВНИМАНИЕ: unsafe
    PEM_write_PrivateKey(stdout, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    std::cout << "========================\n\n";
}

// ===================================================================
// main()
// ===================================================================
int main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        // ---------------------------------------------------------------
        // 1) Генерируем корневой УЦ (RSA) c самоподписанным cert
        // ---------------------------------------------------------------
        auto [caCert, caKey] = generateCA();
        std::cout << "[*] CA certificate & key generated.\n\n";

        // Печатаем сертификат CA
        printCertificatePEM(caCert, "CA Certificate");

        // ---------------------------------------------------------------
        // 2) Генерируем ECC-ключ для A, подписываем УЦ => A_cert
        // ---------------------------------------------------------------
        EVP_PKEY* A_key = generateECKey(); // A's EC key
        X509* A_cert = generateCertSignedByCA(A_key, caCert, caKey, "Alice");
        std::cout << "[*] A's certificate generated.\n\n";

        // Выводим публичный и приватный ключ A (в PEM)
        printPublicKeyPEM(A_key, "A's PUBLIC KEY");
        printPrivateKeyPEM(A_key, "A's PRIVATE KEY");

        // Печатаем сертификат A
        printCertificatePEM(A_cert, "A's Certificate");

        // ---------------------------------------------------------------
        // 3) Генерируем ECC-ключ для B, подписываем УЦ => B_cert
        // ---------------------------------------------------------------
        EVP_PKEY* B_key = generateECKey();
        X509* B_cert = generateCertSignedByCA(B_key, caCert, caKey, "Bob");
        std::cout << "[*] B's certificate generated.\n\n";

        // Выводим публичный и приватный ключ B
        printPublicKeyPEM(B_key, "B's PUBLIC KEY");
        printPrivateKeyPEM(B_key, "B's PRIVATE KEY");

        // Печатаем сертификат B
        printCertificatePEM(B_cert, "B's Certificate");

        // ---------------------------------------------------------------
        // 4) A проверяет B_cert (подписан ли тем же CA), B проверяет A_cert
        // ---------------------------------------------------------------
        bool okA = verifyCertificate(B_cert, caCert);
        bool okB = verifyCertificate(A_cert, caCert);

        if(!okA) {
            std::cerr << "[A] Verification of B_cert failed!\n";
        }
        if(!okB) {
            std::cerr << "[B] Verification of A_cert failed!\n";
        }
        if(!okA || !okB) {
            throw std::runtime_error("Certificate verification failed");
        }

        std::cout << "[*] Both certificates verified successfully!\n\n";

        // ---------------------------------------------------------------
        // 5) A вычисляет общий секрет: A_Secret = ECDH(A_key, B_pub)
        //    B вычисляет общий секрет: B_Secret = ECDH(B_key, A_pub)
        // ---------------------------------------------------------------
        std::vector<unsigned char> secretA = computeECDH(A_key, B_key);
        std::vector<unsigned char> secretB = computeECDH(B_key, A_key);

        if(secretA == secretB) {
            std::cout << "[*] Shared secret matches! ECDH success.\n";
        } else {
            std::cerr << "[!] Shared secret mismatch.\n";
        }

        // Для наглядности печатаем общий секрет в hex
        auto printHex = [](const std::vector<unsigned char>& v)
        {
            for(unsigned char c: v) {
                std::printf("%02X", c);
            }
        };
        std::cout << "A_secret = ";
        printHex(secretA);
        std::cout << "\nB_secret = ";
        printHex(secretB);
        std::cout << "\n\n";

        // ---------------------------------------------------------------
        // Освобождаем ресурсы
        // ---------------------------------------------------------------
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        X509_free(A_cert);
        X509_free(B_cert);
        EVP_PKEY_free(A_key);
        EVP_PKEY_free(B_key);

    } catch(const std::exception &ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        ERR_print_errors_fp(stderr);
    }

    // Финальная очистка OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
