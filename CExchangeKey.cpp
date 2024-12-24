#include "CExchangeKey.h"

// Конструктор
ECKeyExchange::ECKeyExchange(const std::string &ca_cert_path) {
    // Загрузка сертификата CA
    FILE *file = fopen(ca_cert_path.c_str(), "r");
    if (!file) {
        std::cerr << "Не удалось открыть файл с сертификатом CA\n";
        exit(1);
    }
    ca_cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!ca_cert) {
        std::cerr << "Ошибка загрузки сертификата CA\n";
        exit(1);
    }

    // Создаем объект для эллиптической кривой P-256
    curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!curve) {
        std::cerr << "Ошибка создания кривой\n";
        exit(1);
    }
}

// Деструктор
ECKeyExchange::~ECKeyExchange() {
    if (private_key) EC_KEY_free(private_key);
    if (public_key) EC_POINT_free(public_key);
    EC_GROUP_free(curve);
    if (ca_cert) X509_free(ca_cert);
}

// Генерация закрытого и открытого ключа
void ECKeyExchange::generateKeys() {
    private_key = EC_KEY_new();
    if (!private_key) {
        std::cerr << "Ошибка создания ключа\n";
        exit(1);
    }

    if (!EC_KEY_set_group(private_key, curve)) {
        std::cerr << "Ошибка установки группы кривой\n";
        exit(1);
    }

    // Генерация ключей
    if (!EC_KEY_generate_key(private_key)) {
        std::cerr << "Ошибка генерации ключа\n";
        exit(1);
    }

    const EC_POINT *pub_key = EC_KEY_get0_public_key(private_key);
    public_key = EC_POINT_dup(pub_key, curve);
}

// Получение открытого ключа в формате PEM
std::string ECKeyExchange::getPublicKey() {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_EC_PUBKEY(bio, private_key)) {
        std::cerr << "Ошибка сериализации открытого ключа\n";
        exit(1);
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    std::string pub_key(data, len);
    BIO_free(bio);
    return pub_key;
}

// Проверка валидности открытого ключа с помощью CA
bool ECKeyExchange::validatePublicKey(const std::string &other_public_key) {
    BIO *bio = BIO_new_mem_buf(other_public_key.data(), other_public_key.size());
    EC_KEY *peer_key = PEM_read_bio_EC_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!peer_key) {
        std::cerr << "Ошибка десериализации открытого ключа другого клиента\n";
        return false;
    }

    // Здесь можно дополнительно проверить подпись, связанную с сертификатом CA
    EC_KEY_free(peer_key);
    return true; // В данном примере валидация возвращает "успех"
}

// Вычисление общего секрета
std::string ECKeyExchange::computeSharedSecret(const std::string &other_public_key) {
    if (!validatePublicKey(other_public_key)) {
        std::cerr << "Ошибка валидации открытого ключа другого клиента\n";
        exit(1);
    }

    BIO *bio = BIO_new_mem_buf(other_public_key.data(), other_public_key.size());
    EC_KEY *peer_key = PEM_read_bio_EC_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!peer_key) {
        std::cerr << "Ошибка десериализации открытого ключа другого клиента\n";
        exit(1);
    }

    const int secret_len = 32;
    unsigned char *secret = new unsigned char[secret_len];
    int computed_len = ECDH_compute_key(secret, secret_len, EC_KEY_get0_public_key(peer_key), private_key, nullptr);

    if (computed_len <= 0) {
        std::cerr << "Ошибка вычисления общего секрета\n";
        exit(1);
    }

    std::string shared_secret(reinterpret_cast<char*>(secret), computed_len);
    delete[] secret;
    EC_KEY_free(peer_key);

    return shared_secret;
}

void ECKeyExchange::printCertificateDetails() {
    if (!ca_cert) {
        std::cerr << "Сертификат CA отсутствует" << std::endl;
        return;
    }

    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    // Вывод сертификата в текстовом формате
    std::cout << "Данные сертификата CA:" << std::endl;
    if (!X509_print(bio_out, ca_cert)) {
        std::cerr << "Ошибка вывода сертификата CA" << std::endl;
    }

    BIO_free(bio_out);
}

void ECKeyExchange::printKeys() {
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    // Вывод открытого ключа
    std::cout << "Открытый ключ (PEM):" << std::endl;
    if (!PEM_write_bio_EC_PUBKEY(bio_out, private_key)) {
        std::cerr << "Ошибка вывода открытого ключа" << std::endl;
    }

    // Вывод закрытого ключа (для отладки)
    std::cout << "\nЗакрытый ключ (PEM):" << std::endl;
    if (!PEM_write_bio_ECPrivateKey(bio_out, private_key, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Ошибка вывода закрытого ключа" << std::endl;
    }

    BIO_free(bio_out);
}
