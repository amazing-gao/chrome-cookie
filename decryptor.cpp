
#include <iostream>
#include <string>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>

#include "sqlite3.h"

using namespace std;

const char kSalt[] = "saltysalt";
const int kDerivedKeySizeInBits = 128;
const int kEncryptionIterations = 1003;
const char kEncryptionVersionPrefix[] = "v10";

struct Param {
    string pass;
    string host;
    string key;
};

bool deriveKeyFromPassword(const char *password, int pass_len, const unsigned char *salt, int salt_len, unsigned char *out) {
    if( PKCS5_PBKDF2_HMAC_SHA1(password, pass_len, salt, salt_len, kEncryptionIterations, kDerivedKeySizeInBits/8, out) != 0 ) {
        return true;
    } else {
        printf("PKCS5_PBKDF2_HMAC_SHA1 failed\n");
        return false;
    }
}

int decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len = -1;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return plaintext_len;

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        return plaintext_len;

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        goto CLEARUP;
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        plaintext_len = -1;
        goto CLEARUP;
    }
    plaintext_len += len;

CLEARUP:
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

bool chrome_decrypt(const string& password, const string &enc_value, string *dec_value) {
    if (enc_value.find(kEncryptionVersionPrefix) != 0) {
        printf("invalid encrypted data\n");
        return false;
    }

    string raw_enc_value = enc_value.substr(strlen(kEncryptionVersionPrefix));

    unsigned char iv[AES_BLOCK_SIZE] = {0};
    memset(iv, ' ', AES_BLOCK_SIZE);

    unsigned char *decryptedtext = new unsigned char[raw_enc_value.size()];
    int decryptedtext_len = 0;
    bool ret = false;

    unsigned char aes_key[kDerivedKeySizeInBits/8] = {0};
    if (deriveKeyFromPassword(password.c_str(), password.size(), (unsigned char *)kSalt, (int)strlen(kSalt), aes_key)) {
        decryptedtext_len = decrypt((const unsigned char *)raw_enc_value.c_str(), raw_enc_value.size(), aes_key, iv, decryptedtext);
        if (decryptedtext_len > 0) {
            *dec_value = string((char *)decryptedtext, decryptedtext_len);
            ret = true;
        }
    }

    delete[] decryptedtext;

    return ret;
}

int db_callback(void* param, int row_count, char** argv, char** col_name) {
    Param* _param = (Param*)param;
    if (!_param->host.empty() && argv[1] != _param->host)
        return 0;

    bool show_detail = _param->key.empty();

    for(int i = 0; i < row_count; i++) {
        if (show_detail) {
            if (i == 12) {
                string value = "";
                chrome_decrypt(_param->pass, argv[i], &value);
                cout << col_name[i] << ": " << value << "\n";
            } else {
                cout << col_name[i] << ": " << argv[i] << "\n";
            }
        } else {
            if (argv[2] == _param->key && i == 12) {
                string value = "";
                chrome_decrypt(_param->pass, argv[i], &value);
                cout << value << "\n";
            }
        }
    }
    if (show_detail)
        cout << "--------------------------------------------\n";
    return 0;
}

void read_db(const string& db_path, const string& password, const string& host, const string& key) {
    sqlite3* handle = NULL;
    sqlite3_open(db_path.data(), &handle);

    if (handle == NULL) {
        cout << "打开cookie数据库失败！";
        return;
    }

    sqlite3_stmt* stmp = NULL;

    Param param;
    param.pass = password;
    param.host = host;
    param.key = key;

    char* error = NULL;
    string sql = "select * from cookies";
    sqlite3_exec(handle, sql.data(), db_callback, (void*)(&param), &error);
    sqlite3_close(handle);
}

int main(int argc, const char * argv[]) {
    // read_db("/Users/bitebit/Library/Application Support/Google/Chrome/Default/Cookies", "F3/F95DvICIA==", "", "");
    // read_db("/Users/bitebit/Library/Application Support/Google/Chrome/Default/Cookies", "F3/F95DvICIA==", "10.2.69.69", "");
    // read_db("/Users/bitebit/Library/Application Support/Google/Chrome/Default/Cookies", "F3/F95DvICIA==", "10.2.69.69", "LBCLUSTERID");

    if (argc < 3) {
        cout << "使用方法: \n\t decryptor cookie文件路径 chrome钥匙串 [cookie的host] [cookie的名字]\n" << endl;
        cout << "Mac下获取chrome钥匙串: \n\t security find-generic-password -w -s \"Chrome Safe Storage\"" << endl;
        return 1;
    }

    if (argc == 5)
        read_db(argv[1], argv[2], argv[3], argv[4]);
    else if (argc == 4)
        read_db(argv[1], argv[2], argv[3], "");
    else if (argc == 3)
        read_db(argv[1], argv[2], "", "");

    return 0;
}

