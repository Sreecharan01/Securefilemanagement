#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

using namespace std;

class SecureFileManager {
private:
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    void generateKey() {
        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));
    }

    string encrypt(const string &data) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        vector<unsigned char> ciphertext(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int len, ciphertext_len;
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)data.c_str(), data.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        return string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    }

    string decrypt(const string &data) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        vector<unsigned char> plaintext(data.size());
        int len, plaintext_len;
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)data.c_str(), data.size());
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        return string(plaintext.begin(), plaintext.begin() + plaintext_len);
    }

public:
    SecureFileManager() { generateKey(); }

    bool writeFile(const string &filename, const string &content) {
        ofstream file(filename, ios::binary);
        if (!file) return false;
        string encryptedContent = encrypt(content);
        file.write(encryptedContent.c_str(), encryptedContent.size());
        return true;
    }

    string readFile(const string &filename) {
        ifstream file(filename, ios::binary);
        if (!file) return "";
        string encryptedContent((istreambuf_iterator<char>(file)), {});
        return decrypt(encryptedContent);
    }
};

int main() {
    SecureFileManager manager;
    string filename, content;

    cout << "Enter filename to write: ";
    cin >> filename;
    cout << "Enter content: ";
    cin.ignore();
    getline(cin, content);

    if (manager.writeFile(filename, content))
        cout << "File saved securely!\n";

    cout << "Reading file...\n";
    string decryptedContent = manager.readFile(filename);
    cout << "Decrypted Content: " << decryptedContent << endl;

    return 0;
}
