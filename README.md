# Secure File Management System
1. Project Overview**

The Secure File Management System is designed to provide a highly secure and efficient way to store, access, and share files within an organization. With the increasing risks of data breaches, unauthorized access, and cyber threats, organizations require a system that offers robust security mechanisms. This system ensures file integrity, confidentiality, and controlled access by implementing multi-factor authentication (MFA), role-based access control (RBAC), encryption, and audit logs.

The primary objectives of this project are:
- To provide **secure storage** of sensitive files.
- To ensure **controlled access** based on user roles.
- To **encrypt** files to prevent unauthorized access.
- To **track all file activities** with audit logs.
- To allow **secure file transfers** with encryption.

2. Installation Steps**

#Prerequisites
Ensure you have the following installed on your system:
- **Python 3.7+**
- **pip (Python Package Manager)**
- **Virtual Environment (optional but recommended)**

### Step-by-Step Installation Guide

#### 1. Clone the Repository
```sh
git clone https://github.com/your-repository/SecureFileMgmt.git
cd SecureFileMgmt
```

#### 2. Create and Activate a Virtual Environment (Optional)
```sh
python -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate    # On Windows
```

#### 3. Install Dependencies
```sh
pip install -r requirements.txt
```

#### 4. Initialize the Database
```sh
python init_db.py
```

#### 5. Run the Application
```sh
uvicorn secure_file_management:app --reload
```

---

**3. Usage Guide**

### API Endpoints

#### **1. Register a New User**
```sh
curl -X POST "http://127.0.0.1:8000/register" -d "username=admin&password=admin123&role=admin"
```

#### **2. Login and Get a Token**
```sh
curl -X POST "http://127.0.0.1:8000/login" -d "username=admin&password=admin123"
```

#### **3. Upload a File**
```sh
curl -X POST "http://127.0.0.1:8000/upload" -H "Authorization: Bearer <your_token>" -F "file=@test.txt"
```

#### **4. Download a File**
```sh
curl -X GET "http://127.0.0.1:8000/download/test.txt" -H "Authorization: Bearer <your_token>"
```

### Web Interface (Optional)
If a web frontend is available, navigate to:
```sh
http://127.0.0.1:8000/docs
```
Here, you can test the API using an interactive UI.

---

**4. Conclusion and Future Scope**

The Secure File Management System is an effective solution for organizations looking to enhance their data security. By integrating advanced authentication, encryption, and access control mechanisms, the system ensures a high level of security and compliance.

**Future Enhancements:**
- **AI-based Anomaly Detection:** Implement AI algorithms to detect suspicious access patterns.
- **Blockchain-based File Integrity Verification:** Store audit logs on a blockchain ledger for immutability.
- **Integration with Cloud Providers:** Extend compatibility with AWS, Google Cloud, and Azure for scalable storage.
- **Biometric Authentication Improvements:** Enhance facial and voice recognition for better accuracy.

---

**5. References**

1. Houttuin, T. (2024). Blockchain-based Authentication Systems for Secure Access Control in Autonomous Vehicles. *African Journal of Artificial Intelligence and Sustainable Development, 4(1), 78-105.*
2. Nielsen, M. (2023). Human-Centric Authentication Systems for Secure Access Control in IoT-connected Autonomous Vehicles. *Journal of Artificial Intelligence Research and Applications, 3(2), 356-384.*
3. Aslam, M. S., et al. (2024). Novel model to authenticate role-based medical users for blockchain-based IoMT devices. *Plos One, 19(7), e0304774.*
4. Gudala, L., et al. (2022). Leveraging Biometric Authentication and Blockchain Technology for Enhanced Security in Identity and Access Management Systems. *Journal of Artificial Intelligence Research, 2(2), 21-50.*
5. Knapp, E. D. (2024). Industrial Network Security: Securing critical infrastructure networks for smart grid, SCADA, and other Industrial Control Systems. *Elsevier.*
6. Xu, J., et al. (2021). Role-based access control model for cloud storage using identity-based cryptosystem. *Mobile Networks and Applications, 26, 1475-1492.*
7. Saxena, U. R., & Alam, T. (2022). Role based access control using identity and broadcast-based encryption for securing cloud data. *Journal of Computer Virology and Hacking Techniques, 18(3), 171-182.*

---

**6. Appendix**

**A. AI-Generated Project Elaboration/Breakdown Report**

The project consists of multiple modules, including authentication, encryption, access control, and secure file transfer. It uses AI-driven anomaly detection to identify suspicious activity. The system leverages pre-trained AI models for facial and voice recognition, making it highly secure. Additionally, blockchain-based storage can be integrated for immutable file logging.

**B. Problem Statement**

With the rise in cyber threats, organizations face challenges in securing sensitive files and preventing unauthorized access. Traditional password-based authentication is insufficient, making it necessary to integrate advanced authentication mechanisms, encryption, and access control policies.





----------------------------------------------------------------------------------------------------------------------------------------------------
code for c
##include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define KEY_LEN 32   // 256 bits for AES-256
#define IV_LEN 16    // 128 bits block size for AES

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main() {
    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    char filename[100];
    char input[1024];
    FILE *fp;

    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    printf("Enter filename to write: ");
    scanf("%s", filename);
    getchar();  // consume newline
    printf("Enter content: ");
    fgets(input, sizeof(input), stdin);

    int input_len = strlen(input);
    if (input[input_len - 1] == '\n') input[--input_len] = '\0';

    unsigned char encrypted[2048];
    int encrypted_len = encrypt((unsigned char *)input, input_len, key, iv, encrypted);

    fp = fopen(filename, "wb");
    if (!fp) {
        perror("File opening failed");
        return 1;
    }
    fwrite(encrypted, 1, encrypted_len, fp);
    fclose(fp);
    printf("File saved securely!\n");

    printf("Reading file...\n");
    fp = fopen(filename, "rb");
    if (!fp) {
        perror("File opening failed");
        return 1;
    }

    unsigned char read_buf[2048];
    int read_len = fread(read_buf, 1, sizeof(read_buf), fp);
    fclose(fp);

    unsigned char decrypted[2048];
    int decrypted_len = decrypt(read_buf, read_len, key, iv, decrypted);
    decrypted[decrypted_len] = '\0';

    printf("Decrypted Content: %s\n", decrypted);

    return 0;
}

