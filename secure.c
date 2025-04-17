#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASSWORD "admin123"
#define MAX_FILENAME 100
#define BUFFER_SIZE 1024
#define KEY 0xAA  // XOR key for basic encryption

void encryptDecrypt(char *data, int size) {
    for (int i = 0; i < size; i++)
        data[i] ^= KEY;
}

int login() {
    char pass[50];
    printf("Enter password: ");
    scanf("%s", pass);
    return strcmp(pass, PASSWORD) == 0;
}

void createFile() {
    char filename[MAX_FILENAME];
    char data[BUFFER_SIZE];

    printf("Enter file name: ");
    scanf("%s", filename);
    getchar(); // consume newline

    printf("Enter file content:\n");
    fgets(data, BUFFER_SIZE, stdin);

    encryptDecrypt(data, strlen(data));

    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        printf("Error creating file.\n");
        return;
    }

    fwrite(data, 1, strlen(data), fp);
    fclose(fp);
    printf("File created and encrypted successfully.\n");
}

void readFile() {
    char filename[MAX_FILENAME];
    char data[BUFFER_SIZE];

    printf("Enter file name to read: ");
    scanf("%s", filename);

    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("File not found.\n");
        return;
    }

    int size = fread(data, 1, BUFFER_SIZE, fp);
    fclose(fp);
    encryptDecrypt(data, size);
    data[size] = '\0';

    printf("File content (decrypted):\n%s\n", data);
}

void deleteFile() {
    char filename[MAX_FILENAME];
    printf("Enter file name to delete: ");
    scanf("%s", filename);

    if (remove(filename) == 0)
        printf("File deleted successfully.\n");
    else
        printf("Error deleting file.\n");
}

int main() {
    if (!login()) {
        printf("Access denied.\n");
        return 1;
    }

    int choice;
    while (1) {
        printf("\nSecure File Management System\n");
        printf("1. Create File\n2. Read File\n3. Delete File\n4. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: createFile(); break;
            case 2: readFile(); break;
            case 3: deleteFile(); break;
            case 4: exit(0);
            default: printf("Invalid choice.\n");
        }
    }

    return 0;
}
