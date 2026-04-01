#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("Socket creation error"); return -1; }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address"); return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed"); return -1;
    }

    // Step 1: Send credentials
    char credentials[BUFFER_SIZE] = "user2 secret456";
    aes_encrypt(credentials, AES_BLOCK_SIZE);
    send(sock, credentials, AES_BLOCK_SIZE, 0);

    // Step 2: Wait for server confirmation
    int valread = read(sock, buffer, BUFFER_SIZE);
    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';
    printf("Server: %s\n", buffer);

    if (strcmp(buffer, "AUTH_SUCCESS") != 0) {
        printf("Authentication failed!\n");
        close(sock);
        return 0;
    }

    // Step 3: Send encrypted message
    char message[BUFFER_SIZE] = "Hello from client";
    aes_encrypt(message, AES_BLOCK_SIZE);
    send(sock, message, AES_BLOCK_SIZE, 0);

    // Step 4: Receive encrypted response
    memset(buffer, 0, BUFFER_SIZE);
    valread = read(sock, buffer, BUFFER_SIZE);
    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';
    printf("Server: %s\n", buffer);

    close(sock);
    return 0;
}
