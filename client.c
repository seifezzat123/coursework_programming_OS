#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

// Thread function for each user
void *run_user(void *arg) {
    char *credentials = (char *)arg;
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE];

    // Extract username only for display
    char username[BUFFER_SIZE], password[BUFFER_SIZE];
    sscanf(credentials, "%s %s", username, password);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        pthread_exit(NULL);
    }

    // Define server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        close(sock);
        pthread_exit(NULL);
    }

    // Step 1: Send credentials
    char cred_buf[BUFFER_SIZE];
    strcpy(cred_buf, credentials);
    int cred_len = aes_encrypt(cred_buf, strlen(cred_buf));
    send(sock, cred_buf, cred_len, 0);

    // Step 2: Wait for server confirmation
    memset(buffer, 0, BUFFER_SIZE);
    int valread = read(sock, buffer, BUFFER_SIZE);
    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';
    printf("[%s] Server: %s\n", username, buffer);

    if (strcmp(buffer, "AUTH_SUCCESS") != 0) {
        printf("Authentication failed for %s!\n", username);
        close(sock);
        pthread_exit(NULL);
    }

    // Step 3: Send encrypted fixed message
    char message[BUFFER_SIZE] = "Hello from client";
    int msg_len = aes_encrypt(message, strlen(message));
    send(sock, message, msg_len, 0);

    // Step 4: Receive encrypted response
    memset(buffer, 0, BUFFER_SIZE);
    valread = read(sock, buffer, BUFFER_SIZE);
    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';
    printf("[%s] Server: %s\n", username, buffer);

    close(sock);
    pthread_exit(NULL);
}

int main() {
    // Three users hard-coded (must match users.txt exactly)
    char *users[3] = {
        "user1 pass123",
        "user2 secret456",
        "seif1 123pass"
    };

    pthread_t threads[3];

    // Create a thread for each user
    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, run_user, users[i]);
    }

    // Wait for all threads to finish
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
