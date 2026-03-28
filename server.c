#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

// Check credentials against users.txt
int check_credentials(const char *username, const char *password) {
    FILE *file = fopen("users.txt", "r");
    if (!file) return 0;

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char stored_user[BUFFER_SIZE], stored_pass[BUFFER_SIZE];
        sscanf(line, "%s %s", stored_user, stored_pass);
        if (strcmp(username, stored_user) == 0 &&
            strcmp(password, stored_pass) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

// Thread function for each client
void *handle_client(void *arg) {
    int new_socket = *(int*)arg;
    char buffer[BUFFER_SIZE] = {0};

    // Step 1: Receive credentials
    int valread = read(new_socket, buffer, BUFFER_SIZE);
    aes_decrypt(buffer, valread);

    char username[BUFFER_SIZE], password[BUFFER_SIZE];
    sscanf(buffer, "%s %s", username, password);

    if (!check_credentials(username, password)) {
        char fail_msg[] = "AUTH_FAILED";
        aes_encrypt(fail_msg, AES_BLOCK_SIZE);
        send(new_socket, fail_msg, AES_BLOCK_SIZE, 0);
        close(new_socket);
        pthread_exit(NULL);
    }

    // Step 2: Send success
    char success_msg[] = "AUTH_SUCCESS";
    aes_encrypt(success_msg, AES_BLOCK_SIZE);
    send(new_socket, success_msg, AES_BLOCK_SIZE, 0);

    // Step 3: Secure communication
    memset(buffer, 0, BUFFER_SIZE);
    valread = read(new_socket, buffer, BUFFER_SIZE);
    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';
    printf("Client: %s\n", buffer);

    char response[] = "Hello from server";
    aes_encrypt(response, AES_BLOCK_SIZE);
    send(new_socket, response, AES_BLOCK_SIZE, 0);

    close(new_socket);
    pthread_exit(NULL);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) { perror("Socket failed"); exit(EXIT_FAILURE); }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed"); exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed"); exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) { perror("Accept failed"); continue; }

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, &new_socket);
        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}
