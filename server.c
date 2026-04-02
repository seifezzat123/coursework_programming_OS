#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

// Function to check credentials against users.txt
int authenticate(char *credentials) {
    FILE *file = fopen("users.txt", "r");
    if (!file) {
        perror("Could not open users.txt");
        return 0;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(credentials, line) == 0) {
            fclose(file);
            return 1; // Auth success
        }
    }

    fclose(file);
    return 0; // Auth failed
}

// Thread function to handle each client
void *handle_client(void *arg) {
    int new_socket = *((int *)arg);
    free(arg);

    char buffer[BUFFER_SIZE];
    char username[BUFFER_SIZE], password[BUFFER_SIZE];

    // Step 1: Receive credentials
    memset(buffer, 0, BUFFER_SIZE);
    int valread = read(new_socket, buffer, BUFFER_SIZE);
    if (valread <= 0) {
        close(new_socket);
        pthread_exit(NULL);
    }

    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';

    // Extract username and password
    sscanf(buffer, "%s %s", username, password);

    // Authenticate
    if (authenticate(buffer)) {
        char response[BUFFER_SIZE] = "AUTH_SUCCESS";
        int resp_len = aes_encrypt(response, strlen(response));
        send(new_socket, response, resp_len, 0);
    } else {
        char response[BUFFER_SIZE] = "AUTH_FAILED";
        int resp_len = aes_encrypt(response, strlen(response));
        send(new_socket, response, resp_len, 0);
        close(new_socket);
        pthread_exit(NULL);
    }

    // Step 2: Receive message
    memset(buffer, 0, BUFFER_SIZE);
    valread = read(new_socket, buffer, BUFFER_SIZE);
    if (valread <= 0) {
        close(new_socket);
        pthread_exit(NULL);
    }

    aes_decrypt(buffer, valread);
    buffer[valread] = '\0';

    // Print message on server side
    printf("[%s]: %s\n", username, buffer);

    // Step 3: Send response back
    char response[BUFFER_SIZE] = "Hello from server";
    int resp_len = aes_encrypt(response, strlen(response));
    send(new_socket, response, resp_len, 0);

    close(new_socket);
    pthread_exit(NULL);
}

int main() {
    int server_fd, *new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept clients in loop
    while (1) {
        new_socket = malloc(sizeof(int));
        *new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (*new_socket < 0) {
            perror("Accept failed");
            free(new_socket);
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, new_socket);
        pthread_detach(tid);
    }

    return 0;
}
