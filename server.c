#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 4096

int clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
FILE *logf;

void log_event(const char *fmt, const char *msg, const char *addr) {
    logf = fopen("serverlog.txt", "a");
    if (logf) {
        fprintf(logf, fmt, addr, msg);
        fprintf(logf, "\n");
        fclose(logf);
    }
}

void *client_handler(void *arg) {
    int client_sock = *(int *)arg;
    char buffer[BUFFER_SIZE];
    char addr_str[INET_ADDRSTRLEN] = {0};
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    getpeername(client_sock, (struct sockaddr *)&peer, &peer_len);
    inet_ntop(AF_INET, &peer.sin_addr, addr_str, sizeof(addr_str));

    log_event("[Client connected] %s", "", addr_str);

    int n;
    while ((n = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0) {
        log_event("[Msg from %s] %s", buffer, addr_str);

        pthread_mutex_lock(&lock);
        for (int i = 0; i < client_count; i++) {
            if (clients[i] != client_sock) {
                send(clients[i], buffer, n, 0);
            }
        }
        pthread_mutex_unlock(&lock);
    }

    pthread_mutex_lock(&lock);
    for (int i = 0; i < client_count; i++) {
        if (clients[i] == client_sock) {
            clients[i] = clients[client_count - 1];
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&lock);

    log_event("[Client disconnected] %s", "", addr_str);
    close(client_sock);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_sock, 5);

    printf("Server listening on port %d...\n", port);

    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock < 0) continue;

        pthread_mutex_lock(&lock);
        clients[client_count++] = client_sock;
        pthread_mutex_unlock(&lock);

        pthread_t tid;
        pthread_create(&tid, NULL, client_handler, &client_sock);
        pthread_detach(tid);
    }

    close(server_sock);
    return 0;
}
