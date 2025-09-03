#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sodium.h>

#define BUFFER_SIZE 1024
#define NONCE_SIZE crypto_box_NONCEBYTES
#define MAC_SIZE crypto_box_MACBYTES

GtkWidget *entry_ip, *entry_port, *entry_username, *entry_msg, *text_view;
int sockfd;
unsigned char sk[crypto_box_SECRETKEYBYTES];
unsigned char pk[crypto_box_PUBLICKEYBYTES];
unsigned char peer_pk[crypto_box_PUBLICKEYBYTES];

void load_keys() {
    FILE *f = fopen("sk.bin", "rb");
    if (!f) {
        perror("Failed to open sk.bin");
        exit(1);
    }
    fread(sk, 1, crypto_box_SECRETKEYBYTES, f);
    fclose(f);

    f = fopen("pk.bin", "rb");
    if (!f) {
        perror("Failed to open pk.bin");
        exit(1);
    }
    fread(peer_pk, 1, crypto_box_PUBLICKEYBYTES, f);
    fclose(f);
}

gboolean append_text_idle(gpointer data) {
    const char *msg = (const char *)data;
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);
    gtk_text_buffer_insert(buffer, &end, msg, -1);
    gtk_text_buffer_insert(buffer, &end, "\n", -1);
    free((void*)msg);
    return FALSE;
}

void *recv_thread(void *arg) {
    unsigned char buf[BUFFER_SIZE + MAC_SIZE + NONCE_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char decrypted[BUFFER_SIZE];
    ssize_t n;

    while ((n = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
        if (n < NONCE_SIZE + MAC_SIZE) {
            // Message too short
            continue;
        }

        memcpy(nonce, buf, NONCE_SIZE);
        if (crypto_box_open_easy(decrypted, buf + NONCE_SIZE, n - NONCE_SIZE, nonce, peer_pk, sk) == 0) {
            decrypted[n - NONCE_SIZE - MAC_SIZE] = '\0';
            char *msg = strdup((char*)decrypted);
            g_idle_add(append_text_idle, msg);
        } else {
            char *msg = strdup("[Decryption failed]");
            g_idle_add(append_text_idle, msg);
        }
    }
    return NULL;
}

void send_msg(GtkButton *button, gpointer user_data) {
    const char *text = gtk_entry_get_text(GTK_ENTRY(entry_msg));
    const char *username = gtk_entry_get_text(GTK_ENTRY(entry_username));
    if (strlen(text) == 0) return;

    char combined[BUFFER_SIZE];
    snprintf(combined, sizeof(combined), "%s: %s", username, text);

    unsigned char nonce[NONCE_SIZE];
    randombytes_buf(nonce, NONCE_SIZE);

    unsigned char ciphertext[BUFFER_SIZE + MAC_SIZE + NONCE_SIZE];
    memcpy(ciphertext, nonce, NONCE_SIZE);

    int ret = crypto_box_easy(ciphertext + NONCE_SIZE, (unsigned char*)combined, strlen(combined), nonce, peer_pk, sk);
    if (ret != 0) {
        fprintf(stderr, "Encryption failed!\n");
        return;
    }

    send(sockfd, ciphertext, strlen(combined) + MAC_SIZE + NONCE_SIZE, 0);

    // Show your own message immediately
    char *msg_copy = strdup(combined);
    g_idle_add(append_text_idle, msg_copy);

    gtk_entry_set_text(GTK_ENTRY(entry_msg), "");
}

void connect_to_server(GtkButton *button, gpointer user_data) {
    const char *ip = gtk_entry_get_text(GTK_ENTRY(entry_ip));
    const char *port_str = gtk_entry_get_text(GTK_ENTRY(entry_port));
    int port = atoi(port_str);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address\n");
        close(sockfd);
        return;
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return;
    }

    pthread_t tid;
    pthread_create(&tid, NULL, recv_thread, NULL);
    pthread_detach(tid);
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return 1;
    }

    load_keys();

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    gtk_window_set_title(GTK_WINDOW(window), "Secure Chat Client");

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    entry_ip = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_ip), "Server IP");
    gtk_box_pack_start(GTK_BOX(vbox), entry_ip, FALSE, FALSE, 0);

    entry_port = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_port), "Port");
    gtk_box_pack_start(GTK_BOX(vbox), entry_port, FALSE, FALSE, 0);

    entry_username = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_username), "Username");
    gtk_box_pack_start(GTK_BOX(vbox), entry_username, FALSE, FALSE, 0);

    GtkWidget *connect_button = gtk_button_new_with_label("Connect");
    gtk_box_pack_start(GTK_BOX(vbox), connect_button, FALSE, FALSE, 0);
    g_signal_connect(connect_button, "clicked", G_CALLBACK(connect_to_server), NULL);

    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), text_view, TRUE, TRUE, 0);

    entry_msg = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_msg), "Message");
    gtk_box_pack_start(GTK_BOX(vbox), entry_msg, FALSE, FALSE, 0);

    GtkWidget *send_button = gtk_button_new_with_label("Send");
    gtk_box_pack_start(GTK_BOX(vbox), send_button, FALSE, FALSE, 0);
    g_signal_connect(send_button, "clicked", G_CALLBACK(send_msg), NULL);

    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    gtk_widget_show_all(window);
    gtk_main();

    close(sockfd);
    return 0;
}
