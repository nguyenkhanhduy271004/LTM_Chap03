#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <unistd.h>

void ssh_port_forwarding(ssh_session session)
{
    int local_port = 9000;
    const char *remote_host = "localhost"; // Chạy trong container
    int remote_port = 8080;

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL)
    {
        fprintf(stderr, "Error creating SSH channel\n");
        return;
    }

    if (ssh_channel_open_forward(channel, remote_host, remote_port, "127.0.0.1", local_port) != SSH_OK)
    {
        fprintf(stderr, "Error setting up port forwarding: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }

    printf("Port forwarding from localhost:%d to %s:%d established!\n", local_port, remote_host, remote_port);

    // Giữ kết nối SSH mở để tiếp tục chuyển tiếp cổng
    while (ssh_channel_is_open(channel))
    {
        sleep(1);
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);
}

int main()
{
    ssh_session session = ssh_new();
    if (session == NULL)
    {
        fprintf(stderr, "Error creating SSH session\n");
        return -1;
    }

    int port = 22;
    ssh_options_set(session, SSH_OPTIONS_HOST, "172.18.0.2"); // Thay IP đúng
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    if (ssh_connect(session) != SSH_OK)
    {
        fprintf(stderr, "Error connecting to SSH: %s\n", ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    ssh_key key = NULL;
    if (ssh_pki_import_privkey_file("/root/.ssh/id_rsa_key", NULL, NULL, NULL, &key) != SSH_OK)
    {
        fprintf(stderr, "Error loading private key: %s\n", ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    if (ssh_userauth_publickey(session, NULL, key) != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
        ssh_key_free(key);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    ssh_key_free(key);
    printf("Connected to SSH! Starting port forwarding...\n");

    ssh_port_forwarding(session);

    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}
