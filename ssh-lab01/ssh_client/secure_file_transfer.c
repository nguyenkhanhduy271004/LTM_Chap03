#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <fcntl.h>    // Thêm thư viện này để dùng O_WRONLY, O_CREAT, O_TRUNC
#include <sys/stat.h> // Thêm thư viện này để dùng S_IRWXU
#include <unistd.h>

void send_file(ssh_session session, const char *local_path, const char *remote_path)
{
    sftp_session sftp = sftp_new(session);
    if (sftp == NULL)
    {
        fprintf(stderr, "Error creating SFTP session: %s\n", ssh_get_error(session));
        return;
    }

    if (sftp_init(sftp) != SSH_OK)
    {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    FILE *local_file = fopen(local_path, "rb");
    if (local_file == NULL)
    {
        fprintf(stderr, "Error opening local file: %s\n", local_path);
        sftp_free(sftp);
        return;
    }

    sftp_file remote_file = sftp_open(sftp, remote_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    if (remote_file == NULL)
    {
        fprintf(stderr, "Error opening remote file: %s\n", ssh_get_error(session));
        fclose(local_file);
        sftp_free(sftp);
        return;
    }

    char buffer[4096];
    size_t nread;
    while ((nread = fread(buffer, 1, sizeof(buffer), local_file)) > 0)
    {
        if (sftp_write(remote_file, buffer, nread) < 0)
        {
            fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
            break;
        }
    }

    fclose(local_file);
    sftp_close(remote_file);
    sftp_free(sftp);
    printf("File successfully transferred!\n");
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
    printf("Connected to SSH! Starting file transfer...\n");

    send_file(session, "/app/local_test.txt", "/root/remote_test.txt");

    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}
