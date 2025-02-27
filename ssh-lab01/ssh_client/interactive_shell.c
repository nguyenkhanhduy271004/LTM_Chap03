#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <unistd.h>

void execute_interactive_shell(ssh_session session)
{
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL)
    {
        fprintf(stderr, "Error creating SSH channel\n");
        return;
    }

    // Mở phiên SSH
    if (ssh_channel_open_session(channel) != SSH_OK)
    {
        fprintf(stderr, "Error opening SSH session: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }

    // Yêu cầu một pseudo-terminal
    if (ssh_channel_request_pty(channel) != SSH_OK)
    {
        fprintf(stderr, "Error requesting pty: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }

    // Yêu cầu shell
    if (ssh_channel_request_shell(channel) != SSH_OK)
    {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }

    // Đặt chế độ non-blocking để đọc/ghi dữ liệu
    ssh_channel_set_blocking(channel, 0);

    char buffer[1024];
    int nbytes;

    while (1)
    {
        // Đọc dữ liệu từ SSH server
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes > 0)
        {
            fwrite(buffer, 1, nbytes, stdout);
            fflush(stdout);
        }

        // Đọc dữ liệu từ người dùng và gửi lên SSH server
        if (fgets(buffer, sizeof(buffer), stdin) != NULL)
        {
            ssh_channel_write(channel, buffer, strlen(buffer));
        }

        // Kiểm tra nếu SSH channel đóng
        if (ssh_channel_is_eof(channel))
        {
            break;
        }
    }

    // Đóng kênh SSH
    ssh_channel_send_eof(channel);
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

    // Thiết lập kết nối SSH đến `ssh-server`
    int port = 22;
    ssh_options_set(session, SSH_OPTIONS_HOST, "172.18.0.2"); // Thay IP đúng
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    // Kết nối SSH
    if (ssh_connect(session) != SSH_OK)
    {
        fprintf(stderr, "Error connecting to SSH: %s\n", ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    // Import Private Key từ file
    ssh_key key = NULL;
    if (ssh_pki_import_privkey_file("/root/.ssh/id_rsa_key", NULL, NULL, NULL, &key) != SSH_OK)
    {
        fprintf(stderr, "Error loading private key: %s\n", ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    // Xác thực bằng private key
    if (ssh_userauth_publickey(session, NULL, key) != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
        ssh_key_free(key);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    ssh_key_free(key);
    printf("Connected! Interactive shell started.\n");

    // Thực thi interactive shell
    execute_interactive_shell(session);

    // Đóng kết nối SSH
    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}
