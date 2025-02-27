#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main()
{
    ssh_session my_ssh_session;
    int rc;
    ssh_channel channel;
    char buffer[256];
    int nbytes;
    char command[256];

    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
    {
        fprintf(stderr, "Error creating SSH session\n");
        exit(-1);
    }

    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "172.18.0.2"); // Modify this ip
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &(int){22});
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "seed");

    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    rc = ssh_userauth_password(my_ssh_session, NULL, "dees");
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating: %s\n", ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    printf("Successfully connected and authenticated!\n");

    // Create a new channel
    channel = ssh_channel_new(my_ssh_session);
    if (channel == NULL)
    {
        fprintf(stderr, "Error creating channel\n");
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Open a session
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error opening channel: %s\n", ssh_get_error(my_ssh_session));
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Request a pseudo-terminal
    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error requesting PTY: %s\n", ssh_get_error(my_ssh_session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    // Request shell
    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(my_ssh_session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    printf("Interactive shell started. Type commands or 'exit' to quit.\n");

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    return 0;
}