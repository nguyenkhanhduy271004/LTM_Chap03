# Dockerfile (ssh_client/Dockerfile)
FROM alpine:latest

# Install libssh and development tools
RUN apk add --no-cache openssh libssh-dev build-base

# Set working directory
WORKDIR /app

# Copy the C source code (assuming it's in the same directory as this Dockerfile)
COPY ssh_client.c .  


# Keep the container running (for interactive use)
CMD ["tail", "-f", "/dev/null"]