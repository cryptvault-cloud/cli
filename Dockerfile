FROM alpine
ENTRYPOINT ["/usr/bin/vault-cli"]
COPY vault-cli /usr/bin/vault-cli
WORKDIR /vault