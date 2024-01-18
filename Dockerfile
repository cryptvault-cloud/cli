FROM alpine
ENTRYPOINT ["/usr/bin/vault-cli"]
COPY gomake /usr/bin/vault-cli