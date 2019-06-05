FROM vault
RUN apk --no-cache -U add bash shadow sudo jq

ENV PATH                "/usr/local/bin:${PATH}"
ENV VAULT_CONFIG_DIR    "/vault/config"
ENV CONF_PATH           "/vault/config/vault.hcl"
ENV VAULT_ADDR          "https://vault.${INT_DOMAIN}:8200"
ENV INIT_KEYS_FILE      "/vault/backup/keys.txt"
ENV INIT_DIR_PATH       "/vault/init"
ENV VAULT_USER          "vault_user"
ENV VAULT_GROUP         "vault_group"
ENV USER_ID             "1000"
ENV USER_GID            "1000"

WORKDIR                 ${INIT_DIR_PATH}
COPY entrypoint.sh /usr/local/bin
#COPY config/ca.crt /usr/local/share/ca-certificates/
#RUN cd /usr/local/share/ca-certificates/ && update-ca-certificates

ENTRYPOINT ["entrypoint.sh"]
CMD ["run_vault"]
