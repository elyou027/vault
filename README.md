# Docker-compose 

```yaml
version: '2'

networks:
  local-net:

services:
  vault-server:
    image: antonmatyunin/vault
    container_name: vault-server
    hostname: vault.${INT_DOMAIN}
    restart: always
    environment:
      VAULT_ADDR: ${VAULT_ADDR}
      USER_ID: 1000
      USER_GID: 1000
    ports:
      - "8200:8200"
    volumes_from:
      - consul-server
    cap_add:
      - IPC_LOCK
    networks:
      local-net:
    logging:
      options:
        max-size: "50k"
        max-file: "10"
```