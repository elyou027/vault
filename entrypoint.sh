#!/bin/bash
set -e
#set -x

# Colorise output
RED='\033[1;31m'
NC='\033[0m'
Green='\033[1;32m'


# First setup vault store
function init_vault {
  printf "${Green}[*] Start init of vault ${NC}\n"
  vault operator init -address=${VAULT_ADDR} > ${INIT_KEYS_FILE}
  if [ -s "$_file" ]
  then
    printf "${Green}[+] Done ${NC}\n"
  else
    rm -f ${INIT_KEYS_FILE}
    printf "${RED}[!] FAIL ${NC}\n"
  fi

}

function import_data {
  printf "${Green}[+] Enabling approle ${NC}\n"

  for policy_file in `ls ${INIT_DIR_PATH} | grep 'policy.hcl$'`
  do
    printf "${Green}[+] Importing policy $policy_hame from ${INIT_DIR_PATH}/${policy_file} ${NC}\n"
    policy_hame=`echo $policy_file | sed 's/-policy.hcl//g'`
    vault policy write $policy_hame ${INIT_DIR_PATH}/${policy_file}
    vault write auth/approle/role/$policy_hame policies="$policy_hame"

    role_id=`vault read auth/approle/role/$policy_hame/role-id -format=json | jq -r ".data.role_id"`
    secret_id=`vault write -f auth/approle/role/$policy_hame/secret-id -format=json | jq -r ".data.secret_id"`

    echo "$policy_hame $role_id $secret_id" >> ${INIT_KEYS_FILE}
    printf "${Green}[+] Role ID and Secret ID for $policy_hame wroted to ${INIT_KEYS_FILE} ${NC}\n"
  done

  if [ -f ${INIT_DIR_PATH}/vault_users.txt ]
  then
    printf "${Green}[+] Creating vault users ${NC}\n"
    vault auth enable userpass

    printf "${Green}  - Creating admin policy ${NC}\n"
    vault policy write admins ${INIT_DIR_PATH}/admin.hcl

    for line in `cat ${INIT_DIR_PATH}/vault_users.txt`
    do
      user_name=`echo $line | cut -d ':' -f1;`
      user_pass=`echo $line | cut -d ':' -f2;`

      vault write auth/userpass/users/${user_name} \
        password=${user_pass} \
        policies=admins
      printf "${Green} - Added user $user_name ${NC}\n"
    done
    rm -f ${INIT_DIR_PATH}/vault_users.txt
  fi

  for data_file in `ls ${INIT_DIR_PATH} | grep 'data.json$'`
  do
    printf "${Green}[+] Importing data from file $data_file... ${NC}\n"
    data_name=`echo $data_file | sed 's/-data.json//g'`
    DEFAULT_IFS=$IFS
    IFS='_'
    unset d_name
    read -ra ADDR <<< "$data_name"
    for d in "${ADDR[@]}"; do
        d_name+="/${d}"
    done
    IFS=$DEFAULT_IFS
    echo "$d_name"
    vault kv put cynkra${d_name} @$data_file
    printf "${Green} Done ${NC}\n"
  done

}

function unseal_vault {
  printf "${Green}[*] Unseal vault ${NC}\n"
  vault operator unseal -address=${VAULT_ADDR} $(grep 'Key 1:' ${INIT_KEYS_FILE} | awk '{print $NF}')
  vault operator unseal -address=${VAULT_ADDR} $(grep 'Key 2:' ${INIT_KEYS_FILE} | awk '{print $NF}')
  vault operator unseal -address=${VAULT_ADDR} $(grep 'Key 3:' ${INIT_KEYS_FILE} | awk '{print $NF}')
  printf "${Green}[+] Done ${NC}\n"
}

function login_auth {
  printf "${Green}[*] Auth to Vault${NC}\n"
  export VAULT_TOKEN=$(grep 'Initial Root Token:' ${INIT_KEYS_FILE} | awk '{print substr($NF, 1, length($NF))}')
  vault login -address=${VAULT_ADDR} ${VAULT_TOKEN}
}

function create_token {
  if [ "${1}none" == "none" ]
  then
    printf "${RED}[!] Error. create_token must get parameter ${NC}\n"
    exit 15
  fi
  ## CREATE TOKEN
  printf "${Green}[*] Create token ${1}${NC}\n"
  vault_token=`vault token create -policy=admins -address=${VAULT_ADDR} -display-name=${1} | awk '/token/{i++}i==1' | awk '{print $2}'`
  echo "${1}_token: ${vault_token}" >> ${INIT_KEYS_FILE}
  printf "${Green}[+] Done. Wrote down to ${INIT_KEYS_FILE} ${1} ${NC}\n"
}

################################################################################
##############################################################
# Creating user and group if needed
##############################################################
printf "${Green} Create group if needed ${NC}\n"

set +e

etc_group_id=`cat /etc/group | grep :$USER_GID: || echo "None"`
etc_group_name=`cat /etc/group | grep $VAULT_GROUP || echo "None"`

if [ "$etc_group_id" = "None" ] && [ "$etc_group_name" = "None" ]
then
	printf "${Green} Create group $VAULT_GROUP with id $USER_GID ${NC}\n"
	groupadd -g $USER_GID $VAULT_GROUP
elif [ "$etc_group_id" = "None" ] && [ "$etc_group_name" != "None" ]
then
	printf "${Green} Group with name $VAULT_GROUP already exist. Renaming it to conflict_group_name ${NC}\n"
  groupmod -n conflict_group_name $VAULT_GROUP
	printf "${Green} Create group $VAULT_GROUP with id $USER_GID ${NC}\n"
  groupadd -g $USER_GID $VAULT_GROUP
elif [ "$etc_group_name" = "None" ] && [ "$etc_group_id" != "None" ]
then
	printf "${Green} Group with GID $USER_GID already exists. Editing it to new GID 1090 ${NC}\n"
	old_group_name=`echo $etc_group_id | awk -F ":" '{print $1}'`
  groupmod -g 1090 $old_group_name
  printf "${Green} Create group $VAULT_GROUP with id $USER_GID ${NC}\n"
  groupadd -g $USER_GID $VAULT_GROUP
fi

etc_passwd_id=`cat /etc/passwd | grep :$USER_ID: || echo "None"`
etc_passwd_name=`cat /etc/passwd | grep ^$VAULT_USER: || echo "None"`

if [ "$etc_passwd_id" = "None" ] && [ "$etc_passwd_name" = "None" ]
then
  printf "${Green} Creating user with ID $USER_ID and name $VAULT_USER. Assigning to group ID $USER_GID ${NC}\n"
  useradd -s /bin/bash -m -u $USER_ID -g $USER_GID $VAULT_USER
elif [ "$etc_passwd_id" != "None" ] && [ "$etc_passwd_name" = "None" ]
then
  printf "${Green} User with ID $USER_ID already exists. Editing it to new ID 10067 ${NC}\n"
  usermod -g 10067 $USER_ID
  printf "${Green} Creating user with ID $USER_ID and name $VAULT_USER. Assigning to group ID $USER_GID ${NC}\n"
  useradd -s /bin/bash -m -u $USER_ID -g $USER_GID $VAULT_USER
elif [ "$etc_passwd_name" != "None" ] && [ "$etc_passwd_id" = "None" ]
then
  printf "${Green} User with name $VAULT_USER already exists. Rename it to user_conflict_name ${NC}\n"
  old_user_=`echo $etc_passwd_name| awk -F ":" '{print $1}'`
  usermod -l user_conflict_name $VAULT_USER
  printf "${Green} Creating user with ID $USER_ID and name $VAULT_USER. Assigning to group ID $USER_GID ${NC}\n"
  useradd -s /bin/bash -m -u $USER_ID -g $USER_GID $VAULT_USER
fi

################################################################################
# From original docker-entrypoint.sh
set -e
# Note above that we run dumb-init as PID 1 in order to reap zombie processes
# as well as forward signals to all processes in its session. Normally, sh
# wouldn't do either of these functions so we'd leak zombies as well as do
# unclean termination of all our sub-processes.

# Prevent core dumps
ulimit -c 0

# Allow setting VAULT_REDIRECT_ADDR and VAULT_CLUSTER_ADDR using an interface
# name instead of an IP address. The interface name is specified using
# VAULT_REDIRECT_INTERFACE and VAULT_CLUSTER_INTERFACE environment variables. If
# VAULT_*_ADDR is also set, the resulting URI will combine the protocol and port
# number with the IP of the named interface.
get_addr () {
    local if_name=$1
    local uri_template=$2
    ip addr show dev $if_name | awk -v uri=$uri_template '/\s*inet\s/ { \
      ip=gensub(/(.+)\/.+/, "\\1", "g", $2); \
      print gensub(/^(.+:\/\/).+(:.+)$/, "\\1" ip "\\2", "g", uri); \
      exit}'
}

if [ -n "$VAULT_REDIRECT_INTERFACE" ]; then
    export VAULT_REDIRECT_ADDR=$(get_addr $VAULT_REDIRECT_INTERFACE ${VAULT_REDIRECT_ADDR:-"http://0.0.0.0:8200"})
    echo "Using $VAULT_REDIRECT_INTERFACE for VAULT_REDIRECT_ADDR: $VAULT_REDIRECT_ADDR"
fi
if [ -n "$VAULT_CLUSTER_INTERFACE" ]; then
    export VAULT_CLUSTER_ADDR=$(get_addr $VAULT_CLUSTER_INTERFACE ${VAULT_CLUSTER_ADDR:-"https://0.0.0.0:8201"})
    echo "Using $VAULT_CLUSTER_INTERFACE for VAULT_CLUSTER_ADDR: $VAULT_CLUSTER_ADDR"
fi

# VAULT_CONFIG_DIR isn't exposed as a volume but you can compose additional
# config files in there if you use this image as a base, or use
# VAULT_LOCAL_CONFIG below.
VAULT_CONFIG_DIR=/vault/config

# You can also set the VAULT_LOCAL_CONFIG environment variable to pass some
# Vault configuration JSON without having to bind any volumes.
if [ -n "$VAULT_LOCAL_CONFIG" ]; then
    echo "$VAULT_LOCAL_CONFIG" > "$VAULT_CONFIG_DIR/local.json"
fi

# If the user is trying to run Vault directly with some arguments, then
# pass them to Vault.
if [ "${1:0:1}" = '-' ]; then
    set -- vault "$@"
fi

# Look for Vault subcommands.
if [ "$1" = 'server' ]; then
    shift
    set -- vault server \
        -config="$VAULT_CONFIG_DIR" \
        -dev-root-token-id="$VAULT_DEV_ROOT_TOKEN_ID" \
        -dev-listen-address="${VAULT_DEV_LISTEN_ADDRESS:-"0.0.0.0:8200"}" \
        "$@"
elif [ "$1" = 'version' ]; then
    # This needs a special case because there's no help output.
    set -- vault "$@"
elif vault --help "$1" 2>&1 | grep -q "vault $1"; then
    # We can't use the return code to check for the existence of a subcommand, so
    # we have to use grep to look for a pattern in the help output.
    set -- vault "$@"
fi

# If we are running Vault, make sure it executes as the proper user.
if [ "$1" = 'vault' ]; then
    # If the config dir is bind mounted then chown it
    if [ "$(stat -c %u /vault/config)" != "$(id -u $VAULT_USER)" ]; then
        chown -R $VAULT_USER:$VAULT_GROUP /vault/config || echo "Could not chown /vault/config (may not have appropriate permissions)"
    fi

    # If the logs dir is bind mounted then chown it
    if [ "$(stat -c %u /vault/logs)" != "$(id -u $VAULT_USER)" ]; then
        chown -R $VAULT_USER:$VAULT_GROUP /vault/logs
    fi

    # If the file dir is bind mounted then chown it
    if [ "$(stat -c %u /vault/file)" != "$(id -u $VAULT_USER)" ]; then
        chown -R $VAULT_USER:$VAULT_GROUP /vault/file
    fi

    if [ -z "$SKIP_SETCAP" ]; then
        # Allow mlock to avoid swapping Vault memory to disk
        setcap cap_ipc_lock=+ep $(readlink -f $(which vault))

        # In the case vault has been started in a container without IPC_LOCK privileges
        if ! vault -version 1>/dev/null 2>/dev/null; then
            >&2 echo "Couldn't start vault with IPC_LOCK. Disabling IPC_LOCK, please use --privileged or --cap-add IPC_LOCK"
            setcap cap_ipc_lock=-ep $(readlink -f $(which vault))
        fi
    fi

    if [ "$(id -u)" = '0' ]; then
      set -- su-exec vault "$@"
    fi
fi
################################################################################

if [ "$1" == "run_vault" ]
then
  update-ca-certificates
  printf "${Green} Starting vault daemon ${NC}\n"
  exec su-exec ${VAULT_USER}:${VAULT_GROUP} vault server -config=${CONF_PATH}
elif [ "$1" == "init_vault" ]
then
  if [ ! -f ${INIT_KEYS_FILE} ]
  then
    init_vault
    unseal_vault
    login_auth
    import_data
    create_token bootstrap
  else
    unseal_vault
  fi
  chown $VAULT_USER:$VAULT_GROUP ${INIT_KEYS_FILE}
else
	exec "$@"
fi
