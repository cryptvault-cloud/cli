# CryptVault.cloud client CLi

This is the Cli tool for communicating/manage with the [CryptVault](https://cryptvault.cloud).



# Commands:

```
NAME:
   vault-cli - vault-cli

USAGE:
   vault-cli [global options] command [command options] [arguments...]

COMMANDS:
   local         To handle with local files
   create_vault  Create a new Vault
   protected     All stuff where you need a private key and a vault id to handle
   help, h       Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --logLevel value        Loglevel debug, info, warn, error (default: "info") [$VAULT_CLI_LOGLEVEL]
   --serverUrl value       Endpoint where api is running (default: "https://api.cryptvault.cloud/query") [$VAULT_CLI_SERVERURL]
   --should_save_to_file   Should created information be saved to a folder structure (default: true) [$VAULT_CLI_SHOULD_SAVE_TO_FILE]
   --save_file_path value  Path to folder where to save all created data (default: "./.cryptvault/") [$VAULT_CLI_SAVE_FILE_PATH]
   --help, -h              show help

```
**Local commands:**
```
NAME:
   vault-cli local - To handle with local files

USAGE:
   vault-cli local command [command options] [arguments...]

COMMANDS:
   init            create a local workspace for an already exist Vault
   list-vault      All local available Vaults
   selected-vault  Which vault is current selected
   select-vault    Set current selected vault
   help, h         Shows a list of commands or help for one command

OPTIONS:
   --help, -h  show help
```

**Protected Commands:**
```
NAME:
   vault-cli protected - All stuff where you need a private key and a vault id to handle

USAGE:
   vault-cli protected command [command options] [arguments...]

COMMANDS:
   add        add new value or identity
   get        Get Secrets, Identity
   delete     Get Secrets, Identity
   authToken  Generate JWT-Authtoken
   help, h    Shows a list of commands or help for one command

OPTIONS:
   --handlerkey value, --creds value  Private key wich have rights to handle subcommand or path to private key [$VAULT_CLI_HANDLERKEY]
   --vaultid value                    vaultid to handle subcommand [$VAULT_CLI_VAULTID]
   --help, -h                         show help
```



# How to install

### With go

```
go install github.com/cryptvault-cloud/vault-cli@latest
```

### With Docker
You can also use the supplied docker image.
But make sure to mount your destination folder to /work

```sh
docker run -v .:/work ghcr.io/cryptvault-cloud/vault-cli:latest --help
```


# Over download
Go to the release and download the binary you need for your OS

# Getting start

Follow the documentation at [CryptVault.cloud](https://cryptvault.cloud/guides/create_your_cryptvault/overview)
