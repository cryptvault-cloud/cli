package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	client "github.com/cryptvault-cloud/api"
	"github.com/cryptvault-cloud/cli/logger"
	"github.com/cryptvault-cloud/helper"
	"github.com/urfave/cli/v2"
)

const (
	CliLogLevel            = "logLevel"
	CliServerUrl           = "serverUrl"
	CliSaveToFile          = "should_save_to_file"
	CliInitVaultName       = "vaultName"
	CliInitVaultToken      = "vaultToken"
	CliAuthTokenPrivateKey = "authTokenPrivateKey"
	CliAuthTokenVaultId    = "authTokenVaultId"
	CliProtectedHandlerKey = "handlerkey"
	CliProtectedVaultId    = "vaultid"
	CliAddValueName        = "name"
	CliAddIdentityName     = "name"
	CliAddIdentityRights   = "rights"
	CliGetIdentityId       = "id"
	CliGetValueName        = "name"
	CliAddValuePassframe   = "passframe"
	CliAddValueType        = "type"
	CliSaveFilePath        = "save_file_path"
	CliDeleteIdentityId    = "id"
	CliDeleteValueName     = "name"
	App                    = "VAULT_CLI"
)

func getFlagEnvByFlagName(flagName string) string {
	return fmt.Sprintf("%s_%s", App, strings.ToUpper(flagName))
}

func main() {
	runner := Runner{}

	app := &cli.App{
		Usage: "vault-cli",
		Flags: []cli.Flag{

			&cli.StringFlag{
				Name:    CliLogLevel,
				EnvVars: []string{getFlagEnvByFlagName(CliLogLevel)},
				Value:   "info",
				Usage:   "Loglevel debug, info, warn, error",
			},
			&cli.StringFlag{
				Name:    CliServerUrl,
				EnvVars: []string{getFlagEnvByFlagName(CliServerUrl)},
				Value:   "https://api.cryptvault.cloud/query",
				Usage:   "Endpoint where api is running",
			},
			&cli.BoolFlag{
				Name:    CliSaveToFile,
				EnvVars: []string{getFlagEnvByFlagName(CliSaveToFile)},
				Usage:   "Should created information be saved to a folder structure",
				Value:   true,
			},
			&cli.StringFlag{
				Name:    CliSaveFilePath,
				EnvVars: []string{getFlagEnvByFlagName(CliSaveFilePath)},
				Value:   "./.cryptvault/",
				Usage:   "Path to folder where to save all created data",
			},
		},
		Before: runner.Before,
		Commands: []*cli.Command{
			{
				Name:  "local",
				Usage: "To handle with local files",
				Subcommands: []*cli.Command{
					{
						Name:   "list-vault",
						Usage:  "All local available Vaults",
						Action: runner.LocalListVault,
					},
					{
						Name:   "selected-vault",
						Usage:  "Which vault is current selected",
						Action: runner.LocalSelectedVault,
					},
					{
						Name:   "select-vault",
						Usage:  "Set current selected vault",
						Action: runner.LocalSelectVault,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "vault",
								Usage:    "The vaultname to set",
								Required: true,
							},
						},
					},
				},
			},
			{
				Name:   "create_vault",
				Usage:  "Create a new Vault",
				Action: runner.create_vault,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     CliInitVaultName,
						Aliases:  []string{"vault-name"},
						Required: true,
						Usage:    "Name of the new Vault to init",
					},
					&cli.StringFlag{
						Name:     CliInitVaultToken,
						Aliases:  []string{"token"},
						Required: true,
						Usage:    "Token to verify vault generation is allowed",
					},
				},
			},
			GetProtectedCommand(&runner),
		},
	}
	if err := app.Run(os.Args); err != nil {
		logger.Get().Panicw("Application start failed", "error", err)
	}
}

type Runner struct {
	api         client.Api
	fileHandler FileHandling
}

func (r *Runner) LocalListVault(c *cli.Context) error {
	vaults, err := r.fileHandler.AvailableVaults()
	if err != nil {
		return err
	}
	for _, v := range vaults {
		fmt.Println(v)
	}
	return nil
}

func (r *Runner) LocalSelectedVault(c *cli.Context) error {
	t, err := r.fileHandler.SelectedVault()
	if err != nil {
		return err
	}
	fmt.Println(string(t))
	return nil
}

func (r *Runner) LocalSelectVault(c *cli.Context) error {
	vaultName := c.String("vault")
	vaults, err := r.fileHandler.AvailableVaults()
	if err != nil {
		return err
	}
	if helper.Includes[string](vaults, func(s string) bool { return s == vaultName }) {
		r.fileHandler.SaveTextToFile("/currentVault.txt", vaultName)
	} else {
		return fmt.Errorf("Vault not found... ")
	}
	return nil
}

func (r *Runner) Before(c *cli.Context) error {
	_, err := logger.Initialize(c.String(CliLogLevel))

	r.api = client.NewApi(c.String(CliServerUrl), http.DefaultClient)
	if c.Bool(CliSaveToFile) {
		r.fileHandler = &FileHandler{
			RootPath: c.String(CliSaveFilePath),
		}
		err = r.fileHandler.Init()
		if err != nil {
			return err
		}
	} else {
		r.fileHandler = &FileHandlerMock{}
	}

	return err
}

func (r *Runner) create_vault(c *cli.Context) error {
	vaultName := c.String(CliInitVaultName)
	privKey, pubKey, vaultID, err := r.api.NewVault(vaultName, c.String(CliInitVaultToken))
	if err != nil {
		return err
	}

	b64PubKey, err := helper.GetB64FromPublicKey(pubKey)
	if err != nil {
		return err
	}
	b64PrivKey, err := helper.GetB64FromPrivateKey(privKey)
	if err != nil {
		return err
	}
	fmt.Printf("VaultId:\t%s\n", vaultID)
	fmt.Printf("Private Key:\n%s\n", b64PrivKey)
	fmt.Printf("Public Key:\n%s\n", b64PubKey)

	err = errors.Join(r.fileHandler.SaveTextToFile("/currentVault.txt", vaultName), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/vaultId", vaultName), vaultID), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/operator/key.pub", vaultName), b64PubKey), err)
	err = errors.Join(r.fileHandler.SaveTextToFile(fmt.Sprintf("%s/operator/key", vaultName), b64PrivKey), err)
	return err

}
