package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"regexp"

	client "github.com/cryptvault-cloud/api"
	"github.com/cryptvault-cloud/helper"
	"github.com/urfave/cli/v2"
)

type ProtectedRunner struct {
	runner     *Runner
	api        *client.ProtectedApi
	privateKey *ecdsa.PrivateKey
	vaultId    *string
}

type ValueType string

const (
	ValueTypeString ValueType = "String"
	ValueTypeJSON   ValueType = "JSON"
)

var AllValueType = []ValueType{
	ValueTypeString,
	ValueTypeJSON,
}

var ValuePatternRegex *regexp.Regexp

const ValuePatternRegexStr = `^\((?P<directions>(r|w|d)+)\)(?P<target>(VALUES|IDENTITY|SYSTEM))(?P<pattern>(\.[a-z0-9_\->\*]+)+)$`

func init() {
	ValuePatternRegex = regexp.MustCompile(ValuePatternRegexStr)
}

func GetProtectedCommand(runner *Runner) *cli.Command {

	pRunner := &ProtectedRunner{runner: runner}
	return &cli.Command{
		Name:   "protected",
		Usage:  "All stuff where you need a private key and a vault id to handle",
		Before: pRunner.Before,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     CliProtectedHandlerKey,
				Aliases:  []string{"creds"},
				EnvVars:  []string{getFlagEnvByFlagName(CliProtectedHandlerKey)},
				Usage:    "Private key wich have rights to handle subcommand or path to private key ",
				Required: true,
			},
			&cli.StringFlag{
				Name:    CliProtectedVaultId,
				EnvVars: []string{getFlagEnvByFlagName(CliProtectedVaultId)},
				Usage:   "vaultid to handle subcommand",
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:  "add",
				Usage: "add new value or identity",
				Subcommands: []*cli.Command{
					{
						Name:   "identity",
						Usage:  "add a new identity",
						Action: pRunner.AddIdentity,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliAddIdentityName,
								EnvVars:  []string{getFlagEnvByFlagName(CliAddIdentityName)},
								Usage:    "Name of identity",
								Required: true,
							},
							&cli.StringSliceFlag{
								Name:    CliAddIdentityRights,
								Aliases: []string{"r"},
								EnvVars: []string{getFlagEnvByFlagName(CliAddIdentityRights)},
								Usage:   "Rights for the new identity",
								Action: func(ctx *cli.Context, s []string) error {
									var err error = nil
									for _, one := range s {
										if !ValuePatternRegex.Match([]byte(one)) {
											err = errors.Join(fmt.Errorf("Have to match right string pattern: %s", ValuePatternRegexStr))
										}
									}
									return err
								},
								Required: true,
							},
						},
					},
					{
						Name:  "value",
						Usage: "add a new value if value already exists it will be overwritten",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    CliAddValueName,
								EnvVars: []string{getFlagEnvByFlagName(CliAddValueName)},
								Usage:   "Key of value",
							},
							&cli.StringFlag{
								Name:    CliAddValuePassframe,
								EnvVars: []string{getFlagEnvByFlagName(CliAddValuePassframe)},
								Usage:   "Password of value",
							},
							&cli.StringFlag{
								Name:    CliAddValueType,
								EnvVars: []string{getFlagEnvByFlagName(CliAddValueType)},
								Usage:   "type of value String or JSON",
								Value:   "String",
							},
						},
						Action: pRunner.AddValue,
					},
				},
			},
			{
				Name:  "get",
				Usage: "Get Secrets, Identity",
				Subcommands: []*cli.Command{
					{
						Name:   "identity",
						Usage:  "returns information over identity ",
						Action: pRunner.GetIdentity,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliGetIdentityId,
								EnvVars:  []string{getFlagEnvByFlagName(CliGetIdentityId)},
								Usage:    "IdentityId to looking for",
								Required: true,
							},
						},
					},
					{
						Name:   "value",
						Usage:  "returns the secret",
						Action: pRunner.GetValue,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliGetValueName,
								EnvVars:  []string{getFlagEnvByFlagName(CliGetValueName)},
								Usage:    "Value name something like VALUES.a.b",
								Required: true,
							},
						},
					},
				},
			},
			{
				Name:  "delete",
				Usage: "Get Secrets, Identity",
				Subcommands: []*cli.Command{
					{
						Name:   "vault",
						Usage:  "Delete an empty vault",
						Action: pRunner.DeleteVault,
					},
					{
						Name:   "identity",
						Usage:  "Delete an identity",
						Action: pRunner.DeleteIdentity,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliDeleteIdentityId,
								EnvVars:  []string{getFlagEnvByFlagName(CliDeleteIdentityId)},
								Usage:    "ID of identity",
								Required: true,
							},
						},
					},
					{
						Name:   "value",
						Usage:  "Delete an value",
						Action: pRunner.DeleteValue,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliDeleteValueName,
								EnvVars:  []string{getFlagEnvByFlagName(CliDeleteValueName)},
								Usage:    "Name of value to delete",
								Required: true,
							},
						},
					},
				},
			},
			{
				Name:   "authToken",
				Usage:  "Generate JWT-Authtoken",
				Action: pRunner.GenerateAuthToken,
			},
		},
	}
}

func (r *ProtectedRunner) Before(c *cli.Context) error {
	pemKeyOrPath := c.String(CliProtectedHandlerKey)
	pemKey := ""
	if _, err := os.Stat(pemKeyOrPath); errors.Is(err, os.ErrNotExist) {
		// path does not exist so it have to be private key directly
		pemKey = pemKeyOrPath
	} else {
		t, err := r.runner.fileHandler.ReadTextFile(pemKeyOrPath)
		if err != nil {
			return err
		}
		pemKey = t
	}
	privKey, err := helper.GetPrivateKeyFromB64String(pemKey)
	if err != nil {
		return err
	}
	vaultId := c.String(CliProtectedVaultId)
	if vaultId == "" {
		vault, err := r.runner.fileHandler.SelectedVault()
		if err != nil {
			return err
		}
		vaultId, err = r.runner.fileHandler.ReadTextFile(fmt.Sprintf("%s/vaultId", vault))
		if err != nil {
			return err
		}
	}
	r.privateKey = privKey
	r.vaultId = &vaultId

	r.api = r.runner.api.GetProtectedApi(privKey, vaultId)
	return nil
}

func (r *ProtectedRunner) AddValue(c *cli.Context) error {
	valueType := c.String(CliAddValueType)
	if !helper.Includes(AllValueType, func(v ValueType) bool { return valueType == string(v) }) {
		return fmt.Errorf("not allowed Type")
	}
	id, err := r.api.AddValue(c.String(CliAddValueName), c.String(CliAddValuePassframe), client.ValueType(valueType))
	if err != nil {
		return err
	}
	fmt.Printf("ValueID = %s \n", id)
	return nil
}

func getRightInputs(rights []string) ([]*client.RightInput, error) {
	rightInputs := make([]*client.RightInput, 0)
	var errs error = nil
	for _, v := range rights {
		tmp, err := client.GetRightDescriptionByString(v)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("error by right %s :%s", v, err.Error()))
			continue
		}
		for _, tmpV := range tmp {
			rightInputs = append(rightInputs, &client.RightInput{
				Target:            tmpV.Target,
				Right:             tmpV.Right,
				RightValuePattern: tmpV.RightValue,
			})
		}
	}
	return rightInputs, errs
}

func (r *ProtectedRunner) AddIdentity(c *cli.Context) error {
	rights := c.StringSlice(CliAddIdentityRights)
	name := c.String(CliAddIdentityName)
	rightInputs, err := getRightInputs(rights)
	if err != nil {
		return err
	}

	res, err := r.api.CreateIdentity(name, rightInputs)
	if err != nil {
		return err
	}

	values, err := r.api.GetAllRelatedValues(res.IdentityId)
	if err != nil {
		return err
	}
	for _, v := range values {
		err := r.api.SyncValue(v)
		if err != nil {
			return err
		}
	}

	vaultName, err := r.runner.fileHandler.SelectedVault()
	if err != nil {
		return err
	}
	b64PubKey, err := helper.GetB64FromPublicKey(res.PublicKey)
	if err != nil {
		return err
	}
	b64PrivKey, err := helper.GetB64FromPrivateKey(res.PrivateKey)
	if err != nil {
		return err
	}
	r.runner.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/key.pub", vaultName, name), b64PubKey)
	r.runner.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/key", vaultName, name), b64PrivKey)
	r.runner.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/id", vaultName, name), res.IdentityId)
	fmt.Printf("Identity with id %s created", res.IdentityId)
	return nil
}

type rigthHandler interface {
	GetRightValuePattern() string
	GetRight() client.Directions
}

func (r *ProtectedRunner) GetIdentity(c *cli.Context) error {
	id := c.String(CliGetIdentityId)
	res, err := r.api.GetIdentity(id)
	if err != nil {
		return err
	}

	rigthstr := make([]string, len(res.Rights))

	for i, v := range res.Rights {
		rigthstr[i] = fmt.Sprintf("(%s)%s", v.Right, v.RightValuePattern)
	}

	fmt.Printf("ID: %s\nName: %s\nRights: %s\n", res.Id, *res.Name, rigthstr)
	return nil
}

func (r *ProtectedRunner) GetValue(c *cli.Context) error {
	name := c.String(CliGetValueName)
	value, err := r.api.GetValueByName(name)
	if err != nil {
		return err
	}
	values := make([]client.EncryptenValue, 0)
	for _, v := range value.GetValue() {
		values = append(values, v)
	}
	passframe, err := r.api.GetDecryptedPassframe(values)
	if err != nil {
		return err
	}
	fmt.Println(passframe)
	return nil
}

func (r *ProtectedRunner) GenerateAuthToken(c *cli.Context) error {
	jwt, err := helper.SignJWT(r.privateKey, *r.vaultId)
	if err != nil {
		return err
	}
	fmt.Println(jwt)
	return nil
}

func (r *ProtectedRunner) DeleteVault(c *cli.Context) error {

	err := r.api.DeleteVault(*r.vaultId)
	if err != nil {
		return err
	}
	fmt.Println("Vault Deleted")
	return nil

}

func (r *ProtectedRunner) DeleteIdentity(c *cli.Context) error {
	vaultName, err := r.runner.fileHandler.SelectedVault()
	if err != nil {
		return err
	}

	identityIdToDelete := c.String(CliDeleteIdentityId)
	res, err := r.api.GetIdentity(identityIdToDelete)
	if err != nil {
		return err
	}
	err = r.api.DeleteIdentity(identityIdToDelete)
	if err != nil {
		return err
	}
	err = r.runner.fileHandler.DeleteFolder(fmt.Sprintf("%s/identity/%s", vaultName, *res.Name))
	if err != nil {
		return err
	}
	fmt.Println("Identity Deleted")
	return nil
}

func (r *ProtectedRunner) DeleteValue(c *cli.Context) error {
	nameOfValue2Delete := c.String(CliDeleteValueName)
	value, err := r.api.GetValueByName(nameOfValue2Delete)
	if err != nil {
		return err
	}
	err = r.api.DeleteValue(value.Id)
	if err != nil {
		return err
	}
	fmt.Println("Value deleted")
	return nil
}
