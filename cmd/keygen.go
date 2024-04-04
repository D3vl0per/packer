package main

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/D3vl0per/crypt/aged"
	"github.com/D3vl0per/crypt/generic"
	"github.com/pelletier/go-toml"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

type Keys struct {
	PublicKey  string `json:"public_key" yaml:"public_key" toml:"public_key"`
	PrivateKey string `json:"private_key" yaml:"private_key" toml:"private_key"`
}

func Keygen(c *cli.Context) error {
	keys, err := generateKeys(c.Int("number"))
	if err != nil {
		return err
	}

	payload, err := formatKeys(keys, c.String("format"))
	if err != nil {
		return err
	}

	output := c.Path("output")
	if output == "" {
		_, err = os.Stdout.Write(payload)
		return err
	}

	return writeToFile(output, payload)
}

func generateKeys(number int) ([]Keys, error) {
	var keys []Keys
	for i := 0; i < number; i++ {
		keypair, err := aged.GenKeypair()
		if err != nil {
			return nil, err
		}

		keys = append(keys, Keys{
			PublicKey:  keypair.Recipient().String(),
			PrivateKey: keypair.String(),
		})
	}
	return keys, nil
}

func formatKeys(keys []Keys, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.Marshal(keys)
	case "yaml":
		return yaml.Marshal(keys)
	case "toml":
		return toml.Marshal(keys)
	default:
		return formatKeysAsTable(keys), nil
	}
}

func formatKeysAsTable(keys []Keys) []byte {
	tableData := pterm.TableData{
		{pterm.FgGreen.Sprint("Public Key"), pterm.FgRed.Sprint("Private key")},
	}

	for _, key := range keys {
		tableData = append(tableData, []string{pterm.BgGreen.Sprint(key.PublicKey), pterm.BgRed.Sprint(key.PrivateKey)})
	}

	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
	return nil
}

func writeToFile(path string, data []byte) error {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return errors.New(generic.StrCnct([]string{
			"path ", path, " is a directory, not a file"}...))
	}

	return os.WriteFile(path, data, 0644)
}
