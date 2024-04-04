package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/D3vl0per/crypt/aged"
	"github.com/D3vl0per/crypt/generic"
	"github.com/klauspost/compress/zstd"
	"github.com/mholt/archiver/v4"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v2"
)

func UnpackIt(c *cli.Context) error {
	file := c.Path("file")
	key := c.String("key")
	output := c.Path("output")

	var err error
	if output == "" {
		output, err = os.Getwd()
		if err != nil {
			return err
		}
	}

	isEnabledAutocfg, err := IsAutoconfEnabled()
	if err != nil {
		return err
	}

	var profiles []AutoConfigPrivateKeys
	if isEnabledAutocfg {
		pterm.Warning.Println("Autoconf detected")
		config, cfgHashStr, err := GetAutoconf()
		if err != nil {
			return err
		}

		renderStoredProperties(config, cfgHashStr)
		for _, profile := range config.PrivateKeys {
			if !checkPrivateKeyFormat(profile.PrivateKey) {
				return errors.New("invalid private key format")
			}

			profiles = append(profiles, profile)
		}
	} else {
		pterm.Debug.Println("key", key)
		profiles = append(profiles, AutoConfigPrivateKeys{
			Note:       "User provided private key",
			PrivateKey: key,
		})
	}

	if len(profiles) > 1 {
		pterm.Warning.Println("Multiple private keys detected")
		pterm.Warning.Println("Trying to decrypt with each key")
	}

	multi := pterm.DefaultMultiPrinter
	progress, _ := pterm.DefaultProgressbar.WithTotal(100).WithWriter(multi.NewWriter()).Start("progress")
	multi.Start()

	openFile, err := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Open file... ")
	if err != nil {
		return err
	}

	filePath, err := os.Open(file)
	if err != nil {
		openFile.Fail("Failed to open file")
		return err
	}

	blob, err := io.ReadAll(filePath)
	if err != nil {
		openFile.Fail("Failed to open file")
		return err
	}
	openFile.Success("File read")
	progress.Add(10)

	decrypt, err := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Decrypting... ")
	if err != nil {
		return err
	}

	var compressedData []byte
	for _, profile := range profiles {
		pterm.Info.Println("Decrypting with", profile.Note, "key")
		keychain, err := aged.SetupKeychain(aged.SetupKeychainParameters{
			SecretKey:     key,
			SelfRecipient: false,
		})
		if err != nil {
			if len(profiles) > 1 {
				pterm.Warning.Println("Failed to decrypt with", profile.Note, "key")
			} else {
				return err
			}
		}

		compressedData, err = keychain.Decrypt(aged.Parameters{
			Data:        blob,
			Compress:    false,
			Obfuscation: false,
		})
		if err != nil {
			if len(profiles) > 1 {
				pterm.Warning.Println("Failed to decrypt with", profile.Note, "key")
				continue
			} else {
				return errors.New(generic.StrCnct([]string{"failed to decrypt file with", profile.Note, "key", err.Error()}...))
			}
		}

		progress.Add(30)
		decrypt.Success("File decrypted")
		break
	}

	decompress, err := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Decompressing... ")
	if err != nil {
		return err
	}

	format := archiver.CompressedArchive{
		Compression: archiver.Zstd{
			EncoderOptions: []zstd.EOption{
				zstd.WithEncoderLevel(zstd.SpeedBestCompression),
			},
		},
		Archival: archiver.Tar{},
	}

	handler := func(ctx context.Context, f archiver.File) error {
		if progress.Current < progress.Total {
			progress.Add(1)
		}

		fullPath := filepath.Join(output, f.Name())

		if f.IsDir() {
			err := os.MkdirAll(fullPath, 0755)
			if err != nil {
				return err
			}
		} else {

			payload, err := f.Open()
			if err != nil {
				return err
			}
			defer payload.Close()

			outFile, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				return err
			}
			defer outFile.Close()

			_, err = io.Copy(outFile, payload)
			if err != nil {
				return err
			}
		}

		return nil
	}

	reader := bytes.NewReader(compressedData)

	err = format.Extract(context.Background(), reader, nil, handler)
	if err != nil {
		decompress.Fail("Failed to decompress file")
		return err
	}
	progress.Add(progress.Total - progress.Current)

	decompress.Success("File decompressed")

	progress.Stop()
	multi.Stop()
	return nil
}
