package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/D3vl0per/crypt/aged"
	"github.com/D3vl0per/crypt/generic"
	"github.com/klauspost/compress/zstd"
	"github.com/mholt/archiver/v4"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v2"
)

type PackItParams struct {
}

func PackIt(c *cli.Context) error {
	file := c.Path("file")
	directory := c.Path("directory")
	output := c.Path("output")
	recepients := c.StringSlice("recepients")

	isAutoconfEnable, err := IsAutoconfEnabled()
	if err != nil {
		return err
	}

	if isAutoconfEnable {
		pterm.Warning.Println("Autoconf detected")
		config, cfgHashStr, err := GetAutoconf()
		if err != nil {
			return err
		}

		renderStoredProperties(config, cfgHashStr)
		for _, profile := range config.PublicKeys {
			recepients = append(recepients, profile.PublicKey)
		}
	}

	multi := pterm.DefaultMultiPrinter
	progress, _ := pterm.DefaultProgressbar.WithTotal(100).WithWriter(multi.NewWriter()).Start("progress")
	multi.Start()

	var files []archiver.File
	var filename string
	if directory != "" {
		_, err := os.Stat(directory)
		if os.IsNotExist(err) {
			return errors.New("directory does not exist")
		} else if err != nil {
			return err
		} else {
			files, err = archiver.FilesFromDisk(nil, map[string]string{
				directory: "",
			})
			if err != nil {
				return err
			}

			filename = filepath.Dir(directory)
		}
	}

	if file != "" {
		_, err := os.Stat(file)
		if os.IsNotExist(err) {
			return errors.New("file does not exist")
		} else if err != nil {
			return err
		} else {
			filename = filepath.Base(file)

			files, err = archiver.FilesFromDisk(nil, map[string]string{
				file: filename,
			})
			if err != nil {
				return err
			}
		}
	}

	if output != "" {
		filename = generic.StrCnct([]string{output, ".age"}...)
	} else {
		filename = generic.StrCnct([]string{filename, ".age"}...)
	}

	format := archiver.CompressedArchive{
		Compression: archiver.Zstd{
			EncoderOptions: []zstd.EOption{
				zstd.WithEncoderLevel(zstd.SpeedBestCompression),
			},
		},
		Archival: archiver.Tar{},
	}

	progress.Add(10)

	compression, err := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Compress files... ")
	if err != nil {
		return err
	}

	var out bytes.Buffer
	err = format.Archive(context.Background(), &out, files)
	if err != nil {
		compression.Fail("failed to compress files")
		return err
	}

	compression.Success("Files compressed")
	progress.Add(30)

	tmpKey, err := aged.GenKeypair()
	if err != nil {
		return err
	}

	keychain, err := aged.SetupKeychain(aged.SetupKeychainParameters{
		SecretKey:     tmpKey.String(),
		PublicKeys:    recepients,
		SelfRecipient: false,
	})
	if err != nil {
		return err
	}

	encrypt, err := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Encrypt compressed files... ")
	if err != nil {
		return err
	}

	payload, err := keychain.Encrypt(aged.Parameters{
		Data:        out.Bytes(),
		Compress:    false,
		Obfuscation: false,
	})
	if err != nil {
		encrypt.Fail("failed to encrypt files")
		return err
	}

	encrypt.Success("Data encrypted")
	progress.Add(30)

	saveFile, err := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start("Save compressed and encrypted file... ")
	if err != nil {
		return err
	}

	blob, err := os.Create(filename)
	if err != nil {
		saveFile.Fail("failed to save encrypted file")
		return err
	}
	defer blob.Close()

	_, err = blob.Write(payload)
	if err != nil {
		saveFile.Fail("failed to save encrypted file")
		return err
	}

	blob.Close()
	blob.Sync()
	saveFile.Success("Compressed and encrypted file saved")
	progress.Add(30)
	progress.Stop()
	multi.Stop()
	return nil
}
