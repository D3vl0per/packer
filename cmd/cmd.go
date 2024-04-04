package main

import (
	"os"
	"time"

	"github.com/pterm/pterm"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:        "Packer",
		Usage:       "compress and encrypt a file or directory",
		Description: "Packer is a tool for packing and unpacking payloads and configuration files securely",
		Version:     "v0.0.1",
		Compiled:    time.Now(),
		Authors: []*cli.Author{
			{
				Name:  "D3v",
				Email: "mark@zsibok.hu",
			},
		},
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "pack",
				Usage: "Compress and encrypt a file or directory",
				Flags: []cli.Flag{
					&cli.PathFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Usage:   "Input file name",
					},
					&cli.PathFlag{
						Name:    "directory",
						Aliases: []string{"d"},
						Usage:   "Input directory name",
					},
					&cli.PathFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output file",
					},
					&cli.StringSliceFlag{
						Name:    "recepients",
						Aliases: []string{"r"},
						Usage:   "Recepients public keys (comma separated if more than one)",
					},
				},
				Before: func(cCtx *cli.Context) error {
					file := cCtx.Path("file")
					directory := cCtx.Path("directory")
					recepients := cCtx.StringSlice("recepients")

					if file == "" && directory == "" {
						_ = cli.ShowSubcommandHelp(cCtx)
						return cli.Exit("Input file flag are required", 2)
					}

					if directory != "" && file != "" {
						_ = cli.ShowSubcommandHelp(cCtx)
						return cli.Exit("Only one input file or directory flag is allowed", 2)
					}

					isAutoconfEnable, err := IsAutoconfEnabled()
					if err != nil {
						return err
					}

					if !isAutoconfEnable && len(recepients) == 0 {
						_ = cli.ShowSubcommandHelp(cCtx)
						return cli.Exit("Recepients public key is required", 2)
					}

					return nil
				},
				Action: PackIt,
			},
			{
				Name:  "unpack",
				Usage: "Decrypt and decompress",
				Flags: []cli.Flag{
					&cli.PathFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Usage:   "Input file",
					},
					&cli.PathFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output file or directory",
					},
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "Private key",
					},
				},
				Before: func(cCtx *cli.Context) error {
					file := cCtx.Path("file")
					key := cCtx.String("key")
					output := cCtx.Path("output")

					if file == "" {
						_ = cli.ShowSubcommandHelp(cCtx)
						return cli.Exit("Input flag is required", 2)
					}

					_, err := os.Stat(file)
					if os.IsNotExist(err) {
						_ = cli.ShowSubcommandHelp(cCtx)
						return cli.Exit("Input file does not exist", 2)
					} else if err != nil {
						return err
					}

					if output != "" {
						_, err := os.Stat(output)
						if !os.IsNotExist(err) {
							_ = cli.ShowSubcommandHelp(cCtx)
							return cli.Exit("Output file is already exist", 2)
						} else if err != nil {
							return err
						}
					}

					isAutoconfEnable, err := IsAutoconfEnabled()
					if err != nil {
						return err
					}

					if !isAutoconfEnable && key == "" {
						_ = cli.ShowSubcommandHelp(cCtx)
						return cli.Exit("Private key is required", 2)
					}

					if checkPrivateKeyFormat(key) {
						return cli.Exit("Invalid private key format", 2)
					}

					return nil
				},
				Action: UnpackIt,
			},
			{
				Name:  "keygen",
				Usage: "Generate a new key pair",
				Flags: []cli.Flag{
					&cli.PathFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Save keypair to file",
					},
					&cli.StringFlag{
						Name:        "format",
						Aliases:     []string{"f"},
						Usage:       "Output format (json,yaml,toml)",
						DefaultText: "json",
					},
					&cli.IntFlag{
						Name:    "number",
						Aliases: []string{"n"},
						Usage:   "Number of key pairs to generate",
						Value:   1,
					},
				},
				Before: func(cCtx *cli.Context) error {

					output := cCtx.Path("output")
					if output != "" {
						_, err := os.Stat(output)
						if !os.IsNotExist(err) {
							_ = cli.ShowSubcommandHelp(cCtx)
							return cli.Exit("Output file is already exist", 2)
						} else if err != nil {
							return err
						}
					}

					format := cCtx.String("format")

					switch format {
					case "", "json", "yaml", "toml":
					default:
						_ = cli.ShowSubcommandHelp(cCtx)
						return cli.Exit("Invalid export format", 2)
					}

					return nil
				},
				Action: Keygen,
			},
			{
				Name:  "autoconf",
				Usage: "Automagical configure the packer, it embed the public and private key into the binary",
				Subcommands: []*cli.Command{
					{
						Name:  "setup",
						Usage: "Setup the autoconf",
						Flags: []cli.Flag{
							&cli.StringSliceFlag{
								Name:    "recepients",
								Aliases: []string{"r"},
								Usage:   "Recepients public keys",
							},
							&cli.StringSliceFlag{
								Name:    "note",
								Aliases: []string{"n"},
								Usage:   "Note for the recepients",
							},
							&cli.StringSliceFlag{
								Name:    "keys",
								Aliases: []string{"k"},
								Usage:   "Private keys",
							},
							&cli.StringSliceFlag{
								Name:    "keynote",
								Aliases: []string{"kn"},
								Usage:   "Note for private keys",
							},
						},
						Before: func(cCtx *cli.Context) error {
							recepients := cCtx.StringSlice("recepients")
							note := cCtx.StringSlice("note")
							keys := cCtx.StringSlice("keys")
							keynote := cCtx.StringSlice("keynote")

							if len(recepients) == 0 && len(note) == 0 {
								_ = cli.ShowSubcommandHelp(cCtx)
								return cli.Exit("Recepients public key is required", 2)
							}

							if len(recepients) != len(note) {
								_ = cli.ShowSubcommandHelp(cCtx)
								return cli.Exit("Recepients public key and note number must be equal", 2)
							}

							if len(keys) != 0 && len(keynote) != 0 {
								_ = cli.ShowSubcommandHelp(cCtx)
								return cli.Exit("Private key or note is required", 2)
							}

							if len(keys) != len(keynote) {
								_ = cli.ShowSubcommandHelp(cCtx)
								return cli.Exit("Private key and note number must be equal", 2)
							}

							return nil

						},
						Action: SetupAutoconf,
					},
					{
						Name:  "check",
						Usage: "Check the autoconf current stored informations",
						Before: func(cCtx *cli.Context) error {
							isAutoconfEnable, err := IsAutoconfEnabled()
							if err != nil {
								return err
							}

							if !isAutoconfEnable {
								_ = cli.ShowSubcommandHelp(cCtx)
								return cli.Exit("Autoconf is not enabled", 2)
							}

							return nil
						},
						Action: CheckAutoconf,
					},
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		pterm.Error.Println(err)
	}
}
