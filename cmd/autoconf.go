package main

import (
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "regexp"
    "strconv"
    "time"

    "github.com/D3vl0per/crypt/generic"
    "github.com/D3vl0per/crypt/hash"
    "github.com/D3vl0per/packer/internal/elf"
    "github.com/pterm/pterm"
    "github.com/urfave/cli/v2"
)

type AutoConfigPublicKeys struct {
    PublicKey string `json:"public_key"`
    Note      string `json:"note"`
}

type AutoConfigPrivateKeys struct {
    PrivateKey string `json:"private_key"`
    Note       string `json:"note"`
}

type Compresison struct {
    Algorithm    string `json:"algorithm"`
    EncoderLevel int    `json:"encoder_level"`
}

type AutoConfig struct {
    PublicKeys   []AutoConfigPublicKeys  `json:"public_keys"`
    PrivateKeys  []AutoConfigPrivateKeys `json:"private_keys"`
    Compression  Compresison             `json:"compression"`
    BinaryHash   string                  `json:"binary_hash"`
    CreationDate string                  `json:"creation_date"`
    binarySize   int
    configSize   int
}

const AgePublicKeyPattern = "^age1[A-Z2-7]{56}$"
const AgePrivateKeyPattern = "^AGE-SECRET-KEY-1[A-Z0-9]{51}$"

func SetupAutoconf(c *cli.Context) error {
    var config AutoConfig
    config.CreationDate = time.Now().Format(time.RFC3339)

    err := config.populateKeychain(c.StringSlice("recepients"), c.StringSlice("note"), c.StringSlice("keys"), c.StringSlice("keynote"))
    if err != nil {
        return err
    }

    err = config.calculateBinaryHash()
    if err != nil {
        return err
    }

    cfgBlob, cfgHash, err := config.marshal()
    if err != nil {
        return err
    }

    execPath, err := os.Executable()
    if err != nil {
        return err
    }

    binary, err := generic.ReadFileContent(execPath)
    if err != nil {
        return err
    }

    autoconfBinary := make([]byte, config.binarySize+config.configSize)
    copy(autoconfBinary, binary)
    copy(autoconfBinary[len(binary):], cfgBlob)

    filename := filepath.Base(execPath) + "-af"

    file, err := os.Create(filename)
	if err != nil {
        return err
    }
    defer file.Close()

    _, err = file.Write(autoconfBinary)
    if err != nil {
        return err
    }

    err = os.Chmod(filename, 0755)
    if err != nil {
        return err
    }

    renderStoredProperties(config, cfgHash)

    return nil
}

func IsAutoconfEnabled() (bool, error) {
    execPath, err := os.Executable()
    if err != nil {
        return false, err
    }

    isDiff, err := elf.CheckSizeDiff(execPath)
    if err != nil {
        return false, err
    }

    if !isDiff {
        return false, nil
    }

    return true, nil
}

func CheckAutoconf(c *cli.Context) error {
    execPath, err := os.Executable()
    if err != nil {
        return err
    }

    config, cfgHash, err := checkIntegrity(execPath)
    if err != nil {
        return err
    }

    pterm.Info.Println("Binary hash and config binary hash matched")
    renderStoredProperties(config, cfgHash)

    return nil
}

func GetAutoconf() (AutoConfig, string, error) {
    execPath, err := os.Executable()
    if err != nil {
        return AutoConfig{}, "", err
    }

    isEnable, err := IsAutoconfEnabled()
    if err != nil {
        return AutoConfig{}, "", err
    }

    if !isEnable {
        return AutoConfig{}, "", errors.New("autoconf is not enabled")
    }

    config, cfgHashStr, err := checkIntegrity(execPath)
    if err != nil {
        return AutoConfig{}, "", err
    }

    return config, cfgHashStr, nil
}

func checkPublicKeyFormat(key string) bool {
    return regexp.MustCompile(AgePublicKeyPattern).MatchString(key)
}

func checkPrivateKeyFormat(key string) bool {
    return regexp.MustCompile(AgePrivateKeyPattern).MatchString(key)
}

func checkIntegrity(path string) (AutoConfig, string, error) {

    isEnabled, err := IsAutoconfEnabled()
    if err != nil {
        return AutoConfig{}, "", err
    }

    if !isEnabled {
        return AutoConfig{}, "", errors.New("autoconf is not enabled")
    }

    binary, err := elf.ExtractBinary(path)
    if err != nil {
        return AutoConfig{}, "", err
    }

    payload, err := elf.ExtractPayload(path)
    if err != nil {
        return AutoConfig{}, "", err
    }

    var config AutoConfig
    err = json.Unmarshal(payload, &config)
    if err != nil {
        return AutoConfig{}, "", err
    }

    hex := generic.Hex{}
    cfgBinHash, err := hex.Decode(config.BinaryHash)
    if err != nil {
        return AutoConfig{}, "", err
    }

    b256 := hash.Blake2b256{}
    isMatch, err := b256.ValidateHash(binary, cfgBinHash)
    if err != nil {
        return AutoConfig{}, "", err
    }

    if !isMatch {
        return AutoConfig{}, "", errors.New("binary has been tampered with")
    }

    cfgHash, err := b256.Hash(payload)
    if err != nil {
        return AutoConfig{}, "", err
    }

    cfgHashStr := hex.Encode(cfgHash)

    return config, cfgHashStr, nil
}

func (a *AutoConfig) marshal() (config []byte, cfgHash string, err error) {

    config, err = json.Marshal(a)
    if err != nil {
        return nil, "", err
    }

    a.configSize = len(config)

    b256 := hash.Blake2b256{}

    configHash, err := b256.Hash(config)
    if err != nil {
        return nil, "", err
    }

    hex := generic.Hex{}

    return config, hex.Encode(configHash), nil
}

func (a *AutoConfig) calculateBinaryHash() error {
    execPath, err := os.Executable()
    if err != nil {
        return err
    }

    binary, err := generic.ReadFileContent(execPath)
    if err != nil {
        return err
    }

    a.binarySize = len(binary)

    b256 := hash.Blake2b256{}

    hash, err := b256.Hash(binary)
    if err != nil {
        return err
    }

    hex := generic.Hex{}

    a.BinaryHash = hex.Encode(hash)

    return nil
}

func (a *AutoConfig) populateKeychain(recepients, note, keys, keynote []string) (err error) {
    for i, key := range recepients {
        if checkPublicKeyFormat(key) {
            return errors.New(generic.StrCnct([]string{"Invalid public key format: ", key}...))
        }

        a.PublicKeys = append(a.PublicKeys, AutoConfigPublicKeys{
            PublicKey: key,
            Note:      note[i],
        })
    }

    for i, key := range keys {
        if checkPrivateKeyFormat(key) {
            return errors.New(generic.StrCnct([]string{"Invalid private key format: ", key}...))
        }

        a.PrivateKeys = append(a.PrivateKeys, AutoConfigPrivateKeys{
            PrivateKey: key,
            Note:       keynote[i],
        })
    }

    return nil
}

func renderStoredProperties(config AutoConfig, cfgHash string) {
    pterm.Info.Println("Creation date:",
        pterm.FgWhite.Sprint(config.CreationDate))
    pterm.Info.Println("Autoconf configuration file integrity hash:",
        pterm.BgBlue.Sprint(cfgHash[:5])+
            pterm.FgWhite.Sprint(cfgHash[5:len(cfgHash)-5])+
            pterm.BgBlue.Sprint(cfgHash[len(cfgHash)-5:]))
    pterm.Info.Println("Configured public keys:", pterm.FgWhite.Sprint(len(config.PublicKeys)))
    pterm.Info.Println("Configured private keys:", pterm.FgWhite.Sprint(len(config.PrivateKeys)))

    tableData := pterm.TableData{
        {"#", pterm.FgCyan.Sprint("Note"), pterm.FgRed.Sprint("Public keys")},
    }

    for i, profile := range config.PublicKeys {
        tableData = append(tableData, []string{strconv.Itoa(i + 1), pterm.BgWhite.Sprint(profile.Note), pterm.BgGreen.Sprint(profile.PublicKey)})
    }

    pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
}