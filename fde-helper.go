package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jessevdk/go-flags"
	sb "github.com/snapcore/secboot"
	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/fdehelper"
)

const (
	sealedKeyFile   = "/run/mnt/ubuntu-boot/sealed-key"
	lockoutAuthFile = "/run/mnt/ubuntu-data/system-data/var/lib/snapd/device/fde/tpm-lockout-auth"
)

// supported verifies if secure full disk encryption is supported on this
// system.
func supported() error {
	// XXX: check if secure boot enabled
	//if err := checkSecureBootEnabled(); err != nil {
	//	return err
	//}

	// check if TPM device available
	tpm, err := sb.ConnectToDefaultTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// check if TPM device enabled
	if !tpm.IsEnabled() {
		return fmt.Errorf("TPM device is not enabled")
	}

	return nil
}

type loadChain struct {
	Path string       `json:"path"`
	Snap string       `json:"snap"`
	Role string       `json:"role"`
	Next []*loadChain `json:"next"`
}

type modelParams struct {
	fdehelper.ModelParams
}

var _ sb.SnapModel = (*modelParams)(nil)

func (p *modelParams) Series() string {
	return p.ModelParams.Series
}

func (p *modelParams) BrandID() string {
	return p.ModelParams.BrandID
}

func (p *modelParams) Model() string {
	return p.ModelParams.Model
}

func (p *modelParams) Grade() asserts.ModelGrade {
	return p.ModelParams.Grade
}

func (p *modelParams) SignKeyID() string {
	return p.ModelParams.SignKeyID
}

// initialProvision initializes the key sealing system (e.g. provision the TPM
// if TPM is used) and stores the key in a secure place.
func initialProvision(p []byte) error {
	var params fdehelper.InitialProvisionParams
	if err := json.Unmarshal(p, &params); err != nil {
		return err
	}

	key, err := base64.RawStdEncoding.DecodeString(params.Key)
	if err != nil {
		return err
	}

	pcrProfile, err := buildPCRProtectionProfile(params.ModelParams)
	if err != nil {
		return err
	}

	tpm, err := sb.ConnectToDefaultTPM()
	if err != nil {
		return fmt.Errorf("cannot connect to TPM: %v", err)
	}
	defer tpm.Close()

	// provision the TPM
	if err := tpmProvision(tpm, lockoutAuthFile); err != nil {
		return err
	}

	creationParams := sb.KeyCreationParams{
		PCRProfile:             pcrProfile,
		PCRPolicyCounterHandle: 0x01880001,
	}

	// seal the key
	_, err = sb.SealKeyToTPM(tpm, key, sealedKeyFile, &creationParams)

	return err
}

// update reseals or updates the stored key policies.
func update(p []byte) error {
	var params fdehelper.UpdateParams
	if err := json.Unmarshal(p, &params); err != nil {
		return err
	}

	pcrProfile, err := buildPCRProtectionProfile(params.ModelParams)
	if err != nil {
		return err
	}

	tpm, err := sb.ConnectToDefaultTPM()
	if err != nil {
		return fmt.Errorf("cannot connect to TPM: %v", err)
	}
	defer tpm.Close()

	// obtain the update key
	k, err := sb.ReadSealedKeyObject(sealedKeyFile)
	if err != nil {
		return fmt.Errorf("cannot read the sealed key: %v", err)
	}
	_, authKey, err := k.UnsealFromTPM(tpm, "")
	if err != nil {
		return fmt.Errorf("cannot unseal: %v", err)
	}

	// reseal the key
	return sb.UpdateKeyPCRProtectionPolicy(tpm, sealedKeyFile, authKey, pcrProfile)
}

type unlockParams struct {
	VolumeName       string `json:"volume-name"`
	SourceDevicePath string `json:"source-device-path"`
	LockKeysOnFinish bool   `json:"lock-keys-on-finish"`
}

// unlock unseals the key and unlock the encrypted volume.
func unlock(p []byte) error {
	var params fdehelper.UnlockParams
	if err := json.Unmarshal(p, &params); err != nil {
		return err
	}

	if params.VolumeName == "" {
		return fmt.Errorf("volume name not specified")
	}
	if params.SourceDevicePath == "" {
		return fmt.Errorf("source device path not specified")
	}

	tpm, err := sb.ConnectToDefaultTPM()
	if err != nil {
		return fmt.Errorf("cannot connect to TPM: %v", err)
	}
	defer tpm.Close()

	options := &sb.ActivateWithTPMSealedKeyOptions{
		PINTries:            1,
		RecoveryKeyTries:    3,
		LockSealedKeyAccess: params.LockKeysOnFinish,
	}
	ok, err := sb.ActivateVolumeWithTPMSealedKey(tpm, params.VolumeName, params.SourceDevicePath, sealedKeyFile, nil, options)
	if err != nil {
		return err
	}
	// XXX: check if this can happen
	if !ok {
		return fmt.Errorf("volume was not activated")
	}
	return nil
}

type options struct {
	// XXX: all descriptions are placeholders
	Supported bool `long:"supported" description:"Check if fde available"`
	Init      bool `long:"initial-provision" description:"Provision TPM and seal"`
	Update    bool `long:"update" description:"Reseal (update the policy) in the TPM case"`
	Unlock    bool `long:"unlock" description:"Unseal and unlock"`
}

func main() {
	var opt options
	parser := flags.NewParser(&opt, flags.Default)
	if _, err := parser.Parse(); err != nil {
		switch flagsErr := err.(type) {
		case flags.ErrorType:
			if flagsErr == flags.ErrHelp {
				parser.WriteHelp(os.Stdout)
				os.Exit(0)
			}
			os.Exit(1)
		default:
			os.Exit(1)
		}
	}

	if opt.Supported {
		if err := supported(); err != nil {
			fmt.Printf("secure fde unsupported: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	// read JSON-formated parameters from stdin
	reader := bufio.NewReader(os.Stdin)
	p, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch {
	case opt.Init:
		err = initialProvision(p)
	case opt.Update:
		err = update(p)
	case opt.Unlock:
		err = unlock(p)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
