// Dedicatced to my love, Lexi.
package main

import (
	"fmt"
	//	"io/ioutil"
	"os"
	//	"path/filepath"
	//	"strings"

	//	"github.com/gnolang/gno/pkgs/amino"
	"github.com/gnolang/gno/pkgs/command"
	"github.com/gnolang/gno/pkgs/crypto/bip39"
	"github.com/gnolang/gno/pkgs/crypto/keys"
	"github.com/gnolang/gno/pkgs/crypto/keys/client"
	"github.com/gnolang/gno/pkgs/errors"
	//	"github.com/gnolang/gno/pkgs/sdk/vm"
	//	"github.com/gnolang/gno/pkgs/std"
)

func main() {
	cmd := command.NewStdCommand()

	// set default options.

	// customize call to command.
	// insert args and options here.
	// TODO: use flags or */pflags.

	exec := os.Args[0]
	args := os.Args[1:]

	client.AddApp(backupKeyApp, "bkkey", "create a backup key to backup keybase", client.DefaultBaseOptions)
	err := client.RunMain(cmd, exec, args)
	if err != nil {
		cmd.ErrPrintfln("%s", err.Error())
		cmd.ErrPrintfln("%#v", err)
		return // exit
	}
}

// localInfoBK store's back up key in a backup local storage 
type localInfoBK struct {

	Name string `json:"name"` // same as primary key
	PubKey  crypto.PubKey `json:"pubkey"` // backup key derived from ed25519
	PrivKeyArmor string `json:"privkey.armor"` // privated key in armored ASCII format
	//  A ED25519 signature that sign  the  ecoded JSON string  Name + Pubkey
	Signature  []byte 'json:"signature"'
	
}

// It finds the address to the key name and ask user to generate a new  priviate key with the same  nemonic
// and sign the relation between the  new  backup public key and  current pubkey.
// If the name is not found, it asks user to add new key, which automatically genereate back up key.

func backupKeyApp(cmd *command.Command, args []string, iopts interface{}) error {
	opts := iopts.(client.BaseOptions)

	if len(args) != 1 {
		cmd.ErrPrintln("Usage: gnokeybk bkkey <keyname>")
	}

	// read primary key info
	name := args[0]
	kb, err := keys.NewKeyBaseFromDir(opts.Home)
	info, err := kb.Get(name)

	if err != nil {
		//TODO: call addApp to generate mnemonic and the primary key
		return fmt.Errorf("%s does not exist. please add key first", name)
	}
	addr := info.GetAddress()
	cmd.Println(addr.String())
	cmd.Println("This is your wallet address, please input corresponding mnemonic to generate back up key.")

	// import mnemonic and add bkkey in backup key store
	// TODO: take care  of multisig case and ledger case as in addApp()

	// you can have one single seed with multiple passphrases to create multiple different wallets.
	// Each wallet would be designated by a different passphrase. seed = "mnemonic"+phassphrase?
	const bip39Passphrase string = ""
	 // TODO: should user enter bip39 passphrase? Maybe not. User has a lot burn already. 
         // TODO: should we add  bip39 passphrase to backup key generation automatically? 
         // Maybe not, backup key already creates an  layer of security and extra burdon to the user. 
         // Plus, backward compatible  maintenaince will be a nightmare

	encryptPassword, err := cmd.GetCheckPassword(
			"Enter the passphrase to unlock the key store "
		)

	if err != nil {
		return err
	}

	kbBK := keys.NewLazyDBKeyBase("keybk", opts.Home)
	bip39Message := "Enter your bip39 mnemonic"
	mnemonic, err := cmd.GetString(bip39Message)

	if err != nil {

		return err
	}



	if !bip39.IsMnemonicValid(mnemonic) {

		return errors.New("invalid mnemonic")

	}
	// the bip39 passphrase is appendixed to the mnemonic to generate new account
	account := 0
	index := 0
	info, err :=kb.CreateAccount(name, mnemonic, bip39Phassphrase, encryptPassword, account, index )
	bkinfo, err := kbBK.CreateAccount(name, mnemonic, bipPhassphrase, encryptPassword, account, index)
	
	// verify if mnemonic generate the same primary pubkey
	
	return nil
}
