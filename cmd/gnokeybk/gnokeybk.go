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
	"github.com/gnolang/gno/pkgs/crypto/keys"
	"github.com/gnolang/gno/pkgs/crypto/keys/client"
//	"github.com/gnolang/gno/pkgs/errors"
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


// It finds the address to the key name and ask user to generate a new  priviate key with the same  nemonic
// and sign the relation between the  new  backup public key and  current pubkey.
// If the name is not found, it asks user to add new key, which automatically genereate back up key. 

func backupKeyApp(cmd *command.Command, args []string, iopts interface{}) error{
	opts := iopts.(client.BaseOptions)

   if len(args) !=1 {
	cmd.ErrPrintln("Usage: gnokeybk bkkey <keyname>")
    }

	// read key
	name := args[0]
	kb, err := keys.NewKeyBaseFromDir(opts.Home)
	info, err := kb.Get(name)
	if err != nil {
		
		return fmt.Errorf("%s does not exist. please add key first",name)
	}
	addr := info.GetAddress()
	fmt.Println("This is your wallet address, please input corresponding mnemonic to generate back up key",addr.String())

	

    return nil
}

