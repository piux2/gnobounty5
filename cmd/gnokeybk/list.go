package main

import (
	"github.com/gnolang/gno/pkgs/command"
	"github.com/gnolang/gno/pkgs/crypto/keys"
	"github.com/gnolang/gno/pkgs/crypto/keys/client"
	"github.com/gnolang/gno/pkgs/errors"
)

/*
type ListOptions struct {
	client.BaseOptions // home, ...
}

var DefaultListOptions = ListOptions{
	BaseOptions: client.DefaultBaseOptions,
}
*/

func listBkApp(cmd *command.Command, args []string, iopts interface{}) error {

	if len(args) != 0 {
		cmd.ErrPrintfln("Usage: list (no args)")
		return errors.New("invalid args")
	}

	opts := iopts.(client.ListOptions)
	kb, err := keys.NewKeyBaseFromDir(opts.Home)
	if err != nil {
		return err
	}

	bkKeyBase, err := keys.NewBkKeyBaseFromDir(opts.Home)
	if err != nil {
		return err
	}

	infos, err := kb.List()
	if err == nil {
		printInfos(cmd, infos, "primary")
	}

	cmd.Println("\n---------------------------")

	infos, err = bkKeyBase.List()
	if err == nil {
		printInfos(cmd, infos, "backup")
	}

	return err
}

func printInfos(cmd *command.Command, infos []keys.Info, keybaseName string) {

	cmd.Printfln("Keybase %s", keybaseName)

	for i, info := range infos {
		keyname := info.GetName()
		keytype := info.GetType()
		keypub := info.GetPubKey()
		keyaddr := info.GetAddress()
		keypath, _ := info.GetPath()
		cmd.Printfln("%d. %s (%s) - addr: %v pub: %v, path: %v",
			i, keyname, keytype, keyaddr, keypub, keypath)
	}
}
