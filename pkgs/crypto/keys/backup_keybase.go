package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/gnolang/gno/pkgs/crypto"
	"github.com/gnolang/gno/pkgs/crypto/bip39"
	gnoEd25519 "github.com/gnolang/gno/pkgs/crypto/ed25519"
	"github.com/gnolang/gno/pkgs/crypto/hd"
	"github.com/gnolang/gno/pkgs/crypto/keys/armor"

	"github.com/gnolang/gno/pkgs/crypto/secp256k1"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

// InfoBK store's back up key in a backup local storage
// TODO: move gno/pkgs/crypto/keys/type.go

// need review for  this InfoBk structure
/*
type Info = keys.Info
type Keybase = keys.Keybase
type KeyType = keys.KeyType

const TypeLocal = keys.TypeLocal
*/

type InfoBk struct {
	// backup local key information
	Name         string        `json:"name"`          // same as primary key
	PubKey       crypto.PubKey `json:"pubkey"`        // backup key derived from ed25519
	PrivKeyArmor string        `json:"privkey.armor"` // private back key in armored ASCII format

	//  A Secp256k1 signature.
	//  Use the primary priv key sign  the  ecoded JSON string back up info Name + Pubkey(backup)+PrivKeyArmo(backup)
	//  The signature  is to show that infoBk is created by the primary key holder.
	//  It is also verifable if someone change the InfoBk record.

	Signature []byte `json:"signature"`

	// this is used to verify the signature signed using primary key secp256k1
	PrimaryPubKey crypto.PubKey `json:"primary_pubkey"`
}

var _ Info = &InfoBk{}

func newInfoBk(name string, pub crypto.PubKey, privArmor string) Info {
	return &InfoBk{
		Name:         name,
		PubKey:       pub,
		PrivKeyArmor: privArmor,
	}

}

// GetType implements Info interface
func (i InfoBk) GetType() KeyType {
	return TypeLocal
}

// GetType implements Info interface
func (i InfoBk) GetName() string {
	return i.Name
}

// GetType implements Info interface
func (i InfoBk) GetPubKey() crypto.PubKey {
	return i.PubKey
}

// GetType implements Info interface
func (i InfoBk) GetAddress() crypto.Address {
	return i.PubKey.Address()
}

// GetType implements Info interface
func (i InfoBk) GetPath() (*hd.BIP44Params, error) {
	return nil, fmt.Errorf("BIP44 Paths are not available for this type")
}

//TODO: once reviewed, merge these methods to  /pkgs/crypto/keys/keybase.go and lazy_keybase.go
func BackupAccount(kbBk Keybase, name, mnemonic, bip39Passwd, encryptPasswd string, account uint32, index uint32) (Info, error) {

	coinType := crypto.CoinType
	hdPath := hd.NewFundraiserParams(account, coinType, index)
	//create  a mnemonic
	info, err := CreateAccountBip44(kbBk, name, mnemonic, bip39Passwd, encryptPasswd, *hdPath)
	return info, err

}

func CreateAccountBip44(kbBk Keybase, name, mnemonic, bip39Passphrase, encryptPasswd string, params hd.BIP44Params) (Info, error) {

	//bip39 used  PBKDF2 to hash the mnemonic. PBKDF2 is a pass word hash function not really a
	//   KDF which provides key extraction and extension
	// Here it is still a seed
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return InfoBk{}, err
	}

	info, err := persistBkKey(kbBk, seed, name, encryptPasswd, params.String())
	return info, err
}

// nake return and name return variable

func persistBkKey(kbBk Keybase, seed []byte, name, passwd, fullHdPath string) (Info, error) {
	//create master key and derive first key:
	// masterPriv is from hmac no KDF performanced
	masterPriv, ch := hd.ComputeMastersFromSeed(seed)
	//  hd.DerivePrivateKeyForPath tried prevent using secp256k1
	//  but later  in pkgs/crypto/keys/keybase.go persistDerivedKey(), it still use secp256k1 to generate pubkey
	//  it defeats the purose of avoiding secp256k1 in hdpath.go derivePrivateKey()

	derivedPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, fullHdPath)
	if err != nil {
		return InfoBk{}, err
	}

	primaryKey := secp256k1.PrivKeySecp256k1(derivedPriv)

	//The back up key need a simple Sha256 based KDF  which is different from the primary key

	//  We can use HKDF for KDF
	//https://rfc-editor.org/rfc/rfc5869.html
	// hkdf does not expect the salt to be a secret.
	hash := sha256.New
	salt := make([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	info := []byte("gnokey hkdf")
	// the size of the privkey is 32 byte
	expanedKeyReader := hkdf.New(sha256.New, seed, salt, info)
	privKey := make([]byte, 32)
	if _, err := io.ReadFull(expanedKeyReader, privKey); err != nil {

		panic(err)
	}

	// in go/x/crypto/ed25519/ed25519.go
	//This package refers to the RFC8032 private key as the “seed”.

	// ed25519 is used to generate public key from private key
	// the returned a key (64 byte)  =  priveky(32 byte) + pubkey(32 byte)
	// the first 32 byte is private key (see) and  the reset is public key
	bkKey := ed25519.NewKeyFromSeed(privKey)

	// cover to  PriveKeyEd25519 type used in gno
	var privKeyEd gnoEd25519.PrivKeyEd25519
	copy(privKeyEd[:], bkKey)

	bkInfo, err := writeLocalBkKey(kbBk, name, privKeyEd, primaryKey, passwd)

	return bkInfo, err
}

func writeLocalBkKey(kbBk Keybase, name string, bkKey crypto.PrivKey, primaryKey crypto.PrivKey, passphrase string) (Info, error) {

	privArmor := armor.EncryptArmorPrivKey(bkKey, passphrase)
	pub := bkKey.PubKey()
	info := newInfoBk(name, pub, privArmor)
	//TODO: disussion,  could use a document structure. json is simple and good enough  for now.
	msg, err := json.Marshal(info)

	// sign only name+pubkey+privArmor
	infobk := info.(*InfoBk)
	//  only name + PubKey + PrivKeyArmor
	infobk.Signature, err = primaryKey.Sign(msg)
	// attach the pubkey in the end
	infobk.PrimaryPubKey = primaryKey.PubKey()

	k := kbBk.(dbKeybase)

	k.writeInfo(name, infobk)
	return info.(*InfoBk), err
}
