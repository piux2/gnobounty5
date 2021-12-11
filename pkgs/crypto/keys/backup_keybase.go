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

	"github.com/gnolang/gno/pkgs/crypto/multisig"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

// InfoBK store's back up key in a backup local storage
// TODO: move gno/pkgs/crypto/keys/type.go

// need review for  this infoBk structure
/*
type Info = keys.Info
type Keybase = keys.Keybase
type KeyType = keys.KeyType

const TypeLocal = keys.TypeLocal
*/

type infoBk struct {
	// backup local key information
	Name         string        `json:"name"`          // same as primary key
	PubKey       crypto.PubKey `json:"pubkey"`        // backup key derived from ed25519
	PrivKeyArmor string        `json:"privkey.armor"` // private back key in armored ASCII format
	MultisigInfo Info          `json:"multisig_info"` // Multisig  holds the primary pubkey and back pubkey as a 2/2 multisig
	//  A Secp256k1 signature.
	//  Use the primary priv key sign  the  ecoded JSON string back up info Name + Pubkey(backup)+PrivKeyArmo(backup)
	//  The signature  is to show that infoBk is created by the primary key holder.
	//  It is also verifable if someone change the infoBk record.

	Signature []byte `json:"signature"`

	// this is used to verify the signature signed using primary key secp256k1
	PrimaryPubKey crypto.PubKey `json:"primary_pubkey"`
}

//ask the compiler to check infoBk type implements Info interface
var _ Info = &infoBk{}

func newInfoBk(name string, pub crypto.PubKey, privArmor string) Info {
	return &infoBk{
		Name:         name,
		PubKey:       pub,
		PrivKeyArmor: privArmor,
	}

}

// GetType implements Info interface
func (i infoBk) GetType() KeyType {
	return TypeLocal
}

// GetType implements Info interface
func (i infoBk) GetName() string {
	return i.Name
}

// GetType implements Info interface
func (i infoBk) GetPubKey() crypto.PubKey {
	return i.PubKey
}

// GetType implements Info interface
func (i infoBk) GetAddress() crypto.Address {
	return i.PubKey.Address()
}

// GetType implements Info interface
func (i infoBk) GetPath() (*hd.BIP44Params, error) {
	return nil, fmt.Errorf("BIP44 Paths are not available for this type")
}

//TODO: once reviewed passed, merge these methods to  /pkgs/crypto/keys/keybase.go and lazy_keybase.go
func BackupAccount(kbBk Keybase, name, mnemonic, bip39Passwd, encryptPasswd string, account uint32, index uint32) (Info, error) {

	coinType := crypto.CoinType
	hdPath := hd.NewFundraiserParams(account, coinType, index)
	//create  a mnemonic
	info, err := CreateAccountBip44(kbBk, name, mnemonic, bip39Passwd, encryptPasswd, *hdPath)
	return info, err

}

func CreateAccountBip44(kbBk Keybase, name, mnemonic, bip39Passphrase, encryptPasswd string, params hd.BIP44Params) (Info, error) {

	//bip39 uses  PBKDF2 to hash the mnemonic. PBKDF2 is a pass word hash function and not a
	// KDF which provides key extraction and extension
	// at this point the seed is still a seed not a private key yet.
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return infoBk{}, err
	}

	info, err := persistBkKey(kbBk, seed, name, encryptPasswd, params.String())
	return info, err
}

// nake return and name return variable
// persistBkKey uses the same seed to derive both primary key and backup key and
// use primary key to sign the backup key info to key the backup key's integrity
// TODO: review: create multisig threshold and adds to InfoBk. This way no need to
// manage multisig process in seperate entity.

func persistBkKey(kbBk Keybase, seed []byte, name, passwd, fullHdPath string) (Info, error) {
	//create master key and derive first key:
	// masterPriv is from hmac no KDF performanced
	masterPriv, ch := hd.ComputeMastersFromSeed(seed)

	derivedPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, fullHdPath)
	if err != nil {
		return infoBk{}, err
	}

	primaryKey := secp256k1.PrivKeySecp256k1(derivedPriv)

	//The back up key need a simple Sha256 based KDF  which is different from the primary key

	//We can use HKDF for KDF
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

	//TODO: updated the armored privKey file with correct passwd encryption notaion
	// bcrypt is not KDF. It is a secure hash to protect the password
	privArmor := armor.EncryptArmorPrivKey(bkKey, passphrase)
	pub := bkKey.PubKey()
	info := newInfoBk(name, pub, privArmor)
	fmt.Println("back up PubKey", pub)
	fmt.Println("privArmor", privArmor)

	// sign  name+pubkey+privArmor + multisiginfo

	infobk := info.(*infoBk)
	pubkeys := []crypto.PubKey{
		primaryKey.PubKey(), //primary pubkey
		pub,                 //backup pubkey
	}

	multisig := multisig.NewPubKeyMultisigThreshold(2, pubkeys)
	infobk.MultisigInfo = NewMultiInfo("backup", multisig)

	//TODO: disussion,  could use a document structure. json is simple and good enough  for now.
	msg, err := json.Marshal(info)
	fmt.Println("msg", msg)

	//  sign  name + PubKey + PrivKeyArmor + MultisgInfo
	//  To show that the multisig is created by the primary key holder
	infobk.Signature, err = primaryKey.Sign(msg)
	fmt.Println("Signature", infobk.Signature)

	// attach the primary pubkey in the end. it is used to verify the signature and pubkey
	infobk.PrimaryPubKey = primaryKey.PubKey()
	fmt.Println("PrimaryPubkey", infobk.PrimaryPubKey.String())

	k := kbBk.(dbKeybase)

	k.writeInfo(name, infobk)
	return info.(*infoBk), err
}

// Sign uses primary key and backup key to sign the message with the multisig
// The primary keybase and backup keybase must be accessible at the same time, which
// is more secure and not
// the other option is to sign the the message with priamaryKey and back up KEY seperately.
// TODO: A ADR This is also a trade off between usability and security and implementaion complexity.
/*
func Sign(kbPrimary Keybase, kbBk Keybase, name, passPhrase string, msg []byte) (sig []byte, pub crypto.PubKey, err error) {


	//sign the message

	return

}

// Verify verifies the msg signed by primaryKey and backupKey multisig
func Verify(kbBk Keybase, name string, msg []byte, sig []byte) (err error) {

}
*/
