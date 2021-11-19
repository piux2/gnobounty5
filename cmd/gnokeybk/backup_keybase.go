package  main

import (

"github.com/gnolang/gno/pkgs/crypto/keys/"
"github.com/gnolang/gno/pkgs/crypto"
"github.com/gnolang/gno/pkgs/crypto/hd"

"github.com/x/crypto/hkdf"
"github.com/x/crypto/ed25519"
)


// InfoBK store's back up key in a backup local storage
// TODO: move gno/pkgs/crypto/keys/type.go
type InfoBk struct {

        Name string `json:"name"` // same as primary key
        PubKey  crypto.PubKey `json:"pubkey"` // backup key derived from ed25519
        PrivKeyArmor string `json:"privkey.armor"` // private back key in armored ASCII format
        //  A ED25519 signature that sign  the  ecoded JSON string  Name + Pubkey
        Signature  []byte `json:"signature"`

}


func  newInfoBk(name string, pub crypto.Pubkey, privArmor string, sig []byte)Info{
	return &NewInfoBk{
		Name: name,
		Pubkey:	pub,
		PrivkeyArmor: prviArmor,
		Signature : sig,
	}



}

// GetType implements Info interface
func (i localInfo) GetType() KeyType {
	return TypeLocal
}

// GetType implements Info interface
func (i localInfo) GetName() string {
	return i.Name
}

// GetType implements Info interface
func (i localInfo) GetPubKey() crypto.PubKey {
	return i.PubKey
}

// GetType implements Info interface
func (i localInfo) GetAddress() crypto.Address {
	return i.PubKey.Address()
}

// GetType implements Info interface
func (i localInfo) GetPath() (*hd.BIP44Params, error) {
	return nil, fmt.Errorf("BIP44 Paths are not available for this type")
}



  
//TODO: once reviewed, merge it to  /pkgs/crypto/keys/keybase.go
func BackupAccount(name, mnemonic, bip39Passwd, encryptPasswd stirng, account unit32, index unit32)(InfoBk, error){

	coinType := crypto.CoinType
	hdPath := hd.NewFundraiserParams(account, coinType, index)
	//create  a mnemonic 
	return CreateAccountBip44(name,mnemonic, bip39Passwd, encryptPasswd, *hdPath)


}

func CreateAccountBip44(name, mnemonic, bip39Passphrase, encryptPasswd string, params hd.BIP44Params) (info Info, err error) {
	// This is already a key after the pbkdf2  as KDF, which convert a mnemonic to a key.


	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return
	}

	info, err = persistBkKey(seed, encryptPasswd, name, params.String())
	return
}


func persistBkKey(seed []byte, passwd, name, fullHdPath string) (info Info, err error) {
	// create master key and derive first key:
	//masterPriv, ch := hd.ComputeMastersFromSeed(seed)
	//derivedPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, fullHdPath)
       //if err != nil {
        //        return
        //}
	

	//The back up key need a simple Sha256 based KDF

       //  We can use HKDF for KDF 
	//https://rfc-editor.org/rfc/rfc5869.html
	// hkdf does not expect the salt to be a secret. 
	hash := sha256.New
	salt : = make ([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	info : =  []byte("gnokey hkdf")
	// the size of the privkey is 32 byte
	privkey := hkdf.New(sha256.New, seed, salt, info )

// in go/x/crypto/ed25519/ed25519.go 
// the "seed"  is RFC8032's private key for interoperbility.
// ed25519 is used to generate public key from private key
// the returned edprivkey(64 byte)  =  priveky(32 byte) + pubkey(32 byte)
// the first 32 byte is private key (see) and  the reset is public key
	edprivkey := ed25519.NewKeyFromSeed(privkey)
	// cover to  PriveKeyEd25519 type used in gno
	var  privkeyEd PrivKeyEd25519
	copy (privkeyEd[:],edprivekey)
	
	bkinfo := writeLocalBkKey(name, privkeyEd, passwd)

	return bkinfo, nil
}

func writeLocalBkKey(name, ed21559.PrivateKey(drivedPriv),passwd){

}



//
