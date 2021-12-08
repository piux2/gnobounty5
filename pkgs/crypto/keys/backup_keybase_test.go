package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const key_name = "alice_contract"
const alice_mnemonic = "outdoor source brother rib pair case time figure pizza sting first weekend market survey window volcano spike weasel joke flower limit evil vast lyrics"
const alice_passcode = "alic123"
const backup_pubkey = "gpub1pggj7ard9eg82cjtv4u52epjx56nzwgjyg9zpdp4nek8f32l57dv7nacknce5uxxwf86h7u979y9spanchwq9femmsj3a2"
const primary_pubkey = "gpub1pgfj7ard9eg82cjtv4u4xetrwqer2dntxyfzxz3pqfa6tk77u4tkh9ll3rpwr0y7axa4jm42kejfkuc05qutnuzvp4e0w5cef4v"
const privAmorFile = "./privkey_test.armor"

func TestBackupAccount(t *testing.T) {

	kb := NewInMemory()
	kbBk := NewInMemory()

	primaryInfo, err := kb.CreateAccount(
		key_name,
		alice_mnemonic,
		"", alice_passcode, 0, 1)

	assert.NoError(t, err, "creating primary info failed")

	infoBk, err := BackupAccount(kbBk, key_name, alice_mnemonic, "", alice_passcode, 0, 1)
	assert.NoError(t, err, "creating backup info failed")

	assert.Equal(t, primaryInfo.GetName(), infoBk.GetName(), "Names are equal")

}
