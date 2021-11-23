package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBackupAccount(t *testing.T) {

	kb := NewInMemory()
	kbBk := NewInMemory()

	const key_name = "alice_contract"
	const alice_mnemonic = "outdoor source brother rib pair case time figure pizza sting first weekend market survey window volcano spike weasel joke flower limit evil vast lyrics"
	const alice_passcode = "alic123"

	primaryInfo, err := kb.CreateAccount(
		key_name,
		alice_mnemonic,
		"", alice_passcode, 0, 1)

	assert.NoError(t, err, "primary info is created sucessfully")

	infoBk, err := BackupAccount(kbBk, key_name, alice_mnemonic, "", alice_passcode, 0, 1)
	assert.NoError(t, err, "backup info is created sucessfully")

	assert.Equal(t, primaryInfo.GetName(), infoBk.GetName())

}
