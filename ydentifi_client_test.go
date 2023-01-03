package yclient

import (
	"github.com/schmuio/cryptography"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKeyPack(t *testing.T) {
	// Want: keys and secrets are successfully created
	yk := YdentifiClient{
		ClientAppId: "some-id",
		ApiBaseUrl:  "https://does-not-matter-here.com",
	}

	ePrK, ePuK, sPrK, sPuK, pass, err := yk.KeyPack()
	if err != nil {
		t.Fatal(err.Error())
	}
	_, err = cryptography.RsaPrivateKeyFromPemStr(ePrK)
	if err != nil {
		t.Fatal(err.Error())
	}
	_, err = cryptography.RsaPublicKeyFromPemStr(ePuK)
	if err != nil {
		t.Fatal(err.Error())
	}
	_, err = cryptography.RsaPrivateKeyFromPemStr(sPrK)
	if err != nil {
		t.Fatal(err.Error())
	}
	_, err = cryptography.RsaPublicKeyFromPemStr(sPuK)
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, 32, len(pass))
	assert.NotEqual(t, ePrK, sPrK)
	assert.NotEqual(t, ePuK, sPuK)
}
