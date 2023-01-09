package yclient

import (
	"encoding/base64"
	"encoding/json"
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

func TestServerAuthorization_PositivePath(t *testing.T) {
	// Want: successful generation of credentials
	serverChallenge := "a-very-hard-challenge"
	serverPrivateEncryptionKey, serverPubEncryptionKey, err := cryptography.RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	clientPrivateSignKey, clientPublicSignKey, err := cryptography.RsaKeyPairPem()
	if err != nil {
		t.Fatal(err.Error())
	}
	yclient := YdentifiClient{}
	bs64encodedServerCredentials, err := yclient.ServerAuthorization(serverChallenge, serverPubEncryptionKey, clientPrivateSignKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	decodedCredentialsSting, err := base64.StdEncoding.DecodeString(bs64encodedServerCredentials)
	if err != nil {
		t.Fatal(err.Error())
	}
	authPayload := ServerAuthorizationPayload{}
	err = json.Unmarshal([]byte(decodedCredentialsSting), &authPayload)
	if err != nil {
		t.Fatal(err.Error())
	}
	decryptedEphemeralSymKey, err := cryptography.DecryptRsa(authPayload.EncryptedKey, serverPrivateEncryptionKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	decryptedTokenString, err := cryptography.DecryptAesGcm(authPayload.Token, decryptedEphemeralSymKey)
	challengeResponse := ServerChallengeResponse{}
	err = json.Unmarshal([]byte(decryptedTokenString), &challengeResponse)
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, challengeResponse.Challenge, serverChallenge)
	err = cryptography.VerifyRsaPss(challengeResponse.Challenge, challengeResponse.Signature, clientPublicSignKey)
}
