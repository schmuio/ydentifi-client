// yclient provides an interface for communicating with the Ydentifi MFA API
//
// Optionally, a consumer application can always make direct http
// requests to the API, however using the client will greatly
// diminish the complexity of this communication.
package yclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/schmuio/cryptography"
	"io/ioutil"
	"net/http"
)

// YdentfiClient is the default intermediary between a consumer
// application and the Ydentifi API.
//
// ClientAppId - the unique ID of your app provided by the Ydentifi service/API
// ApiBaseUrl - the schema and the URL location of the Ydentifi API (e.g. https://where-ydentifi-is-hosted.com).
type YdentifiClient struct {
	ClientAppId string
	ApiBaseUrl  string
}

// KeyPack initiates all the secrets necessary to communicate with the Ydentifi API
func (y *YdentifiClient) KeyPack() (string, string, string, string, string, error) {
	encryptionPrivateKey, encryptionPublicKey, err := cryptography.RsaKeyPairPem()
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("InitiateClientAppSecrets failed to generate RSA encryption key pair with error: [%w]", err)
	}
	signPrivateKey, signPublicKey, err := cryptography.RsaKeyPairPem()
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("InitiateClientAppSecrets failed to generate RSA sign key pair with error: [%w]", err)
	}
	ydentifiApiPassword, err := cryptography.Key256b()
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("InitiateClientAppSecrets failed to generate password with error: [%,w]", err)
	}
	return encryptionPrivateKey, encryptionPublicKey, signPrivateKey, signPublicKey, ydentifiApiPassword, nil
}

// FetchServerChallenge gets a challenge from the Ydentifi API server as a part
// of the service-to-service authentication process
func (y *YdentifiClient) FetchServerChallenge() (string, string, error) {
	response, err := http.Get(y.ApiBaseUrl + GetServerChallengeUrl)
	if err != nil {
		return "", "", fmt.Errorf("YdentifClient.FetchServerChallenge failed with error [%w]", err)
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", "", fmt.Errorf("YdentifClient.FetchServerChallenge failed reading response body with error [%w]", err)
	}

	if response.StatusCode != 200 && response.StatusCode != 201 {
		return "", "", fmt.Errorf("YdentifClient.FetchServerChallenge failed to get server challenge with sever message [%v] and status code [%v]", string(responseBody), response.StatusCode)
	}

	responseData := ServerChallenge{}
	err = json.Unmarshal(responseBody, &responseData)
	if err != nil {
		return "", "", fmt.Errorf("YdentifClient.FetchServerChallenge failed unmarshalling response body with error [%w]", err)
	}

	return responseData.AuthorizationChallenge, responseData.ServerPublicEncryptionKey, nil
}

// ApiAuthToken generates authorization credentials for invoking the
// Ydentifi API
func (y *YdentifiClient) ServerAuthorization(serverChallenge string, serverPublicEncryptionKeyPem string, clientSignKeyPem string) (string, error) {
	signature, err := cryptography.SignRsaPss(serverChallenge, clientSignKeyPem)
	if err != nil {
		return "", fmt.Errorf("YdentifiClient.ServerAuthorization failed to issue signature with error [%w]", err)
	}
	challengeResponse := ServerChallengeResponse{
		Challenge: serverChallenge,
		Signature: signature,
	}
	challengeResponseBytes, err := json.Marshal(challengeResponse)
	if err != nil {
		return "", fmt.Errorf("YdentifiClient.ServerAuthorization failed to jsonify response with error: [%w]", err)
	}
	token, encryptedKey, err := cryptography.EnvelopeEncryptAes(string(challengeResponseBytes), serverPublicEncryptionKeyPem)
	if err != nil {
		return "", fmt.Errorf("YdentifiClient.ServerAuthorization failed to generate credentials with error: [%w]", err)
	}
	authorization := ServerAuthorizationPayload{
		Token:        token,
		EncryptedKey: encryptedKey,
	}
	serverCredentials, err := json.Marshal(authorization)
	if err != nil {
		return "", fmt.Errorf("YdentifiClient.ServerAuthorization failed to jsonify credentials with error: [%w]", err)
	}
	return base64.StdEncoding.EncodeToString(serverCredentials), nil
}
