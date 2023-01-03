// yclient provides an interface for communicating with the Ydentifi MFA API
//
// Optionally, a consumer application can always make direct http
// requests to the API, however using the client will greatly
// diminish the complexity of this communication.
package yclient

import (
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

// fetchServerChallenge gets a challenge from the Ydentifi API server as a part
// of the service-to-service authentication process
func (y *YdentifiClient) fetchServerChallenge() (string, error) {
	response, err := http.Get(y.ApiBaseUrl + GetServerChallengeUrl)
	if err != nil {
		return "", fmt.Errorf("YdentifClient.fetchServerChallenge failed with error [%w]", err)
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("YdentifClient.fetchServerChallenge failed reading response body with error [%w]", err)
	}

	if response.StatusCode != 200 && response.StatusCode != 201 {
		return "", fmt.Errorf("YdentifClient.fetchServerChallenge failed to get server challenge with sever message [%v] and status code [%v]", string(responseBody), response.StatusCode)
	}

	responseData := serverChallengeResponse{}
	err = json.Unmarshal(responseBody, &responseData)
	if err != nil {
		return "", fmt.Errorf("YdentifClient.fetchServerChallenge failed unmarshalling response body with error [%w]", err)
	}

	return responseData.authorizationChallenge, nil
}

// CreateChallengeResponse generates a response to an Ydentifi API server challenge
func (y *YdentifiClient) CreateChallengeResponse(challenge string, signKeyPem string, apiPassword string) (string, error) {
	signature, err := cryptography.SignRsaPss(y.ClientAppId+challenge, signKeyPem)
	if err != nil {
		return "", fmt.Errorf("YdentifiClient.CreateChallengeResponse failed with error [%w]", err)
	}

	challengeResponse := ApiAuthToken{
		RequestorId:       y.ClientAppId,
		RequestorPassword: apiPassword,
		Challenge:         challenge,
		Signature:         signature,
	}

	challengeResponseBytes, err := json.Marshal(challengeResponse)
	if err != nil {
		return "", fmt.Errorf("YdentifiClient.CreateChallengeResponse failed to jsonify response with error: [%w]", err)
	}
	return string(challengeResponseBytes), nil
}

func (y *YdentifiClient) CreateApiAuthToken(signKeyPem string, apiPassword string) (string, error) {
	serverChallenge, err := y.fetchServerChallenge()
	if err != nil {
		return "", fmt.Errorf("YdentifClient.CreatApiAuthToken to fetch server challenge with error [%w]", err)
	}
	authToken, err := y.CreateChallengeResponse(serverChallenge, signKeyPem, apiPassword)
	if err != nil {
		return "", fmt.Errorf("YdentifClient.CreatApiAuthToken to create challenge response [%w]", err)
	}
	return authToken, nil
}
