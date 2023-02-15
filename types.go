package yclient

import (
	"time"
)

// ServerChallenge defines the content of the
// the server challenge payload
type ServerChallenge struct {
	AuthorizationChallenge    string
	ServerPublicEncryptionKey string
}

// ServerChallengeResponse contains a signature
// on the server challenge
type ServerChallengeResponse struct {
	Challenge string
	Signature string
}

// ServerAuthorization contains credentials for
// calling the API endpoints
type ServerAuthorizationPayload struct {
	Token        string
	EncryptedKey string // Encrypted AES or ChaCha20 compatible key used for envelope encryption
}

// CreateUserPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type CreateUserPayload struct {
	UserEmail string
}

// UnlockUserPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type UnlockUserPayload struct {
	UserEmail string
}

// CreateMobile2faUserPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type CreateMobile2faUserPayload struct {
	UserEmail       string
	UserPhoneNumber string
	UserDisplayName string
}

// AuthenticateEmailAndPasswordPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type AuthenticateEmailAndPasswordPayload struct {
	UserEmail          string
	PasswordPlaintext  string
	IdentityProofToken string
}

// DeleteUserPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type DeleteUserPayload struct {
	UserEmail string
}

// UserRecordData defines the payload
// structure for sharing client data
// with the frontend in the Ydentifi API
type UserRecordData struct {
	UserEmail       string
	PhoneNumber     string
	UserDisplayName string
	EmailVerified   bool
	Disabled        bool
}

// EnrollSoftToken2faPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type EnrollSoftToken2faPayload struct {
	IdentityProofToken string
}

// AuthenticateTotpPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type AuthenticateTotpPayload struct {
	UserEmail          string
	Totp               string
	IdentityProofToken string
}

// VerifyEmailPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type VerifyEmailPayload struct {
	UserEmail          string
	VerificationCode   string
	IdentityProofToken string
}

// SendEmailVerificationCodePayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type SendEmailVerificationCodePayload struct {
	UserEmail string
}

// UpdatePublicKeysPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
//
// Note: keys are expected in PEM format
type UpdatePublicKeysPayload struct {
	NewEncryptionPublicKey string
	NewSigningPublicKey    string
}

// IdTokenClaims contains the claims payload of an IdToken
type IdTokenClaims struct {
	Iss    string                 `json:"iss"`
	Aud    string                 `json:"aud"`
	Iat    time.Time              `json:"iat"`
	Exp    time.Time              `json:"exp"`
	Ctx    []string               `json:"ctx"`
	Uid    string                 `json:"uid"`
	Custom map[string]interface{} `json:"custom"`
}

// IdToken is a type containing proof of identity
// claims for a particular user
type IdToken struct {
	Claims    IdTokenClaims `json:"claims"`
	Signature string        `json:"signature"`
}
