package yclient

type serverChallengeResponse struct {
	authorizationChallenge string
}

// ApiAuthToken contains all
// the necessary information for a
// consumer application to authenticate
// to the Ydentifi API
type ApiAuthToken struct {
	RequestorId       string
	RequestorPassword string
	Challenge         string
	Signature         string
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
	UserEmail         string
	PasswordPlaintext string
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
	ContinueToken string
}

// Authenticate2faPayload defines the required
// payload structure for the respective
// endpoints in the Ydentifi API
type Authenticate2faPayload struct {
	ContinueToken string
	Totp          string
}
