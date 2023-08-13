package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/spiretechnology/go-webauthn"
)

var (
	// User details. In production this should not be hard-coded.
	user = webauthn.User{
		ID:          "user1",
		Name:        "user1@example.com",
		DisplayName: "User 1",
	}

	// WebAuthn instance for registering and authenticating user credentials.
	wa = webauthn.New(webauthn.Options{
		RP: webauthn.RelyingParty{
			ID:   "localhost",
			Name: "WebAuthn Example",
		},
		Credentials: &Credentials{},
	})
)

func main() {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("example/static")))
	mux.Handle("/api/register-challenge", HttpGet(registerChallenge))
	mux.Handle("/api/register-verify", HttpPost(registerVerify))
	mux.Handle("/api/authenticate-challenge", HttpGet(authenticateChallenge))
	mux.Handle("/api/authenticate-verify", HttpPost(authenticateVerify))

	fmt.Println("Listening on http://localhost:4000")
	if err := http.ListenAndServe("127.0.0.1:4000", mux); err != nil {
		log.Fatalln("Server error: ", err)
	}
}

func registerChallenge(ctx context.Context) (*webauthn.RegistrationChallenge, error) {
	return wa.CreateRegistration(ctx, user)
}

func registerVerify(ctx context.Context, req *webauthn.RegistrationResponse) (*webauthn.RegistrationResult, error) {
	return wa.VerifyRegistration(ctx, user, req)
}

func authenticateChallenge(ctx context.Context) (*webauthn.AuthenticationChallenge, error) {
	return wa.CreateAuthentication(ctx, user)
}

func authenticateVerify(ctx context.Context, req *webauthn.AuthenticationResponse) (*webauthn.AuthenticationResult, error) {
	return wa.VerifyAuthentication(ctx, user, req)
}
