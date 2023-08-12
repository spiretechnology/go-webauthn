package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/spiretechnology/go-webauthn"
)

//go:embed index.html
var indexHTML string

func main() {
	wa := webauthn.New(webauthn.Options{
		RP: webauthn.RelyingParty{
			ID:   "localhost",
			Name: "WebAuthn Example",
		},
		Credentials: &Credentials{},
	})

	user := webauthn.User{
		ID:          "user1",
		Name:        "user1@example.com",
		DisplayName: "User 1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/html")
		w.Header().Add("Content-Length", strconv.Itoa(len(indexHTML)))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(indexHTML))
	})
	mux.HandleFunc("/api/register-challenge", func(w http.ResponseWriter, r *http.Request) {
		challenge, _ := wa.CreateRegistration(r.Context(), user)
		challengeJSON, _ := json.Marshal(challenge)

		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Content-Length", strconv.Itoa(len(challengeJSON)))
		w.WriteHeader(http.StatusOK)
		w.Write(challengeJSON)
	})
	mux.HandleFunc("/api/register-response", func(w http.ResponseWriter, r *http.Request) {
		var res webauthn.RegistrationResponse
		_ = json.NewDecoder(r.Body).Decode(&res)
		result, _ := wa.VerifyRegistration(r.Context(), user, &res)
		resultJSON, _ := json.Marshal(result)

		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Content-Length", strconv.Itoa(len(resultJSON)))
		w.WriteHeader(http.StatusOK)
		w.Write(resultJSON)
	})
	mux.HandleFunc("/api/authenticate-challenge", func(w http.ResponseWriter, r *http.Request) {
		challenge, _ := wa.CreateAuthentication(r.Context(), user)
		challengeJSON, _ := json.Marshal(challenge)

		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Content-Length", strconv.Itoa(len(challengeJSON)))
		w.WriteHeader(http.StatusOK)
		w.Write(challengeJSON)
	})
	mux.HandleFunc("/api/authenticate-response", func(w http.ResponseWriter, r *http.Request) {
		var res webauthn.AuthenticationResponse
		_ = json.NewDecoder(r.Body).Decode(&res)
		result, _ := wa.VerifyAuthentication(r.Context(), user, &res)
		resultJSON, _ := json.Marshal(result)

		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Content-Length", strconv.Itoa(len(resultJSON)))
		w.WriteHeader(http.StatusOK)
		w.Write(resultJSON)
	})

	server := http.Server{
		Addr:    "127.0.0.1:4000",
		Handler: mux,
	}
	fmt.Println("Listening on http://localhost:4000")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalln("Server error: ", err)
	}
}
