# go-webauthn

Go server-side library for WebAuthn registration and verification.

## Installation

```bash
go get github.com/spiretechnology/go-webauthn
```

## Usage

### 1. Create a credentials store

When users register credentials, they need to be stored somewhere. You can store credentials anywhere you'd like, as long as you implement the `webauthn.CredentialStore` interface.

```go
type myCredentialStore struct {}

func (s *myCredentialStore) GetCredentials(ctx context.Context, user webauthn.User) ([]webauthn.Credential, error) {
    // ...
}

func (s *myCredentialStore) GetCredential(ctx context.Context, user webauthn.User, credentialID []byte) (*webauthn.Credential, error) {
    // ...
}

func (s *myCredentialStore) StoreCredential(ctx context.Context, user webauthn.User, credential webauthn.Credential) error {
    // ...
}
```

Make sure to store all the fields provided in the `webauthn.Credential` struct in your database: `ID`, `Type`, `PublicKey`, and `PublicKeyAlg`.

### 2. Setup a `webauthn.WebAuthn` instance

```go
wa := webauthn.New(webauthn.Options{
    RP:          webauthn.RelyingParty{ID: "mycompany.com", Name: "My Company"},
    Credentials: &myCredentialStore{},
})
```
