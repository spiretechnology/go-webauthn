# go-webauthn

Go server-side library for WebAuthn registration and verification.

## Installation

```bash
go get github.com/spiretechnology/go-webauthn
```

## Getting Started

### 1. Create a credential store

When users register credentials, they need to be stored somewhere. You can store credentials anywhere you'd like, as long as you implement the `webauthn.CredentialStore` interface.

```go
type myCredentialStore struct {}

func (s *myCredentialStore) GetCredentials(ctx context.Context, user webauthn.User) ([]webauthn.Credential, error) {
    // ...
}

func (s *myCredentialStore) GetCredential(ctx context.Context, user webauthn.User, credentialID []byte) (*webauthn.Credential, error) {
    // ...
}

func (s *myCredentialStore) StoreCredential(ctx context.Context, user webauthn.User, credential webauthn.Credential, meta webauthn.CredentialMeta) error {
    // ...
}
```

Make sure to store all the fields provided in the `webauthn.Credential` struct in your database: `ID`, `Type`, `PublicKey`, and `PublicKeyAlg`.

### 2. Setup a `webauthn.WebAuthn` instance

Create a WebAuthn instance with your relying party information and credential store.

```go
wa := webauthn.New(webauthn.Options{
    RP:          webauthn.RelyingParty{ID: "mycompany.com", Name: "My Company"},
    Credentials: &myCredentialStore{},
})
```

## Registration Example

### 1. Create a registration challenge

When a user sends a request to register a WebAuthn credential, you'll need to generate a registration challenge and send it to the client. You can do this with the `CreateRegistration` method.

```go
// Create a registration challenge
challenge, err := wa.CreateRegistration(ctx, webauthn.User{
    ID:          "123",      // Unique ID for the user (eg. database ID)
    Name:        "johndoe",  // Username or email
    DisplayName: "John Doe", // User's full name
})

// Marshal `challenge` to JSON and send it to the client
// ...
```

The `challenge` value returned is JSON-serializable and can be sent to the client without any additional processing or encoding.

### 2. Verify the registration response

When the user sends back a response to the registration challenge, you can verify it with the `VerifyRegistration` method.

```go
// Unmarshal the user's response from JSON
var response webauthn.RegistrationResponse
// ...

// Verify the registration response
user := webauthn.User{ /* same user as before */ }
result, err := wa.VerifyRegistration(ctx, user, response)
```

## Authentication Example

### 1. Create an authentication challenge

When a user sends a request to authenticate with a WebAuthn credential, you'll generate an authentication challenge and send it to the client. You can do this with the `CreateAuthentication` method.

```go
// Create an authentication challenge
user := webauthn.User{ /* same user as before */ }
challenge, err := wa.CreateAuthentication(ctx, user)

// Marshal `challenge` to JSON and send it to the client
// ...
```

### 2. Verify the authentication response

When the user sends back a response to the authentication challenge, you can verify it with the `VerifyAuthentication` method.

```go
// Unmarshal the user's response from JSON
var response webauthn.AuthenticationResponse
// ...

// Verify the authentication response
user := webauthn.User{ /* same user as before */ }
result, err := wa.AuthenticationRegistration(ctx, user, response)
```

## Client-side processing

For both registration and authentication, the client is responsible for requesting challenges from the server, and responding to those challenges.

We recommend using our [js-webauthn](https://github.com/spiretechnology/js-webauthn) library to handle the client-side flow for you. That library is designed to work with this one.
