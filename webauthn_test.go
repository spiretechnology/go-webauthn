package webauthn_test

import (
	"github.com/spiretechnology/go-webauthn"
	"github.com/spiretechnology/go-webauthn/internal/mocks"
	"github.com/spiretechnology/go-webauthn/internal/testutil"
	"github.com/spiretechnology/go-webauthn/spec"
)

var (
	testRP = spec.RelyingParty{
		ID:   "localhost",
		Name: "Test",
	}

	testUser = webauthn.User{
		ID:          testutil.Encode([]byte{0x01, 0x02, 0x03, 0x04}),
		Name:        "test",
		DisplayName: "Test",
	}

	testCases = []testutil.TestCase{
		{
			Name:               "yubikey 1",
			RelyingParty:       testRP,
			User:               testUser,
			RegistrationJSON:   `{"challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","credentialId":"X-IUuDEypIEmRhA2fy3Nu6vEE6BQqx-VDAaqD269vOSQm-GQnyM8mE6y4oijXPJ8tuKiUp7TtY3xb1Kizn29Ow","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAgAAAAAAAAAAAAAAAAAAAAAAQF_iFLgxMqSBJkYQNn8tzburxBOgUKsflQwGqg9uvbzkkJvhkJ8jPJhOsuKIo1zyfLbiolKe07WN8W9Sos59vTulAQIDJiABIVggLb0gNXeJOo1SwN4LF2StsRVbkEdhgAs9jHTYo6cXmHgiWCDgL2ZzTsVFtXGPuare0-8_oBkJ_4bO0WM5G30FdTZg7g"},"publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELb0gNXeJOo1SwN4LF2StsRVbkEdhgAs9jHTYo6cXmHjgL2ZzTsVFtXGPuare0-8_oBkJ_4bO0WM5G30FdTZg7g","publicKeyAlg":-7}`,
			AuthenticationJSON: `{"challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","credentialId":"X-IUuDEypIEmRhA2fy3Nu6vEE6BQqx-VDAaqD269vOSQm-GQnyM8mE6y4oijXPJ8tuKiUp7TtY3xb1Kizn29Ow","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABA","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","signature":"MEYCIQC-BozuJn4mY5PEqDlEkO2N1_I-EqDZ6W8rWhPbyv8S6QIhAK_ii2WQpanc4jkWc2XktFf_5o2nHOXE1-h8ARnr134W","userHandle":null}}`,
		},
		{
			Name:               "yubikey 2",
			RelyingParty:       testRP,
			User:               testUser,
			RegistrationJSON:   `{"challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","credentialId":"OV8mzVAK474Mpq1Bv-Jp686qsd1G0nMnx9G8_ZQLqCemGSTL459261Rk5evgpyROMNo4upt88EbooRMQ4pbQJg","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAwAAAAAAAAAAAAAAAAAAAAAAQDlfJs1QCuO-DKatQb_iaevOqrHdRtJzJ8fRvP2UC6gnphkky-OfdutUZOXr4KckTjDaOLqbfPBG6KETEOKW0CalAQIDJiABIVggXIFhM06nTGhSjjX7b01SMrhoWW9gYvE2-nVZ6bUTOMsiWCBbMZRb31ULcC6h49_Lv8Drx-Hhbn-BddWGagvjtf7exw"},"publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXIFhM06nTGhSjjX7b01SMrhoWW9gYvE2-nVZ6bUTOMtbMZRb31ULcC6h49_Lv8Drx-Hhbn-BddWGagvjtf7exw","publicKeyAlg":-7}`,
			AuthenticationJSON: `{"challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","credentialId":"OV8mzVAK474Mpq1Bv-Jp686qsd1G0nMnx9G8_ZQLqCemGSTL459261Rk5evgpyROMNo4upt88EbooRMQ4pbQJg","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABw","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9","signature":"MEUCIBqT4_MOE9okSZWCsxrXmv6HrCSLU3D6p-dy3fiOVMQbAiEApmISjHvgfDZlp0E7wbL53U8GBTNCkN7u5AXJ90SLJfM","userHandle":null}}`,
		},
		{
			Name:               "touchid 1",
			RelyingParty:       testRP,
			User:               testUser,
			RegistrationJSON:   `{"challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","credentialId":"sF1j8tUniIBMm6D25knMoFo78_c","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJ9","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFLBdY_LVJ4iATJug9uZJzKBaO_P3pQECAyYgASFYIFD9Km3kX7Rcmcn5qY34qTCe1w1Veg2Cl3scv8wU3-KlIlggRjFcsG6zPRicnEgLI6VdYoI0YFAuhRiSCrzT2ejIogE"},"publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUP0qbeRftFyZyfmpjfipMJ7XDVV6DYKXexy_zBTf4qVGMVywbrM9GJycSAsjpV1igjRgUC6FGJIKvNPZ6MiiAQ","publicKeyAlg":-7}`,
			AuthenticationJSON: `{"challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","credentialId":"sF1j8tUniIBMm6D25knMoFo78_c","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJ9","signature":"MEUCIQD288F5ndy_OvPPjlxZCMVLZnIuWb4NL13soOtUeGuIzwIgGTCmWR4TqTgFyMr5Zj2JCQzRi8Fw0Qya2MV0mdkSfMM","userHandle":"AQIDBA"}}`,
		},
		{
			Name:               "touchid 2",
			RelyingParty:       testRP,
			User:               testUser,
			RegistrationJSON:   `{"challenge":"qwpphdaakQIY6nj38xrzT_Fv6E6rTkp-cVf4KqG5dds","credentialId":"iNoCFwrwzmTJg12Dq19J3e0FaK4","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicXdwcGhkYWFrUUlZNm5qMzh4cnpUX0Z2NkU2clRrcC1jVmY0S3FHNWRkcyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJ9","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIjaAhcK8M5kyYNdg6tfSd3tBWiupQECAyYgASFYIOrn5xzwjOzDjZRJgMytQz-Mc3WKdTaRipGuqhYcqC8CIlggALld712ougeXgzMdE0sAzk-Y1xI7Lf-3yMhqnrPNH6o"},"publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6ufnHPCM7MONlEmAzK1DP4xzdYp1NpGKka6qFhyoLwIAuV3vXai6B5eDMx0TSwDOT5jXEjst_7fIyGqes80fqg","publicKeyAlg":-7}`,
			AuthenticationJSON: `{"challenge":"u1opD5oUNJALsrYFJUrLpJOyPApU2pw0wC5jKoe1JKs","credentialId":"iNoCFwrwzmTJg12Dq19J3e0FaK4","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidTFvcEQ1b1VOSkFMc3JZRkpVckxwSk95UEFwVTJwdzB3QzVqS29lMUpLcyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJ9","signature":"MEYCIQC6wWQxlzK8xV5Wv9l2GzzSOBH2PImLDamWEcnoIOBStQIhAKNAASoESPHL90Ylaa6eBAsVfDcXo8m6UALIwbbgNYAH","userHandle":"AQIDBA"}}`,
		},
	}
)

func setupMocks(opts *webauthn.Options) (webauthn.WebAuthn, *mocks.MockCredentials, *mocks.MockChallenges) {
	credentials := &mocks.MockCredentials{}
	challenges := &mocks.MockChallenges{}

	var options webauthn.Options
	if opts != nil {
		options = *opts
	}
	options.RP = testRP
	options.Credentials = credentials
	options.Challenges = challenges

	w := webauthn.New(options)

	return w, credentials, challenges
}
