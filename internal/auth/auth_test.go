package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "this_is_a_valid_password",
			wantErr:  false,
		}, {
			name:     "empty password",
			password: "",
			wantErr:  false,
		}, {
			name:     "long password",
			password: strings.Repeat("a", 100),
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if hash == "" {
					t.Error("HashPassword() returned empty hash")
				}
				if hash == tt.password {
					t.Errorf("HashPassword() returned unhashed password")
				}
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "test_p@ssword_123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to create hash for test: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		wantErr  bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			wantErr:  false,
		}, {
			name:     "wrong password",
			password: "wrong_password",
			hash:     hash,
			wantErr:  true,
		}, {
			name:     "invalid hash",
			password: password,
			hash:     "invalid_hash",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHashPasswordAndCheck(t *testing.T) {
	testsCases := []string{
		"simple_password",
		"",
		"special!@#$%^&*()chars",
	}
	for _, password := range testsCases {
		t.Run(password, func(t *testing.T) {
			hash, err := HashPassword(password)
			if err != nil {
				t.Errorf("HashPassword() failed: %v", err)
			}
			err = CheckPasswordHash(password, hash)
			if err != nil {
				t.Errorf("CheckPasswordHash() failed with correct password: %v", err)
			}
			wrongPassword := password + "_wrong"
			err = CheckPasswordHash(wrongPassword, hash)
			if err == nil {
				t.Error("CheckPasswordHash() should fail with wrong password")
			}
		})
	}
}

func TestMakeJWTAndValidate(t *testing.T) {
	tokenSecret := "testSecret"
	userUUID := uuid.New()
	validToken, err := MakeJWT(userUUID, tokenSecret, 1*time.Hour) // 1 hour
	if err != nil {
		t.Fatalf("Failed to create token for test: %v", err)
	}

	// Create an expired token for testing
	expiredToken, err := MakeJWT(userUUID, tokenSecret, -1*time.Hour) // Already expired
	if err != nil {
		t.Fatalf("Failed to create expired token for test: %v", err)
	}

	// Create a token with different secret
	differentSecretToken, err := MakeJWT(userUUID, "differentSecret", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create token with different secret: %v", err)
	}

	tests := []struct {
		name        string
		tokenSecret string
		token       string
		wantErr     bool
		wantUUID    uuid.UUID
		checkUUID   bool // whether to validate the returned UUID
	}{
		{
			name:        "valid token",
			tokenSecret: tokenSecret,
			token:       validToken,
			wantErr:     false,
			wantUUID:    userUUID,
			checkUUID:   true,
		},
		{
			name:        "wrong secret",
			tokenSecret: "wrongSecret",
			token:       validToken,
			wantErr:     true,
			checkUUID:   false,
		},
		{
			name:        "expired token",
			tokenSecret: tokenSecret,
			token:       expiredToken,
			wantErr:     true,
			checkUUID:   false,
		},
		{
			name:        "malformed token",
			tokenSecret: tokenSecret,
			token:       "not.a.token",
			wantErr:     true,
			checkUUID:   false,
		},
		{
			name:        "empty token",
			tokenSecret: tokenSecret,
			token:       "",
			wantErr:     true,
			checkUUID:   false,
		},
		{
			name:        "token signed with different secret",
			tokenSecret: tokenSecret,
			token:       differentSecretToken,
			wantErr:     true,
			checkUUID:   false,
		},
		{
			name:        "empty secret",
			tokenSecret: "",
			token:       validToken,
			wantErr:     true,
			checkUUID:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ValidateJWT(tt.token, tt.tokenSecret)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Only check UUID if test expects success
			if tt.checkUUID && !tt.wantErr {
				if id != tt.wantUUID {
					t.Errorf("ValidateJWT() id = %v, want %v", id, tt.wantUUID)
				}
			}
		})
	}
}
