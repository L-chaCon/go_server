package auth

import (
	"strings"
	"testing"
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
