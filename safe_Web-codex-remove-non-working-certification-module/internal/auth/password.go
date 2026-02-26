package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost = 12
)

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyPassword(password, encoded string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return false, err
}
