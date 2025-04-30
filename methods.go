package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var global_access_token string //переменная имитирующая переменную во фронтенде, в которую сохраняется access токен при авторизации
var accessKey []byte

func GenerateAccessToken(userIP string) (string, error) {

	claims := jwt.MapClaims{
		"user_ip": userIP,
		"exp":     time.Now().Add(time.Minute * 1).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	global_access_token, _ = token.SignedString(accessKey)

	return token.SignedString(accessKey)
}

func GenerateRefreshToken(userIP string) (string, error) {
	str_err := "Осечка при создании refresh токена:"

	b := make([]byte, 32)
	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)

	if _, err := r.Read(b); err != nil {
		return "", fmt.Errorf("%s: %w", str_err, err)
	}
	return fmt.Sprintf("%x", b), nil

}

func CryptRefreshToken(token string) ([]byte, error) {
	str_err := "Осечка при шифровании refresh токена"
	cryptToken, err := bcrypt.GenerateFromPassword([]byte(token), 3)
	if err != nil {
		return []byte{}, fmt.Errorf("%s: %w", str_err, err)
	}

	return cryptToken, nil
}

func CheckRefreshToken(providedToken, cryptToken string, time_of_creation_refreshToken time.Time) bool {
	fmt.Println(time.Since(time_of_creation_refreshToken))

	if time.Since(time_of_creation_refreshToken) <= time.Second*120 {
		err := bcrypt.CompareHashAndPassword([]byte(cryptToken), []byte(providedToken))
		return err == nil
	}

	return false
}
