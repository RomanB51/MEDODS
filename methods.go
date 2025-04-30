package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
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

func CheckToken(providedToken string, cryptToken []byte) bool {
	err := bcrypt.CompareHashAndPassword(cryptToken, []byte(providedToken))

	return err == nil
}

func CreateTokens(c *fiber.Ctx, user *User) error {
	var err error

	user.AccessToken, err = GenerateAccessToken(user.Ip)
	if err != nil {
		return c.Status(500).SendString("Генерация access токена не удалась")
	}

	user.RefreshToken, err = GenerateRefreshToken(user.Ip)
	if err != nil {
		return c.Status(500).SendString("Генерация refresh токена не удалась")
	}

	cryptoRefreshToken, err := CryptRefreshToken(user.RefreshToken)
	if err != nil {
		return c.Status(500).SendString("Шифрование токена не удалось")
	}

	_, err = pool.Exec(ctx, "UPDATE test SET refresh = $1 WHERE id = $2",
		cryptoRefreshToken, user.Id)
	if err != nil {
		return c.Status(500).SendString("Ошибка вставки данных в БД")
	}
	return nil
}

func SetCookies(c *fiber.Ctx, access_token, refresh_token string) error {

	access_cookie := new(fiber.Cookie)
	access_cookie.Name = "access_token"
	access_cookie.Value = access_token
	access_cookie.Expires = time.Now().Add(time.Minute * 15)
	access_cookie.Path = "/auth"
	access_cookie.HTTPOnly = true
	access_cookie.SameSite = "strict"
	access_cookie.Secure = true
	c.Cookie(access_cookie)

	refresh_cookie := new(fiber.Cookie)
	refresh_cookie.Name = "refresh_token"
	refresh_cookie.Value = refresh_token
	refresh_cookie.Expires = time.Now().Add(time.Minute * 30)
	refresh_cookie.Path = "/auth"
	refresh_cookie.HTTPOnly = true
	refresh_cookie.SameSite = "strict"
	refresh_cookie.Secure = true
	c.Cookie(refresh_cookie)
	return nil
}

func CreateSession(c *fiber.Ctx) error {
	var err error
	user := new(User)
	user.Id = c.Get("id")
	user.Ip = c.IP()

	user.RefreshToken, err = GenerateRefreshToken(user.Ip)
	if err != nil {
		return c.Status(500).SendString("Генерация refresh токена не удалась")
	}

	cryptoRefreshToken, err := CryptRefreshToken(user.RefreshToken)
	if err != nil {
		fmt.Println(err)
		return c.Status(500).SendString("Шифрование токена для нового пользователя не удалось")
	}

	_, err = pool.Exec(ctx, "INSERT INTO test (id, refresh) VALUES ($1, $2)",
		user.Id, cryptoRefreshToken)
	if err != nil {
		return c.Status(500).SendString("Ошибка вставки данных в БД")
	}

	user.AccessToken, err = GenerateAccessToken(user.Ip)
	if err != nil {
		return c.Status(500).SendString("Генерация access токена для нового пользователя не удалась")
	}

	SetCookies(c, user.AccessToken, user.RefreshToken)
	return c.Status(201).SendString("Сессия создана для пользователя: " + user.Id)

}

func RefreshTokens(c *fiber.Ctx) error {
	user := new(User)
	user.Id = c.Get("id")
	user.RefreshToken = c.Get("refresh")
	user.Ip = c.IP()

	var refreshToken_from_DB string

	rows, err := pool.Query(ctx, "SELECT refresh FROM test WHERE id = $1",
		user.Id)
	if err != nil {
		return c.Status(400).SendString("Пользователь с таким id не найден")
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&refreshToken_from_DB)
		if err != nil {
			return c.Status(500).SendString("Ошибка сканирования данных")
		}
	}

	if !CheckToken(user.RefreshToken, []byte(refreshToken_from_DB)) {
		return c.Status(400).SendString("Refresh токен устарел")
	}
	fmt.Println("Токен сошелся")

	CreateTokens(c, user)
	SetCookies(c, user.AccessToken, user.RefreshToken)
	return c.Status(201).SendString("Токены успешно обновлены для пользователя: " + user.Id)
}

func GetSecretData(c *fiber.Ctx) error {
	access_token := c.Get("Authorization")
	access_token = strings.TrimPrefix(access_token, "Bearer ")
	fmt.Println("access_token:", access_token)
	fmt.Println("global_access_token:", global_access_token)
	if access_token == global_access_token {
		token, _ := jwt.Parse(access_token, func(token *jwt.Token) (interface{}, error) {
			if _, err := token.Method.(*jwt.SigningMethodHMAC); !err {
				return nil, fmt.Errorf("какие-то проблемы с парсингом токена")
			}
			return accessKey, nil
		})

		claims, err := token.Claims.(jwt.MapClaims)
		if !err {
			return c.Status(202).SendString("Извлечение Payload не удалось")
		}

		for key, val := range claims {
			fmt.Printf("Key: %v, value: %v\n", key, val)
		}

		exp := claims["exp"].(float64)
		if int64(exp) < time.Now().Local().Unix() {
			return c.Status(400).SendString("Токен устарел. Нужна refresh операция.")
		}

		return c.Status(202).SendString("Вот тебе твои секретные данные")

	}
	return c.Status(400).SendString("Неверный токен")

}
