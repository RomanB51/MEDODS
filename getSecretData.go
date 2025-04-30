package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var global_access_token string //переменная имитирующая переменную во фронтенде, в которую сохраняется access токен при авторизации,
//она нужна исключительно для проверки работоспособности функции GetSecretData

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
