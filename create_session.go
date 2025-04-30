package main

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

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
