package main

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
)

func RefreshTokens(c *fiber.Ctx) error {
	user := new(User)
	user.Id = c.Get("id")
	user.RefreshToken = c.Get("refresh")
	user.Ip = c.IP()

	var refreshToken_from_DB string
	var time_of_creation_refreshToken time.Time

	rows, err := pool.Query(ctx, "SELECT refresh, created_at FROM test WHERE id = $1",
		user.Id)
	if err != nil {
		return c.Status(400).SendString("Пользователь с таким id не найден")
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&refreshToken_from_DB, &time_of_creation_refreshToken)
		if err != nil {
			return c.Status(500).SendString("Ошибка сканирования данных")
		}
	}

	if !CheckRefreshToken(user.RefreshToken, refreshToken_from_DB, time_of_creation_refreshToken) {
		return c.Status(400).SendString("Refresh токен устарел или неверен. Введите логин и пароль заново.")
	}
	fmt.Println("Токен сошелся")

	CreateTokens(c, user)
	SetCookies(c, user.AccessToken, user.RefreshToken)
	return c.Status(201).SendString("Токены успешно обновлены для пользователя: " + user.Id)
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

	_, err = pool.Exec(ctx, "UPDATE test SET refresh = $1, created_at = DEFAULT WHERE id = $2",
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
