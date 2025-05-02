
# Часть сервиса аутентификации с использованием JWT.
<!-- описание программы -->
Данное API представляет собой часть сервиса аутентификации с использованием JWT. Список открытых сессий хранится в БД PostgreSQL.

<!--Состав программы-->
## Составные части программы
Реализованная программа имеет в своем составе следующие функции:
1. Conn_to_DB() - функция отвечающая за подключение к БД
2. GenerateAccessToken(userIP string) - функция генерирующая access токен.
3. GenerateRefreshToken(userIP string) - функция генерирующая refresh токен.
4. CryptRefreshToken(token string) - функция шифрующая refresh токен.
5. CheckRefreshToken(providedToken, cryptToken string, time_of_creation_refreshToken time.Time) - функция проверяющая на правильность refresh токен и на то, что его срок годности еще не вышел.
6. SetCookies(c *fiber.Ctx, access_token, refresh_token string) - функция создающая cookie.
7. CreateSession(c *fiber.Ctx) - функция создающая сессию для пользователя с указанным id. Генерирует токены и взаимодействует с БД.
8. RefreshTokens(c *fiber.Ctx) - функция обновляющая токены для указанного пользователя.
9. CreateTokens(c *fiber.Ctx, user *User) - функция создающая новые токены для пользователя и обновляющая их в в БД.

<!--Запуск программы-->
## Запуск программы.
Запуск программы осуществляется из Visual Studio Code, после этого сервер готов к приему запросов по адресу http://localhost:3000.
