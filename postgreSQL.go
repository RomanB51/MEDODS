package main

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Conn_to_DB() error {

	var err error
	pool, err = pgxpool.New(ctx, "postgres://postgres:postgres@localhost:5432/my_DB")
	if err != nil {
		fmt.Println("Не удалось подключиться к базе данных:", err)
		return err
	}

	if err := pool.Ping(ctx); err != nil {
		fmt.Println("Соединение с БД не активно:", err)
		return err
	}

	fmt.Println("Подключение к PostgreSQL произошло успешно!")
	return nil
}
