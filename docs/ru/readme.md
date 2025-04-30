
# REST API для управления задачами (TODO-лист)
Данное API позволяет создавать задачи, читать список всех задач, обновлять задачи и удалять задачи. Список задач хранится в БД PostgreSQL.<!-- описание программы -->

<!--Состав программы-->
## Составные части программы
Реализованная программа имеет в своем составе следующие функции:
1. Conn_to_DB() - функция отвечающая за подключение к БД
2. GetTasks(c *fiber.Ctx) - функция отвечающая за получение списка задач из БД.
3. CreateTask(c *fiber.Ctx) - функция отвечающая за создание новой задачи.
4. UpdateTask(c *fiber.Ctx) - функция отвечающая за обновление состояния задачи.
5. DeleteTask(c *fiber.Ctx) - функция отвечающая за удаление задач из БД

<!--Запуск программы-->
## Запуск программы.
Запуск программы осуществляется из Visual Studio Code, после этого сервер готов к приему запросов по адресу http://localhost:3000. Ниже приведены примеры
различных запросов через Postman и результаты их выполнения:

## Запрос GET:
*Запрос в Postman и результаты запроса:*

![image](https://github.com/RomanB51/Image_for_readme/blob/main/Image_for_SkillsRock/Результат%20выполнения%20запроса%20GET%20Postman%20.png)


*Данные в БД на момент запроса:*

![image](https://github.com/RomanB51/Image_for_readme/blob/main/Image_for_SkillsRock/Результат%20выполнения%20запроса%20GET%20PostgreSQL%20.png)

## Запрос POST:
Создается задание с заголовком "example_title" и описанием "example_descript".
*Запрос в Postman и результаты запроса:*

![image](https://github.com/RomanB51/Image_for_readme/blob/main/Image_for_SkillsRock/Результат%20выполнения%20запроса%20POST%20Postman%20.png)


*Данные в БД после запроса. Созданное задание получило id = 15.*

![image](https://github.com/RomanB51/Image_for_readme/blob/main/Image_for_SkillsRock/Результат%20выполнения%20запроса%20POST%20PostgreSQL%20.png)

## Запрос PUT:
Обновляется задание с id = 3.
*Запрос в Postman и результаты запроса:*

![image](https://github.com/RomanB51/Image_for_readme/blob/main/Image_for_SkillsRock/Результат%20выполнения%20запроса%20PUT%20Postman%20.png)


*Данные в БД после запроса. Задание с id = 3 получило новый заголовок (см. скриншоты БД выше и ниже) "put_title", новое описание "put_descript",
новый статус "done" и также обновилось поле updated_at*

![image](https://github.com/RomanB51/Image_for_readme/blob/main/Image_for_SkillsRock/Результат%20выполнения%20запроса%20PUT%20PostgreSQL%20.png)


## Запрос DELETE:
Удаляется задание с id = 4.
*Запрос в Postman и результаты запроса:*

![image](https://github.com/RomanB51/Image_for_readme/blob/main/Image_for_SkillsRock/Результат%20выполнения%20запроса%20DELETE%20Postman%20.png)


*Данные в БД после запроса. Задание с id = 4 удален из БД (см. скриншоты БД выше и ниже)*

![image](https://github.com/RomanB51/Image_for_readme/blob/main/Image_for_SkillsRock/Результат%20выполнения%20запроса%20DELETE%20PostgreSQL%20.png)






