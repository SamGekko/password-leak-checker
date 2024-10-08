# Проверка утечки паролей

Это приложение позволяет проверить, были ли ваши пароли скомпрометированы с помощью API сервиса "Have I Been Pwned". Вы можете загрузить текстовый файл с парами "имя пользователя, пароль" и получить результаты проверки в таблице.

## Задание

Напишите программу на Python, которая считывает файл, содержащий список имен пользователей и паролей, по одной паре в строке (через запятую). Он проверяет каждый пароль на предмет утечки данных в результате утечки данных. Вы можете использовать API «Have I Been Pwned» (https://haveibeenpwned.com/API/v3), чтобы проверить, не была ли утечка пароля. (import requests, hashlib)

## Установка

1. Клонируйте репозиторий:

   ```bash
   git clone https://github.com/SamGekko/password-leak-checker.git
   cd password-leak-checker

2. Установите зависимости:
    ```bash
    pip install -r requirements.txt

## Использование

1. Запустите приложение:
    ```bash
    python main.py

2. Нажмите кнопку "Загрузить файл для проверки", чтобы выбрать файл с парами "имя пользователя, пароль". Формат файла должен быть следующим:
    ```txt
    username1,password1
    username2,password2

<i>P.S. В качестве примера можно использовать уже сгенерированный файл user_pass_test_list.txt</i>

3. После загрузки файла приложение проверит пароли и отобразит результаты в таблице. Вы можете сортировать результаты по количеству утечек.

## Пример вывода:

### 1. По умолчанию:

![plot](default_output.png)

### 2. По убыванию

![plot](decr_output.png)
