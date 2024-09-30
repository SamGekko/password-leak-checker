import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import hashlib
import concurrent.futures

# Кэширование результатов
results_cache = {}

# Функция для хеширования пароля с помощью SHA-1
def hash_password_sha1(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1_hash

# Функция для проверки пароля через API "Have I Been Pwned"
def check_password_pwned(password):
    if password in results_cache:
        return results_cache[password]  # Возвращаем кэшированный результат

    sha1_hash = hash_password_sha1(password)
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(url)

    if response.status_code != 200:
        raise RuntimeError(f'Ошибка API: {response.status_code}')

    # Проверяем, есть ли наш пароль в списке утечек
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            results_cache[password] = int(count)  # Сохраняем в кэш
            return int(count)  # Возвращаем количество утечек

    results_cache[password] = 0  # Пароль не найден, сохраняем в кэш
    return 0

# Функция для отображения результатов в таблице
def show_results_in_table(results):
    # Создаем новое окно для таблицы
    result_window = tk.Toplevel(root)
    result_window.title("Результаты проверки паролей")
    result_window.geometry("850x650")  # Устанавливаем размер окна для таблицы

    # Зафиксируем минимальные размеры окна
    result_window.minsize(850, 650)
    # Ограничим максимальные размеры окна для возможности развертывания в полноэкранный режим
    result_window.maxsize(1920, 1080)

    # Создание стиля для Treeview
    style = ttk.Style()
    style.configure("Treeview", font=('Helvetica', 12))  # Устанавливаем шрифт для Treeview
    style.configure("Treeview.Heading", font=('Helvetica', 14, 'bold'), background="white", foreground="black")  # Стиль заголовков

    # Создаем таблицу (Treeview)
    tree = ttk.Treeview(result_window, columns=("ID", "Username", "Password", "PwnedCount"), show="headings", height=20)
    tree.heading("ID", text="ID")
    tree.heading("Username", text="Имя пользователя")
    tree.heading("Password", text="Пароль")
    tree.heading("PwnedCount", text="Количество утечек")

    # Сортируем результаты по умолчанию по ID
    results.sort(key=lambda x: x[0])  # Сортировка по ID
    for index, (user_id, username, password, count) in enumerate(results):
        tag = "even_row" if index % 2 == 0 else "odd_row"
        tree.insert("", tk.END, values=(user_id, username, password, count), tags=(tag,))

    # Задаем цвета для четных и нечетных строк
    tree.tag_configure("even_row", background="#E8F0FE")
    tree.tag_configure("odd_row", background="#FFFFFF")

    # Упаковываем таблицу
    tree.grid(row=0, column=0, sticky="nsew")

    # Создаем скроллбар
    scrollbar = ttk.Scrollbar(result_window, orient="vertical", command=tree.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")

    # Привязываем скроллбар к таблице
    tree.configure(yscrollcommand=scrollbar.set)

    # Настройка весов для строки и столбца
    result_window.grid_rowconfigure(0, weight=1)  # Строка с таблицей
    result_window.grid_columnconfigure(0, weight=1)  # Столбец с таблицей

    # Добавляем выпадающий список для сортировки
    sort_var = tk.StringVar(value='По умолчанию')  # Значение по умолчанию
    sort_combobox = ttk.Combobox(result_window, textvariable=sort_var, values=["По умолчанию", "По убыванию", "По возрастанию"], state='readonly')
    sort_combobox.grid(row=1, column=0, pady=5)

    # Кнопка для сортировки
    sort_button = tk.Button(result_window, text="Сортировать", command=lambda: sort_results(tree, results, sort_var.get()), font=('Helvetica', 10))
    sort_button.grid(row=2, column=0, padx=5, pady=5)  # Размещаем кнопку в следующем ряду


# Функция для сортировки результатов
def sort_results(tree, results, sort_order):
    # Сортируем результаты в зависимости от выбранного порядка
    if sort_order == 'По убыванию':
        results.sort(key=lambda x: x[3], reverse=True)  # Сортировка по количеству утечек
    elif sort_order == 'По возрастанию':
        results.sort(key=lambda x: x[3])  # Сортировка по количеству утечек
    elif sort_order == 'По умолчанию':
        results.sort(key=lambda x: x[0])  # Сортировка по ID

    # Очищаем текущие элементы в таблице
    tree.delete(*tree.get_children())

    # Заполняем таблицу отсортированными результатами с использованием тегов
    for index, (user_id, username, password, count) in enumerate(results):
        tag = "even_row" if index % 2 == 0 else "odd_row"
        tree.insert("", tk.END, values=(user_id, username, password, count), tags=(tag,))

# Функция для чтения файла и проверки паролей
def check_passwords_from_file():
    file_path = filedialog.askopenfilename(title="Выберите файл", filetypes=(("Текстовые файлы", "*.txt"),))

    if not file_path:
        return

    try:
        with open(file_path, 'r') as file:
            results = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_to_credentials = {}
                
                for line_number, line in enumerate(file, start=1):  # Получаем номер строки
                    line = line.strip()
                    if line:  # Пропускаем пустые строки
                        username, password = line.split(',', 1)  # Разделяем имя и пароль
                        future_to_credentials[executor.submit(check_password_pwned, password)] = (line_number, username, password)

                for future in concurrent.futures.as_completed(future_to_credentials):
                    line_number, username, password = future_to_credentials[future]
                    try:
                        pwned_count = future.result()
                        results.append((line_number, username, password, pwned_count))  # Добавляем line_number как ID
                    except Exception as e:
                        results.append((line_number, username, password, f"Ошибка: {e}"))

            # Показать результаты в таблице
            show_results_in_table(results)

    except Exception as e:
        messagebox.showerror("Ошибка", f'Ошибка при чтении файла: {e}')

# Настройка GUI
root = tk.Tk()
root.title("Проверка утечки паролей")
root.geometry("850x400")  # Устанавливаем размер главного окна

# Зафиксируем минимальные размеры окна
root.minsize(850, 400)
# Ограничим максимальные размеры окна для возможности развертывания в полноэкранный режим
root.maxsize(1920, 1080)

# Установка более крупного шрифта
font_style = ('Helvetica', 12)

# Кнопка для загрузки и проверки файла
file_button = tk.Button(root, text="Загрузить файл для проверки", command=check_passwords_from_file, font=font_style)
file_button.pack(pady=10)

# Запуск главного цикла окна
root.mainloop()
