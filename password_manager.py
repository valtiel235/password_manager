import secrets
import string
import hashlib
from abc import ABC, abstractmethod
import tkinter as tk
from tkinter import messagebox, filedialog

# Интерфейсы для компонентов
class PasswordGenerator(ABC):
    @abstractmethod
    def generate_password(self, length: int) -> str:
        pass

class PasswordStrengthChecker(ABC):
    @abstractmethod
    def is_strong(self, password: str) -> bool:
        pass

class PasswordHasher(ABC):
    @abstractmethod
    def hash_password(self, password: str) -> str:
        pass

# Реализация генератора паролей
class SecurePasswordGenerator(PasswordGenerator):
    def generate_password(self, length: int) -> str:
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(characters) for _ in range(length))

# Реализация проверки силы пароля
class DefaultPasswordStrengthChecker(PasswordStrengthChecker):
    def is_strong(self, password: str) -> bool:
        return (
            len(password) >= 8 and
            any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)
        )

# Реализация хеширования паролей
class SHA256PasswordHasher(PasswordHasher):
    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

# Класс для работы с GUI
class PasswordManagerApp:
    def __init__(self, generator: PasswordGenerator, checker: PasswordStrengthChecker, hasher: PasswordHasher):
        self.generator = generator
        self.checker = checker
        self.hasher = hasher
        self.root = tk.Tk()
        self.root.title("Менеджер паролей")
        self.create_gui()

    def create_gui(self):
        tk.Label(self.root, text="Длина пароля:").grid(row=0, column=0)
        self.entry_length = tk.Entry(self.root)
        self.entry_length.grid(row=0, column=1)
        self.entry_length.insert(0, "12")

        tk.Button(self.root, text="Сгенерировать пароль", command=self.generate_password_gui).grid(row=1, column=0, columnspan=2, pady=5)

        tk.Label(self.root, text="Сгенерированный пароль:").grid(row=2, column=0)
        self.entry_password = tk.Entry(self.root, width=30)
        self.entry_password.grid(row=2, column=1)

        tk.Button(self.root, text="Проверить силу пароля", command=self.check_password_gui).grid(row=3, column=0, columnspan=2, pady=5)

        tk.Label(self.root, text="Хеш пароля (SHA-256):").grid(row=4, column=0)
        self.entry_hashed_password = tk.Entry(self.root, width=30)
        self.entry_hashed_password.grid(row=4, column=1)

        tk.Button(self.root, text="Хешировать пароль", command=self.hash_password_gui).grid(row=5, column=0, columnspan=2, pady=5)
        tk.Button(self.root, text="Сохранить пароль", command=self.save_password_gui).grid(row=6, column=0, columnspan=2, pady=5)

    def generate_password_gui(self):
        try:
            length = int(self.entry_length.get())
            password = self.generator.generate_password(length)
            self.entry_password.delete(0, tk.END)
            self.entry_password.insert(0, password)
        except ValueError:
            messagebox.showerror("Ошибка", "Введите корректную длину пароля.")

    def check_password_gui(self):
        password = self.entry_password.get()
        if self.checker.is_strong(password):
            messagebox.showinfo("Проверка силы", "Пароль достаточно силен.")
        else:
            messagebox.showwarning("Проверка силы", "Пароль слабый. Попробуйте другой.")

    def hash_password_gui(self):
        password = self.entry_password.get()
        hashed_password = self.hasher.hash_password(password)
        self.entry_hashed_password.delete(0, tk.END)
        self.entry_hashed_password.insert(0, hashed_password)

    def save_password_gui(self):
        password = self.entry_password.get()
        if password:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                     filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(f"Пароль: {password}\n")
                    file.write(f"Хеш пароля (SHA-256): {self.hasher.hash_password(password)}\n")
                messagebox.showinfo("Сохранение", "Пароль сохранен в файл.")
        else:
            messagebox.showwarning("Сохранение", "Пароль отсутствует для сохранения.")

    def run(self):
        self.root.mainloop()

# Инициализация приложения
if __name__ == "__main__":
    generator = SecurePasswordGenerator()
    checker = DefaultPasswordStrengthChecker()
    hasher = SHA256PasswordHasher()
    app = PasswordManagerApp(generator, checker, hasher)
    app.run()
