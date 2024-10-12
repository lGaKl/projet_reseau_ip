# login.py
# Interface pour le login
import sys
import bcrypt
import sqlite3
from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QLineEdit, QPushButton, QMessageBox, QLabel, QHBoxLayout, QWidget
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPixmap
from register import RegisterDialog

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Bienvenue')
        self.setWindowState(Qt.WindowMaximized)
        
        main_layout = QVBoxLayout()
        
        # Widget central pour contenir tous les éléments
        central_widget = QWidget()
        central_layout = QVBoxLayout()
        central_widget.setLayout(central_layout)
        
        # Formulaire
        form_layout = QVBoxLayout()
        form_layout.setContentsMargins(30, 30, 30, 30)
        form_layout.setSpacing(10)
        
        title_label = QLabel('Connexion')
        title_label.setObjectName("title_label")
        title_label.setFont(QFont('Arial', 24, QFont.Bold))
        form_layout.addWidget(title_label, alignment=Qt.AlignCenter)

        username_label = QLabel('Identifiant:')
        username_label.setObjectName("username_label")
        form_layout.addWidget(username_label, alignment=Qt.AlignCenter)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Entrez votre identifiant')
        self.username_input.setObjectName("username_input")
        form_layout.addWidget(self.username_input, alignment=Qt.AlignCenter)

        password_label = QLabel('Mot de passe:')
        password_label.setObjectName("password_label")
        form_layout.addWidget(password_label, alignment=Qt.AlignCenter)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Entrez votre mot de passe')
        self.password_input.setObjectName("password_input")
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(self.password_input, alignment=Qt.AlignCenter)

        loginBtn = QPushButton('Se connecter')
        loginBtn.setObjectName("loginBtn")
        loginBtn.clicked.connect(self.handle_login)
        form_layout.addWidget(loginBtn, alignment=Qt.AlignCenter)

        registerBtn = QPushButton('Créer un compte')
        registerBtn.setObjectName("registerBtn")
        registerBtn.clicked.connect(self.open_register_dialog)
        form_layout.addWidget(registerBtn, alignment=Qt.AlignCenter)

        central_layout.addLayout(form_layout)
        
        main_layout.addWidget(central_widget, alignment=Qt.AlignCenter)
        self.setLayout(main_layout)

    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if self.check_info(username, password):
            self.accept()
        else:
            QMessageBox.warning(self, 'Connexion échouée', 'Identifiant ou mot de passe incorrect.')

    def open_register_dialog(self):
        register_dialog = RegisterDialog()
        if register_dialog.exec_() == QDialog.Accepted:
            QMessageBox.information(self, 'Parfait', 'Enregistrement réussi')

    def check_info(self, username, password):
        conn = sqlite3.connect('D:/USB/ECOLE/BAC3/ReseauIP/projet_bis/users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            hashed_pw = result[0]
            return bcrypt.checkpw(password.encode(), hashed_pw)
        else:
            return False