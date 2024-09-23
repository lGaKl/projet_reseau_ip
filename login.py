# login.py
# Interface pour le login
import sys
import bcrypt
import sqlite3
from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QLineEdit, QPushButton, QMessageBox, QLabel
from PyQt5.QtGui import QFont
from register import RegisterDialog

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Connexion')
        self.setFixedSize(800, 600)
        
        
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(30)

        
        title_label = QLabel('Connexion')
        title_label.setObjectName("title_label")
        layout.addWidget(title_label)

        # Champs pour le login
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Identifiant')
        self.username_input.setObjectName("username_input")
        self.username_input.setFixedHeight(80)
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Mot de passe')
        self.password_input.setObjectName("password_input")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedHeight(80)
        layout.addWidget(self.password_input)

        #btn de connexion
        loginBtn = QPushButton('Se connecter')
        loginBtn.setObjectName("loginBtn")
        loginBtn.clicked.connect(self.handle_login)
        loginBtn.setFixedHeight(80)
        layout.addWidget(loginBtn)

        # btn pour se register
        registerBtn = QPushButton('S\'enregistrer')
        registerBtn.setObjectName("registerBtn")
        registerBtn.clicked.connect(self.open_register_dialog)
        registerBtn.setFixedHeight(80)
        layout.addWidget(registerBtn)

    
        self.setLayout(layout)

    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if self.check_info(username, password):
            self.accept()
        else:
            QMessageBox.warning(self, 'Connexion échouée', 'Identifiant ou mot de passe incorrecte.')

    def open_register_dialog(self):
        register_dialog = RegisterDialog()
        if register_dialog.exec_() == QDialog.Accepted:
            QMessageBox.information(self, 'Parfait', 'Enregistrement réussi')

    def check_info(self, username, password):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # sélectionne le mdp hashé pour ce user
        # Ajout d'une virgule après username pour en faire un tuple qui contient 1 seul élément
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()

        conn.close()
        
        if result:
            # result[0] est le mot de passe hashé récupéré de la base de données (qui est déjà en bytes)
            hashed_pw = result[0]

            # On compare directement avec le mdp en bytes
            return bcrypt.checkpw(password.encode(), hashed_pw)
        else:
            return False