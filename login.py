# login.py
import sys
import bcrypt
import sqlite3
from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QLineEdit, QPushButton, QMessageBox
from register import RegisterDialog

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Connexion')
        self.setFixedSize(300, 200)
        
        # Créer la disposition principale
        layout = QVBoxLayout()

        # Champs pour le login
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Identifiant')
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Mot de passe')
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        #btn de connexion
        login_button = QPushButton('Se connecter')
        login_button.clicked.connect(self.handle_login)
        layout.addWidget(login_button)

        # btn pour se register
        register_button = QPushButton('S''enregistrer')
        register_button.clicked.connect(self.open_register_dialog)
        layout.addWidget(register_button)

        # Définir la disposition comme layout principal de la boîte de dialogue
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
