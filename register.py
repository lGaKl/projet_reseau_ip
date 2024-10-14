# register.py
# Classe pour l'enregistrement d'un nouveau user
import sqlite3
import bcrypt
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QPushButton, QMessageBox, QLabel, QWidget
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class RegisterDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Enregistrement')
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

        title_label = QLabel('Créer un compte')
        title_label.setObjectName("title_label")
        title_label.setFont(QFont('Arial', 24, QFont.Bold))
        form_layout.addWidget(title_label, alignment=Qt.AlignCenter)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Identifiant')
        self.username_input.setObjectName("username_input")
        form_layout.addWidget(self.username_input, alignment=Qt.AlignCenter)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Mot de passe')
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setObjectName("password_input")
        form_layout.addWidget(self.password_input, alignment=Qt.AlignCenter)

        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText('Confirmer le mot de passe')
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setObjectName("password_input")
        form_layout.addWidget(self.confirm_password_input, alignment=Qt.AlignCenter)

        register_button = QPushButton('Enregistrer')
        register_button.setObjectName("registerBtn")
        register_button.clicked.connect(self.handle_register)
        form_layout.addWidget(register_button, alignment=Qt.AlignCenter)

        central_layout.addLayout(form_layout)
        main_layout.addWidget(central_widget, alignment=Qt.AlignCenter)
        self.setLayout(main_layout)

    #Gestion du processus d'enregistrement quand on clique sur le bouton d'enregistrement
    def handle_register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()

        #Vérifier les mdp 
        if password != confirm_password:
            QMessageBox.warning(self, 'Erreur', 'Les mots de passe ne sont pas les mêmes.')
            return

        # si les mdp sont ok -> affiche le message de confirmation
        if self.register_user(username, password):
            QMessageBox.information(self, 'Parfait', 'L\'utilisateur a été enregistré correctement.')
            self.accept()
        else:
            QMessageBox.warning(self, 'Erreur', 'Enregistrement échoué.')

    #Méthode pour enregistrer le user dans la db
    def register_user(self, username, password):
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()

            # Vérifier si l'utilisateur existe déjà
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                return False

            # Hacher le mot de passe
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            # Insérer le nouvel utilisateur
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))

            #validation de l'ajout du user
            conn.commit()
            conn.close()
            return True #True si l'enregistrement est OK
        except Exception as e:
            print(f"Erreur lors de l\'enregistrement: {e}")
            return False
