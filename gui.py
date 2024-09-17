#gui.py
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QHBoxLayout, QGroupBox, QFormLayout, QAction, QMenu
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from utils import validate_ip, validate_mask, mask_to_cidr, process_classfull, process_classless

class IPSubnetApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.loadStyle()

    # Configurer la fenêtre pour occuper tout l'écran avec la barre d'état visible
    def initUI(self):
        self.setWindowTitle('Projet RéseauIP Groupe 9')
        self.resize(800, 600) # Définir une taille initiale plus grande
        self.showMaximized()

        # Création de la barre de menu
        menubar = self.menuBar()
        mode_menu = QMenu('Choix du mode', self)
        menubar.addMenu(mode_menu)

        # Ajout des actions pour les modes Classfull et Classless
        self.classfull_action = QAction('Classfull', self, checkable=True)
        self.classless_action = QAction('Classless', self, checkable=True)

        # Classfull ets choisi par défaut
        self.classfull_action.setChecked(True)

        # Connecter les actions à leurs méthodes
        self.classfull_action.triggered.connect(self.setClassfullMode)
        self.classless_action.triggered.connect(self.setClasslessMode)

        mode_menu.addAction(self.classfull_action)
        mode_menu.addAction(self.classless_action)

        # Disposition principale
        central_widget = QWidget()
        main_layout = QVBoxLayout()

        # Groupe pour le formulaire IP et Masque
        form_group = QGroupBox('Entrer les détails:')
        form_layout = QFormLayout()

        # Champ de saisie pour l'adresse IP
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText('Entrer l\'adresse IP (ex: 192.168.0.1)')
        self.ip_input.setFont(QFont('Arial', 20))
        self.ip_input.setFixedHeight(40)

        # Champ de saisie pour la masque
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText('Entrer le masque (ex: 255.255.255.0 ou /24)')
        self.mask_input.setFont(QFont('Arial', 20))
        self.mask_input.setFixedHeight(40)

        form_layout.addRow(QLabel('Adresse IP:'), self.ip_input)
        form_layout.addRow(QLabel('Masque de sous-réseaux:'), self.mask_input)

        # Label pour afficher les résultats
        self.result_label = QLabel()
        self.result_label.setFont(QFont('Arial', 20))
        self.result_label.setObjectName('result_label')
        form_layout.addRow(QLabel('Résultats:'), self.result_label)

        form_group.setLayout(form_layout)

        # Ajout du formulaire au layout principal
        main_layout.addWidget(form_group)

        # Boutons de calcul et sortie
        button_layout = QHBoxLayout()
        submit_button = QPushButton('Calculer')
        submit_button.setObjectName('submit_button')
        submit_button.clicked.connect(self.submit)

        exit_button = QPushButton('Quitter')
        exit_button.setObjectName('exit_button')
        exit_button.clicked.connect(self.closeApp)

        button_layout.addWidget(submit_button)
        button_layout.addWidget(exit_button)

        # Ajout des boutons au layout principal
        main_layout.addLayout(button_layout)

        # Ajout de marges autour des éléments
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # Définir le widget central et appliquer la disposition principale
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    # Charger le fichier QSS et appliquer le style à l'application
    def loadStyle(self):
        try: 
            with open('style.qss', 'r') as file:
                style = file.read()
            self.setStyleSheet(style)
        except FileNotFoundError:
            print("Le fichier de style est introuvable.")
        except Exception as e:
            print("Erreur lors du chargement du fichier de style :", e)

    # Récupérer les valeurs saisies par l'utilisateur
    def submit(self):
        ip_address = self.ip_input.text()
        mask = self.mask_input.text()

        # Déterminer le mode sélectionné et faire le traitement en fonction
        if self.classfull_action.isChecked():
            result = process_classfull(ip_address, mask)
        else:
            result = process_classless(ip_address, mask)

        # Afficher les résultats
        self.result_label.setText(result)

    # Pour la fermeture de l'application
    def closeApp(self):
        self.close()

    # Permet de quitter l'application en appuyant sur "Esc"
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()

    # selection de classfull
    def setClassfullMode(self):
        self.classfull_action.setChecked(True)
        self.classless_action.setChecked(False)

    # selection de classless
    def setClasslessMode(self):
        self.classfull_action.setChecked(False)
        self.classless_action.setChecked(True)
