# gui_classfull.py
# Classe pour l'interface du classfull
from PyQt5.QtWidgets import QWidget, QLabel, QFormLayout, QGroupBox, QLineEdit, QVBoxLayout, QPushButton
from PyQt5.QtGui import QFont

class GuiClassFull(QWidget): 
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.initUI()

    def initUI(self):
        
        main_layout = QVBoxLayout()

        # Formulaire
        form_group = QGroupBox('Mode ClassFull:')
        form_layout = QFormLayout()

        # Adresse IP
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.0.1)")
        self.ip_input.setObjectName("ip_input")
        self.ip_input.setFixedHeight(70)

        # Masque
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("Entrer le masque (ex: 255.255.255.0 ou /24)")
        self.mask_input.setObjectName("mask_input")
        self.mask_input.setFixedHeight(70)

        # Labels pour Adresse IP et Masque avec objectName
        self.ip_label = QLabel('Adresse IP:')
        self.ip_label.setObjectName("ip_label")
        
        self.mask_label = QLabel('Masque de sous-réseaux:')
        self.mask_label.setObjectName("mask_label")

        # Ajout des champs de saisie et des labels au formulaire
        form_layout.addRow(self.ip_label, self.ip_input)
        form_layout.addRow(self.mask_label, self.mask_input)

        # Résultats
        self.result_label = QLabel('Résultats : ')
        self.result_label.setObjectName("result_label")
        self.res_label = QLabel()
        form_layout.addRow(self.result_label, self.res_label)

        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)

        # Bouton "Changer de mode"
        prevBtn = QPushButton("Changer de mode")
        prevBtn.setObjectName("prevBtn")
        prevBtn.clicked.connect(self.show_classless)
        main_layout.addWidget(prevBtn)

        # Bouton Calculer
        calculateBtn = QPushButton("Calculer")
        calculateBtn.setObjectName("calculateBtn")
        calculateBtn.clicked.connect(self.calculate)
        main_layout.addWidget(calculateBtn)

        self.setLayout(main_layout)

    def show_classless(self):
        self.main_window.showClassLessWidget()

    def calculate(self):
        print("on attend pour les calculs")
