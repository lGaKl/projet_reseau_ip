# gui_classless.py
# Classe pour l'interface du classless
from PyQt5.QtWidgets import QWidget, QLabel, QFormLayout, QGroupBox, QLineEdit, QVBoxLayout, QPushButton
from PyQt5.QtGui import QFont

class GuiClassLess(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.initUI()

    def initUI(self):

        main_layout = QVBoxLayout()

        # Formulaire
        form_group = QGroupBox('Mode ClassLess:')
        form_layout = QFormLayout()

        # Adresse IP
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.0.1)")
        self.ip_input.setFont(QFont('Arial', 25))
        self.ip_input.setFixedHeight(70)

        # Masque
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("Entrer le masque (ex: 255.255.255.0 ou /24)")
        self.mask_input.setFont(QFont('Arial', 25))
        self.mask_input.setFixedHeight(70)

        form_layout.addRow(QLabel('Adresse IP:'), self.ip_input)
        form_layout.addRow(QLabel('Masque de sous-réseaux:'), self.mask_input)

        # Résultats
        self.result_label = QLabel()
        self.result_label.setFont(QFont('Arial', 25))
        self.result_label.setObjectName('result_label')
        form_layout.addRow(QLabel('Résultats:'), self.result_label)

        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)

        # Bouton "Changer de mode"
        prev_button = QPushButton("Changer de mode")
        prev_button.clicked.connect(self.show_classfull)
        main_layout.addWidget(prev_button)

        calculateBtn = QPushButton("Calculer")
        calculateBtn.clicked.connect(self.calculate)
        main_layout.addWidget(calculateBtn)

        self.setLayout(main_layout)

    def show_classfull(self):
        self.main_window.showClassFullWidget()

    def calculate(self):
        print("on attend pour les calculs")
