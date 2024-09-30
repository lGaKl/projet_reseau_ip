# gui_classless.py
# Classe pour l'interface du classless
from PyQt5.QtWidgets import QWidget, QLabel, QFormLayout, QGroupBox, QLineEdit, QVBoxLayout, QPushButton
from PyQt5.QtGui import QFont
from utils import validate_ip, validate_mask, mask_to_cidr, cidr_to_mask

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
        self.ip_input.setObjectName("ip_input")
        self.ip_input.setFixedHeight(70)

        # Masque
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("Entrer le masque (ex:/24)")
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
        prevBtn.clicked.connect(self.show_classfull)
        main_layout.addWidget(prevBtn)

        calculateBtn = QPushButton("Calculer")
        calculateBtn.setObjectName("calculateBtn")
        calculateBtn.clicked.connect(self.calculate)
        calculateBtn.clicked.connect(self.calculate)
        main_layout.addWidget(calculateBtn)

        self.setLayout(main_layout)

    def show_classfull(self):
        self.main_window.showClassFullWidget()

    def calculate(self):
        ip = self.ip_input.text()
        cidr_mask = self.mask_input.text()

        # Validation de l'adresse IP
        if not validate_ip(ip):
            self.res_label.setText("Adresse IP invalide.")
            return

        # Validation du masque en notation CIDR
        if not cidr_mask.startswith("/") or not validate_mask(cidr_mask):
            self.res_label.setText("Le masque doit être en notation CIDR (ex: /24).")
            return

        # Extraire la valeur CIDR (ex: /24 -> 24)
        cidr_value = int(cidr_mask[1:])

        # Convertir la notation CIDR en masque décimal
        subnet_mask = cidr_to_mask(cidr_value)  # Par exemple, /24 devient 255.255.255.0

        # Calculer l'adresse réseau et l'adresse de broadcast
        network_address, broadcast_address = self.calculate_subnet(ip, subnet_mask)

        # Affichage des résultats
        self.res_label.setText(f"Adresse réseau : {network_address}\nAdresse de broadcast : {broadcast_address}")

    # Fonction pour calculer l'adresse réseau et l'adresse de broadcast
    def calculate_subnet(self, ip, mask):
        # Convertir IP et masque en binaire
        ip_bin = ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
        mask_bin = ''.join([bin(int(x)+256)[3:] for x in mask.split('.')])

        # Calcul de l'adresse réseau (AND entre IP et masque)
        network_bin = ''.join(['1' if ip_bin[i] == '1' and mask_bin[i] == '1' else '0' for i in range(32)])

        # Calcul de l'adresse de broadcast (OR entre adresse réseau et inverse du masque)
        broadcast_bin = ''.join([network_bin[i] if mask_bin[i] == '1' else '1' for i in range(32)])

        # Conversion des adresses binaires en format décimal
        network_address = '.'.join([str(int(network_bin[i:i+8], 2)) for i in range(0, 32, 8)])
        broadcast_address = '.'.join([str(int(broadcast_bin[i:i+8], 2)) for i in range(0, 32, 8)])

        return network_address, broadcast_address

