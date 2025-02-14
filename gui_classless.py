# gui_classless.py
# Classe pour l'interface du classless
from PyQt5.QtWidgets import QWidget, QLabel, QFormLayout, QGroupBox, QLineEdit, QVBoxLayout, QPushButton, QHBoxLayout, QApplication, QMessageBox
from PyQt5.QtGui import QFont, QRegExpValidator
from PyQt5.QtCore import QRegExp
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
        ip_regex = QRegExp(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        ip_validator = QRegExpValidator(ip_regex)
        self.ip_input.setValidator(ip_validator)

        # Masque
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("Entrer le masque (ex: /24)")
        self.mask_input.setObjectName("mask_input")
        mask_regex = QRegExp(r"^/(?:[1-9]|[12][0-9]|3[0-1])$")
        mask_validator = QRegExpValidator(mask_regex)
        self.mask_input.setValidator(mask_validator)

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

        # Layout pour les boutons
        btn_group = QHBoxLayout()
        

        # Bouton Calculer
        calculateBtn = QPushButton("Calculer")
        calculateBtn.setObjectName("calculateBtn")
        calculateBtn.clicked.connect(self.calculate)
        btn_group.addWidget(calculateBtn)

        #Bouton pour reset le contenu des champs
        resetBtn = QPushButton("Vider les champs")
        resetBtn.setObjectName("resetBtn")
        resetBtn.clicked.connect(self.reset_field)
        btn_group.addWidget(resetBtn)

        # Ajout du layout des boutons au layout principal
        main_layout.addLayout(btn_group)

        self.setLayout(main_layout)

    def reset_field(self):
        self.ip_input.clear()
        self.mask_input.clear()
        self.res_label.clear()
    
    def show_classfull(self):
        self.main_window.showClassFullWidget()

    def calculate(self):
        """
        Cette méthode calcule l'adresse réseau et l'adresse de broadcast à partir d'une adresse IP et d'un masque CIDR.

        Fonctionnement :
        1. Récupère l'adresse IP et le masque CIDR saisis par l'utilisateur.
        2. Valide le format de l'adresse IP et du masque.
        3. Convertit le masque CIDR en masque de sous-réseau décimal.
        4. Calcule l'adresse réseau et l'adresse de broadcast.
        5. Affiche les résultats dans l'interface.

        En cas d'erreur de saisie ou de masque invalide, affiche un message d'erreur approprié.
        """
        ip = self.ip_input.text()
        cidr_mask = self.mask_input.text()

        if not validate_ip(ip):
            self.res_label.setText("Adresse IP invalide. Format attendu : xxx.xxx.xxx.xxx (0-255 pour chaque octet)")
            return

        if not validate_mask(cidr_mask):
            self.res_label.setText("Masque invalide. Format attendu : /xx (1-31)")
            return

        cidr_value = int(cidr_mask[1:])
        if cidr_value == 32:
            QMessageBox.critical(self, "Erreur", "Le masque /32 n'est pas valide pour ce calcul.")
            return

        subnet_mask = cidr_to_mask(cidr_value)

        network_address, broadcast_address = self.calculate_subnet(ip, subnet_mask)

        self.res_label.setText(f"Adresse réseau : {network_address}\nAdresse de broadcast : {broadcast_address}")


    """
        Cette méthode calcule l'adresse réseau et l'adresse de broadcast à partir d'une adresse IP et d'un masque de sous-réseau.

        Fonctionnement :
        1. Conversion de l'adresse IP et du masque en format binaire.
        2. Calcul de l'adresse réseau en effectuant un AND logique entre l'IP et le masque.
        3. Calcul de l'adresse de broadcast en effectuant un OR entre l'adresse réseau et l'inverse du masque.
        4. Conversion des adresses binaires obtenues en format décimal.
        5. Retour des adresses réseau et de broadcast calculées.

        Paramètres :
        - ip : L'adresse IP en format décimal (ex: "192.168.1.1")
        - mask : Le masque de sous-réseau en format décimal (ex: "255.255.255.0")

        Retourne :
        Un tuple contenant l'adresse réseau et l'adresse de broadcast en format décimal.
        """
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