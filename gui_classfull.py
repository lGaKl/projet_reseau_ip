from PyQt5.QtWidgets import QWidget, QLabel, QFormLayout, QGroupBox, QLineEdit, QVBoxLayout, QPushButton
from utils import validate_ip, validate_mask, mask_to_cidr, cidr_to_mask

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
        self.mask_input.setPlaceholderText("Entrer le masque (ex: 255.255.255.0)")
        self.mask_input.setObjectName("mask_input")
        self.mask_input.setFixedHeight(70)

        # Labels pour Adresse IP et Masque
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
        ip = self.ip_input.text()
        mask = self.mask_input.text()

        # Validation de l'adresse IP
        if not validate_ip(ip):
            self.res_label.setText("Adresse IP invalide.")
            return

        # Validation du masque
        if mask.startswith("/"):
            self.res_label.setText("Le masque doit être en format décimal pour le mode ClassFull.")
            return
        elif not validate_mask(mask):
            self.res_label.setText("Masque décimal invalide.")
            return

        # Vérifier la classe de l'adresse IP
        first_octet = int(ip.split('.')[0])
        
        # Déterminer la classe de l'adresse IP et valider le masque
        if 1 <= first_octet <= 126:  # Classe A
            expected_mask = "255.0.0.0"
            mask_class = "Classe A"
            valid_subnets = [
                "255.0.0.0", "255.128.0.0", "255.192.0.0", "255.224.0.0", "255.240.0.0",
                "255.248.0.0", "255.252.0.0", "255.254.0.0", "255.255.0.0", "255.255.128.0",
                "255.255.192.0", "255.255.224.0", "255.255.240.0", "255.255.248.0",
                "255.255.252.0", "255.255.254.0", "255.255.255.0"
            ]
            if mask not in valid_subnets:
                self.res_label.setText("Masque invalide pour une adresse IP de classe A.")
                return
        elif first_octet == 127:  # Classe réservée
            self.res_label.setText("Adresse IP réservée (127.x.x.x) non acceptée.")
            return
        elif 128 <= first_octet <= 191:  # Classe B
            expected_mask = "255.255.0.0"
            mask_class = "Classe B"
            valid_subnets = [
                "255.255.0.0", "255.255.128.0", "255.255.192.0", "255.255.224.0", "255.255.240.0",
                "255.255.248.0", "255.255.252.0", "255.255.254.0", "255.255.255.0"
            ]
            if mask not in valid_subnets:
                self.res_label.setText("Masque invalide pour une adresse IP de classe B.")
                return
        elif 192 <= first_octet <= 223:  # Classe C
            expected_mask = "255.255.255.0"
            mask_class = "Classe C"
            valid_subnets = [
                "255.255.255.0", "255.255.255.128", "255.255.255.192", "255.255.255.224",
                "255.255.255.240", "255.255.255.248", "255.255.255.252"
            ]
            if mask not in valid_subnets:
                self.res_label.setText("Masque invalide pour une adresse IP de classe C.")
                return
        elif 224 <= first_octet <= 239:  # Classe D
            self.res_label.setText("Pas de masque autorisé pour une adresse IP de classe D.")
            return
        elif 240 <= first_octet <= 255:  # Classe E
            self.res_label.setText("Pas de masque autorisé pour une adresse IP de classe E.")
            return

        # Afficher les résultats avec la classe du masque
        self.res_label.setText(f"IP : {ip}, Masque : {mask}, Classe du masque : {mask_class}")
