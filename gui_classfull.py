from PyQt5.QtWidgets import QWidget, QLabel, QFormLayout, QGroupBox, QLineEdit, QVBoxLayout, QHBoxLayout, QPushButton, QApplication
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

        # Layout pour les boutons
        btn_group = QHBoxLayout()
        
        # Bouton "Changer de mode"
        prevBtn = QPushButton("Changer de mode")
        prevBtn.setObjectName("prevBtn")
        prevBtn.clicked.connect(self.show_classless)
        btn_group.addWidget(prevBtn)

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

        # Bouton pour quitter le programme
        quitBtn = QPushButton("Quitter")
        quitBtn.setObjectName("quitBtn")
        quitBtn.clicked.connect(QApplication.quit)
        btn_group.addWidget(quitBtn)


        # Ajout du layout des boutons au layout principal
        main_layout.addLayout(btn_group)

        self.setLayout(main_layout)

    def reset_field(self):
        self.ip_input.clear()
        self.mask_input.clear()
        self.res_label.clear()

    def show_classless(self):
        self.main_window.showClassLessWidget()

    def calculate(self):
        ip = self.ip_input.text()
        mask = self.mask_input.text()

        # Validation de l'adresse IP
        if not validate_ip(ip):
            self.res_label.setText("Adresse IP invalide.")
            return

        # Validation du masque (doit être en format décimal pour ClassFull)
        if mask.startswith("/"):
            self.res_label.setText("Le masque doit être en format décimal pour le mode ClassFull.")
            return
        elif not validate_mask(mask):
            self.res_label.setText("Masque décimal invalide.")
            return

        # Vérification de la classe IP à partir du premier octet
        first_octet = int(ip.split('.')[0])

        if 1 <= first_octet <= 126:  # Classe A
            expected_mask = "255.0.0.0"
            default_network, default_broadcast = self.calculate_subnet(ip, expected_mask)

            if mask != expected_mask:
                # Découpage en sous-réseaux
                subnet_network, subnet_broadcast = self.calculate_subnet(ip, mask)
                self.res_label.setText(
                    f"IP de sous-réseau : {subnet_network}, IP de broadcast : {subnet_broadcast}"
                )
            else:
                self.res_label.setText(f"Adresse réseau : {default_network}, Adresse broadcast : {default_broadcast}")
            return

        elif 128 <= first_octet <= 191:  # Classe B
            expected_mask = "255.255.0.0"
            default_network, default_broadcast = self.calculate_subnet(ip, expected_mask)

            if mask != expected_mask:
                subnet_network, subnet_broadcast = self.calculate_subnet(ip, mask)
                self.res_label.setText(
                    f"IP de sous-réseau : {subnet_network}, IP de broadcast : {subnet_broadcast}"
                )
            else:
                self.res_label.setText(f"Adresse réseau : {default_network}, Adresse broadcast : {default_broadcast}")
            return

        elif 192 <= first_octet <= 223:  # Classe C
            expected_mask = "255.255.255.0"
            default_network, default_broadcast = self.calculate_subnet(ip, expected_mask)

            if mask != expected_mask:
                subnet_network, subnet_broadcast = self.calculate_subnet(ip, mask)
                self.res_label.setText(
                    f"IP de sous-réseau : {subnet_network}, IP de broadcast : {subnet_broadcast}"
                )
            else:
                self.res_label.setText(f"Adresse réseau : {default_network}, Adresse broadcast : {default_broadcast}")
            return

        # Classe D et E: 224 - 255, non valides
        elif 224 <= first_octet <= 239:  # Classe D
            self.res_label.setText("Pas de masque valide pour une adresse IP de classe D.")
            return
        elif 240 <= first_octet <= 255:  # Classe E
            self.res_label.setText("Pas de masque valide pour une adresse IP de classe E.")
            return

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
        first_ip = '.'.join([str(int(network_bin[i:i+8], 2)) for i in range(0, 32, 8)])
        last_ip = '.'.join([str(int(broadcast_bin[i:i+8], 2)) for i in range(0, 32, 8)])

        return first_ip, last_ip