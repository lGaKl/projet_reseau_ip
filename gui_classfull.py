# gui_classfull.py
# Classe pour l'interface du classfull
from PyQt5.QtWidgets import (QWidget, QLabel, QFormLayout, QGroupBox, 
                             QLineEdit, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QApplication, QStackedWidget, 
                             QTableWidget, QTableWidgetItem, QComboBox)
from PyQt5.QtGui import QFont
from utils import validate_ip, validate_mask, mask_to_cidr
import sys
import ipaddress

class GuiClassFull(QWidget): 
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setObjectName("stacked_widget")
        
        self.create_interface_1()
        self.create_interface_2()
        self.create_interface_3()
        self.create_interface_4()
        
        self.stacked_widget.addWidget(self.interface_1)
        self.stacked_widget.addWidget(self.interface_2)
        self.stacked_widget.addWidget(self.interface_3)
        self.stacked_widget.addWidget(self.interface_4)
        
        btn_group = QHBoxLayout()
        
        interface1_btn = QPushButton("Vérifier le masque et retour des adresses")
        interface1_btn.setObjectName("interface1_btn")
        interface1_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        btn_group.addWidget(interface1_btn)

        interface2_btn = QPushButton("Vérifier l'appartenance IP")
        interface2_btn.setObjectName("interface2_btn")
        interface2_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        btn_group.addWidget(interface2_btn)

        interface3_btn = QPushButton("Réaliser une découpe en sous-réseau")
        interface3_btn.setObjectName("interface3_btn")
        interface3_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        btn_group.addWidget(interface3_btn)

        interface4_btn = QPushButton("Réaliser une découpe en IP")
        interface4_btn.setObjectName("interface4_btn")
        interface4_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(3))
        btn_group.addWidget(interface4_btn)

        main_layout.addLayout(btn_group)
        main_layout.setObjectName("main_layout")
        main_layout.addWidget(self.stacked_widget)

        self.setLayout(main_layout)

    def create_interface_1(self):
        self.interface_1 = QWidget()
        layout = QVBoxLayout()

        form_group = QGroupBox('Vérifier le masque et calculer réseau/broadcast:')
        form_layout = QFormLayout()

        self.ip_input_1 = QLineEdit()
        self.ip_input_1.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.0.1)")
        self.ip_input_1.setObjectName("ipInput1")
        form_layout.addRow(QLabel("Adresse IP:"), self.ip_input_1)

        self.mask_input_1 = QLineEdit()
        self.mask_input_1.setPlaceholderText("Entrer le masque (ex: 255.255.255.0)")
        self.mask_input_1.setObjectName("maskInput1")
        form_layout.addRow(QLabel("Masque:"), self.mask_input_1)

        self.result_label_1 = QLabel()
        self.result_label_1.setObjectName("resultLabel1")
        form_layout.addRow(QLabel("Résultat:"), self.result_label_1)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        calculate_btn = QPushButton("Calculer")
        calculate_btn.setObjectName("calculateBtn1")
        calculate_btn.clicked.connect(self.calculate_interface_1)
        layout.addWidget(calculate_btn)

        self.interface_1.setLayout(layout)

    def create_interface_2(self):
        self.interface_2 = QWidget()
        layout = QVBoxLayout()

        form_group = QGroupBox("Vérifier l'appartenance à un réseau:")
        form_layout = QFormLayout()

        self.ip_input_2 = QLineEdit()
        self.ip_input_2.setPlaceholderText("Entrer l'adresse IP")
        self.ip_input_2.setObjectName("ipInput2")
        form_layout.addRow(QLabel("Adresse IP:"), self.ip_input_2)

        self.mask_input_2 = QLineEdit()
        self.mask_input_2.setPlaceholderText("Entrer le masque")
        self.mask_input_2.setObjectName("maskInput2")
        form_layout.addRow(QLabel("Masque:"), self.mask_input_2)

        self.network_input_2 = QLineEdit()
        self.network_input_2.setPlaceholderText("Entrer l'adresse réseau")
        self.network_input_2.setObjectName("networkInput2")
        form_layout.addRow(QLabel("Adresse réseau:"), self.network_input_2)

        self.result_label_2 = QLabel()
        self.result_label_2.setObjectName("resultLabel2")
        form_layout.addRow(QLabel("Résultat:"), self.result_label_2)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        verify_btn = QPushButton("Vérifier")
        verify_btn.clicked.connect(self.verify_interface_2)
        layout.addWidget(verify_btn)

        self.interface_2.setLayout(layout)

    def create_interface_3(self):
        self.interface_3 = QWidget()
        layout = QVBoxLayout()

        form_group = QGroupBox('Découper en sous-réseaux :')
        form_group.setObjectName("form_group_3")
        form_layout = QFormLayout()

        self.ip_input_3 = QLineEdit()
        self.ip_input_3.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.1.0)")
        self.ip_input_3.setObjectName("ip_input_3")
        form_layout.addRow(QLabel("Adresse IP :"), self.ip_input_3)

        self.subnet_input_3 = QLineEdit()
        self.subnet_input_3.setPlaceholderText("Entrer le nombre de sous-réseaux")
        self.subnet_input_3.setObjectName("subnet_input_3")
        form_layout.addRow(QLabel("Nombre de sous-réseaux:"), self.subnet_input_3)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        self.calculate_button = QPushButton("Calculer")
        self.calculate_button.setObjectName("calculate_button_3")
        self.calculate_button.clicked.connect(self.calculate_subnets_interface_3)
        layout.addWidget (self.calculate_button)

        # Créer un tableau pour afficher les résultats
        self.result_table = QTableWidget(self)
        self.result_table.setObjectName("result_table_3")
        self.result_table.setColumnCount(6)  # 6 colonnes pour les données des sous-réseaux
        self.result_table.setHorizontalHeaderLabels([
            "Numéro du Sous-Réseau",
            "Adresse de Sous-Réseau",
            "Adresse de Broadcast",
            "1ère IP",
            "Dernière IP",
            "Pas"
        ])
        layout.addWidget(self.result_table, 5)

        self.interface_3.setLayout(layout)

    def create_interface_4(self):
        self.interface_4 = QWidget()
        layout = QVBoxLayout()

        form_group = QGroupBox('Découper en IP:')
        form_layout = QFormLayout()

        self.ip_input_4 = QLineEdit()
        self.ip_input_4.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.1.0)")
        form_layout.addRow(QLabel("Adresse IP :"), self.ip_input_4)

        self.mask_input_4 = QLineEdit()
        self.mask_input_4.setPlaceholderText("Entrer le masque (ex: 255.255.255.0)")
        form_layout.addRow(QLabel("Masque:"), self.mask_input_4)

        self.host_input_4 = QLineEdit()
        self.host_input_4.setPlaceholderText("Entrer le nombre d'IP par sous-réseau")
        form_layout.addRow(QLabel("Nombre d'IP par sous-réseau:"), self.host_input_4)

        self.result_label_4 = QLabel()
        form_layout.addRow(QLabel("Résultat:"), self.result_label_4)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        calculate_btn = QPushButton("Calculer")
        # calculate_btn.clicked.connect(self.)
        layout.addWidget(calculate_btn)

        self.interface_4.setLayout(layout)

# OK GARDER
    def calculate_interface_1(self):
        ip_address = self.ip_input_1.text().split(".")
        mask_address = self.mask_input_1.text().split(".")

        ip_address = [int(i) for i in ip_address]
        mask_address = [int(i) for i in mask_address]

        network_address = self.get_network_address(ip_address, mask_address)
        broadcast_address = self.get_broadcast_address(network_address, mask_address)

        self.result_label_1.setText(f"Adresse réseau: {self.address_to_string(network_address)}\nAdresse broadcast: {self.address_to_string(broadcast_address)}")
# OK GARDER
    def verify_interface_2(self):
        ip_address = self.ip_input_2.text().split(".")
        mask_address = self.mask_input_2.text().split(".")
        network_address = self.network_input_2.text().split(".")

        ip_address = [int(i) for i in ip_address]
        mask_address = [int(i) for i in mask_address]
        network_address = [int(i) for i in network_address]

        if self.is_in_network(ip_address, mask_address, network_address):
            self.result_label_2.setText("L'adresse IP appartient au réseau.")
        else:
            self.result_label_2.setText("L'adresse IP n'appartient pas au réseau.")

    def calculate_subnets_interface_3(self):
        ip = self.ip_input_3.text()
        try:
            num_subnets = int(self.subnet_input_3.text())
            subnets = self.calculate_subnets(ip, num_subnets)

            self.result_table.setRowCount(num_subnets)  # Ajuster le nombre de lignes
            for i, subnet in enumerate(subnets):
                self.result_table.setItem(i, 0, QTableWidgetItem(str(subnet['numéro_du_sous_réseau'])))
                self.result_table.setItem(i, 1, QTableWidgetItem(subnet['adresse_de_sous_réseau']))
                self.result_table.setItem(i, 2, QTableWidgetItem(subnet['adresse_de_broadcast']))
                self.result_table.setItem(i, 3, QTableWidgetItem(subnet['1ère_ip']))
                self.result_table.setItem(i, 4, QTableWidgetItem(subnet['dernière_ip']))
                self.result_table.setItem(i, 5, QTableWidgetItem(str(subnet['pas'])))

        except ValueError as e:
            self.result_table.setRowCount(0)  # Réinitialiser la table en cas d'erreur
            self.result_table.setColumnCount(1)
            self.result_table.setItem(0, 0, QTableWidgetItem(f"Erreur : {e}"))

# OK GARDER
    def address_to_string(self, arr_address):
        return '.'.join(map(str, arr_address))

# OK GARDER
    def get_network_address(self, arr_address, arr_mask):
        arr_network = [arr_address[i] & arr_mask[i] for i in range(4)]
        return arr_network

# OK GARDER
    def get_broadcast_address(self, arr_address, arr_mask):
        arr_broadcast_address = [arr_address[i] | (arr_mask[i] ^ 255) for i in range(4)]
        return arr_broadcast_address

# OK GARDER
    def is_in_network(self, ip_address, mask_address, network_address):
        network_address_int = self.address_to_int(network_address)
        ip_address_int = self.address_to_int(ip_address)
        mask_address_int = self.address_to_int(mask_address)
        return (ip_address_int & mask_address_int) == network_address_int
    
    def get_default_mask(self, ip_str):
        """Détermine le masque par défaut en fonction de la classe de l'adresse IP."""
        first_octet = int(ip_str.split('.')[0])

        if first_octet >= 1 and first_octet <= 126:  # Classe A
            return '/8'
        elif first_octet >= 128 and first_octet <= 191:  # Classe B
            return '/16'
        elif first_octet >= 192 and first_octet <= 223:  # Classe C
            return '/24'
        else:
            raise ValueError("Adresse IP non valide. Elle doit être de classe A, B ou C.")

    def calculate_subnets(self, ip_str, num_subnets):
        # Ajouter un masque par défaut si nécessaire
        if '/' not in ip_str:
            # Appelez la méthode avec self
            ip_str += self.get_default_mask(ip_str)

        # Convertir l'adresse IP en objet IPv4Network
        network = ipaddress.IPv4Network(ip_str, strict=False)

        # Déterminer le nombre de bits nécessaires pour les sous-réseaux
        n = 0
        while (2 ** n) - 2 < num_subnets:  # -2 car on ne compte pas le dernier sous-réseau
            n += 1

        # Nouvelle longueur de masque
        new_prefix = network.prefixlen + n
        new_network = ipaddress.IPv4Network(f"{network.network_address}/{new_prefix}", strict=False)

        # Taille du pas
        step = 2 ** (32 - new_prefix)

        # Calculer et afficher les sous-réseaux
        subnets_info = []
        for i in range(num_subnets):  # Limiter aux sous-réseaux demandés
            subnet_address = new_network.network_address + i * step
            broadcast_address = subnet_address + step - 1
            first_ip = subnet_address + 1
            last_ip = broadcast_address - 1

            subnets_info.append({
                "numéro_du_sous_réseau": i + 1,
                "adresse_de_sous_réseau": str(subnet_address),
                "adresse_de_broadcast": str(broadcast_address),
                "1ère_ip": str(first_ip),
                "dernière_ip": str(last_ip),
                "pas": step
            })

        return subnets_info