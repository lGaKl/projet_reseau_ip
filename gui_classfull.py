# gui_classfull.py
# Classe pour l'interface du classfull
from PyQt5.QtWidgets import (QWidget, QLabel, QFormLayout, QGroupBox, 
                             QLineEdit, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QApplication, QStackedWidget, 
                             QTableWidget, QTableWidgetItem, QComboBox, QHeaderView, QSizePolicy, QDialog, QDialogButtonBox, QMessageBox)
from PyQt5.QtGui import QFont, QRegExpValidator
from PyQt5.QtCore import QRegExp, Qt
from utils import validate_ip, validate_mask, mask_to_cidr
import sys
import ipaddress
import math

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
        form_group.setObjectName("form_group_1")
        form_layout = QFormLayout()

        self.ip_input_1 = QLineEdit()
        self.ip_input_1.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.0.1)")
        self.ip_input_1.setObjectName("ipInput1")
        ip_regex = QRegExp(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        ip_validator = QRegExpValidator(ip_regex)
        self.ip_input_1.setValidator(ip_validator)
        form_layout.addRow(QLabel("Adresse IP:"), self.ip_input_1)

        self.mask_input_1 = QLineEdit()
        self.mask_input_1.setPlaceholderText("Entrer le masque (ex: 255.255.255.0)")
        self.mask_input_1.setObjectName("maskInput1")
        mask_regex = QRegExp(r"^(((255\.){3}(255|254|252|248|240|224|192|128|0+))|((255\.){2}(255|254|252|248|240|224|192|128|0+)\.0)|((255\.)(255|254|252|248|240|224|192|128|0+)(\.0+){2})|((255|254|252|248|240|224|192|128|0+)(\.0+){3}))$")
        mask_validator = QRegExpValidator(mask_regex)
        self.mask_input_1.setValidator(mask_validator)
        form_layout.addRow(QLabel("Masque:"), self.mask_input_1)

        self.result_label_1 = QLabel()
        self.result_label_1.setObjectName("resultLabel1")
        form_layout.addRow(QLabel("Résultat:"), self.result_label_1)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        calculate_btn = QPushButton("Calculer")
        calculate_btn.setObjectName("calculate_btn_1")
        calculate_btn.clicked.connect(self.calculate_interface_1)
        layout.addWidget(calculate_btn)

        self.interface_1.setLayout(layout)

    def create_interface_2(self):
        self.interface_2 = QWidget()
        layout = QVBoxLayout()

        form_group = QGroupBox("Vérifier l'appartenance à un réseau:")
        form_group.setObjectName("form_group_2")
        form_layout = QFormLayout()

        self.ip_input_2 = QLineEdit()
        self.ip_input_2.setPlaceholderText("Entrer l'adresse IP")
        self.ip_input_2.setObjectName("ipInput2")
        ip_regex = QRegExp(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        ip_validator = QRegExpValidator(ip_regex)
        self.ip_input_2.setValidator(ip_validator)
        form_layout.addRow(QLabel("Adresse IP:"), self.ip_input_2)

        self.mask_input_2 = QLineEdit()
        self.mask_input_2.setPlaceholderText("Entrer le masque")
        self.mask_input_2.setObjectName("maskInput2")
        mask_regex = QRegExp(r"^(((255\.){3}(255|254|252|248|240|224|192|128|0+))|((255\.){2}(255|254|252|248|240|224|192|128|0+)\.0)|((255\.)(255|254|252|248|240|224|192|128|0+)(\.0+){2})|((255|254|252|248|240|224|192|128|0+)(\.0+){3}))$")
        mask_validator = QRegExpValidator(mask_regex)
        self.mask_input_2.setValidator(mask_validator)
        form_layout.addRow(QLabel("Masque:"), self.mask_input_2)

        self.network_input_2 = QLineEdit()
        self.network_input_2.setPlaceholderText("Entrer l'adresse réseau")
        self.network_input_2.setObjectName("networkInput2")
        network_regex = QRegExp(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        network_validator = QRegExpValidator(network_regex)
        self.network_input_2.setValidator(network_validator)
        form_layout.addRow(QLabel("Adresse réseau:"), self.network_input_2)

        self.result_label_2 = QLabel()
        self.result_label_2.setObjectName("resultLabel2")
        form_layout.addRow(QLabel("Résultat:"), self.result_label_2)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        verify_btn = QPushButton("Vérifier")
        verify_btn.setObjectName("verify_btn_2")
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
        ip_regex = QRegExp(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        ip_validator = QRegExpValidator(ip_regex)
        self.ip_input_3.setValidator(ip_validator)
        form_layout.addRow(QLabel("Adresse IP :"), self.ip_input_3)

        self.subnet_input_3 = QLineEdit()
        self.subnet_input_3.setPlaceholderText("Entrer le nombre de sous-réseaux")
        self.subnet_input_3.setObjectName("subnet_input_3")
        subnet_regex = QRegExp(r"^[1-9]\d*$")
        subnet_validator = QRegExpValidator(subnet_regex)
        self.subnet_input_3.setValidator(subnet_validator)
        form_layout.addRow(QLabel("Nombre de sous-réseaux:"), self.subnet_input_3)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        self.calculate_button = QPushButton("Calculer")
        self.calculate_button.setObjectName("calculate_btn_3")
        self.calculate_button.clicked.connect(self.open_ip_input_dialogs)
        layout.addWidget(self.calculate_button)

        # Créer un tableau pour afficher les résultats
        self.result_table = QTableWidget(self)
        self.result_table.setObjectName("tableWidget_3")
        self.result_table.setColumnCount(7)
        self.result_table.setHorizontalHeaderLabels([
            "Numéro du Sous-Réseau",
            "Adresse de Sous-Réseau",
            "Adresse de Broadcast",
            "1ère IP",
            "Dernière IP",
            "Pas",
            "Nombre d'IP"
        ])

        # Configurer l'en-tête horizontal pour remplir l'espace disponible
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        # Configurer l'en-tête vertical pour s'ajuster au contenu
        self.result_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        # Permettre au tableau de s'étirer verticalement
        self.result_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        layout.addWidget(self.result_table)

        self.interface_3.setLayout(layout)

    def open_ip_input_dialogs(self):
        if self.ip_input_3.text().startswith("127"):
            QMessageBox.warning(self, "Erreur", "Adresse IP invalide")
            return

        try:
            num_subnets = int(self.subnet_input_3.text())
            ip_per_subnet = []

            for i in range(num_subnets):
                dialog = QDialog(self)
                dialog.setWindowTitle(f"Nombre d'IP pour le sous-réseau {i+1}")
                dialog.setMinimumWidth(800)  # Augmenter la largeur minimale
                dialog.setMinimumHeight(300)  # Augmenter la hauteur minimale
                layout = QVBoxLayout()

                ip_input = QLineEdit()
                ip_input.setPlaceholderText(f"Entrer le nombre d'IP pour le sous-réseau {i+1}")
                ip_input.setMinimumWidth(300)  # Augmenter la largeur minimale du champ de saisie
                layout.addWidget(ip_input)

                button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
                button_box.accepted.connect(dialog.accept)
                button_box.rejected.connect(dialog.reject)
                layout.addWidget(button_box)

                dialog.setLayout(layout)

                if dialog.exec_() == QDialog.Accepted:
                    try:
                        ip_count = int(ip_input.text())
                        ip_per_subnet.append(ip_count)
                    except ValueError:
                        raise ValueError(f"Nombre d'IP invalide pour le sous-réseau {i+1}")
                else:
                    return  # L'utilisateur a annulé, on arrête le processus

            self.calculate_subnets_interface_3(ip_per_subnet)
        except ValueError as e:
            self.result_table.setRowCount(0)
            self.result_table.setColumnCount(1)
            self.result_table.setItem(0, 0, QTableWidgetItem(f"Erreur : {e}"))

    def calculate_subnets_interface_3(self, ip_per_subnet):
        ip = self.ip_input_3.text()
        try:
            subnets = self.calculate_subnets(ip, ip_per_subnet)

            self.result_table.setRowCount(len(subnets))
            for i, subnet in enumerate(subnets):
                self.result_table.setItem(i, 0, QTableWidgetItem(str(subnet['numéro_du_sous_réseau'])))
                self.result_table.setItem(i, 1, QTableWidgetItem(subnet['adresse_de_sous_réseau']))
                self.result_table.setItem(i, 2, QTableWidgetItem(subnet['adresse_de_broadcast']))
                self.result_table.setItem(i, 3, QTableWidgetItem(subnet['1ère_ip']))
                self.result_table.setItem(i, 4, QTableWidgetItem(subnet['dernière_ip']))
                self.result_table.setItem(i, 5, QTableWidgetItem(subnet['pas']))
                self.result_table.setItem(i, 6, QTableWidgetItem(str(subnet['nombre_d_ip'])))

        except ValueError as e:
            self.result_table.setRowCount(0)
            self.result_table.setColumnCount(1)
            self.result_table.setItem(0, 0, QTableWidgetItem(f"Erreur : {e}"))
        except Exception as e:
            self.result_table.setRowCount(0)
            self.result_table.setColumnCount(1)
            self.result_table.setItem(0, 0, QTableWidgetItem(f"Erreur inattendue : {e}"))

    def calculate_subnets(self, ip_str, ip_per_subnet):
        # Ajouter un masque par défaut si nécessaire
        if '/' not in ip_str:
            ip_str += self.get_default_mask(ip_str)

        # Convertir l'adresse IP en objet IPv4Network
        network = ipaddress.IPv4Network(ip_str, strict=False)

        subnets_info = []
        current_ip = network.network_address

        for i, num_ips in enumerate(ip_per_subnet):
            # Calculer le nombre de bits nécessaires pour les hôtes
            host_bits = math.ceil(math.log2(num_ips + 2))  # +2 pour l'adresse réseau et de broadcast
            
            # Nouvelle longueur de masque pour ce sous-réseau
            new_prefix = min(32, 32 - host_bits)
            
            # Créer le sous-réseau
            subnet = ipaddress.IPv4Network(f"{current_ip}/{new_prefix}", strict=False)
            
            # Calculer le pas
            pas = subnet.num_addresses
            pas_ip = ipaddress.IPv4Address(pas)
            
            # Déterminer sur quel octet le pas s'applique
            pas_octet = 4 - (32 - new_prefix) // 8
            pas_value = pas_ip.packed[pas_octet - 1]
            
            subnets_info.append({
                "numéro_du_sous_réseau": i + 1,
                "adresse_de_sous_réseau": str(subnet.network_address),
                "adresse_de_broadcast": str(subnet.broadcast_address),
                "1ère_ip": str(subnet.network_address + 1),
                "dernière_ip": str(subnet.broadcast_address - 1),
                "pas": f"{pas_value} sur le {pas_octet}ème octet",
                "nombre_d_ip": num_ips
            })
            
            # Passer à l'adresse IP suivante pour le prochain sous-réseau
            current_ip = subnet.broadcast_address + 1

        return subnets_info

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

    def create_interface_4(self):
        self.interface_4 = QWidget()
        layout = QVBoxLayout()

        form_group = QGroupBox('Découper en IP:')
        form_group.setObjectName("form_group_4")
        form_layout = QFormLayout()

        self.ip_input_4 = QLineEdit()
        self.ip_input_4.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.1.0)")
        self.ip_input_4.setObjectName("ip_input_4")
        ip_regex = QRegExp(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        ip_validator = QRegExpValidator(ip_regex)
        self.ip_input_4.setValidator(ip_validator)
        form_layout.addRow(QLabel("Adresse IP :"), self.ip_input_4)

        self.host_input_4 = QLineEdit()
        self.host_input_4.setPlaceholderText("Entrer le nombre d'IP par sous-réseau")
        self.host_input_4.setObjectName("host_input_4")
        host_regex = QRegExp(r"^[1-9]\d*$")
        host_validator = QRegExpValidator(host_regex)
        self.host_input_4.setValidator(host_validator)
        form_layout.addRow(QLabel("Nombre d'IP par sous-réseau:"), self.host_input_4)

        self.subnet_count_input_4 = QLineEdit()
        self.subnet_count_input_4.setPlaceholderText("Entrer le nombre de sous-réseaux à afficher")
        self.subnet_count_input_4.setObjectName("subnet_count_input_4")
        subnet_count_regex = QRegExp(r"^[1-9]\d*$")
        subnet_count_validator = QRegExpValidator(subnet_count_regex)
        self.subnet_count_input_4.setValidator(subnet_count_validator)
        form_layout.addRow(QLabel("Nombre de sous-réseaux à afficher:"), self.subnet_count_input_4)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        calculate_btn = QPushButton("Calculer")
        calculate_btn.setObjectName("calculate_btn_4")
        calculate_btn.clicked.connect(self.calculate_subnets_interface_4)
        layout.addWidget(calculate_btn)

        # Créer un tableau pour afficher les résultats
        self.result_table_4 = QTableWidget(self)
        self.result_table_4.setObjectName("tableWidget_4")
        self.result_table_4.setColumnCount(7)
        self.result_table_4.setHorizontalHeaderLabels([
            "Numéro du Sous-Réseau",
            "Adresse de Sous-Réseau",
            "Adresse de Broadcast",
            "1ère IP",
            "Dernière IP",
            "Pas",
            "Nombre d'Hôtes"
        ])

        # Configurer l'en-tête horizontal pour remplir l'espace disponible
        header = self.result_table_4.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        # Configurer l'en-tête vertical pour s'ajuster au contenu
        self.result_table_4.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        # Permettre au tableau de s'étirer verticalement
        self.result_table_4.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        layout.addWidget(self.result_table_4)

        self.interface_4.setLayout(layout)

    def calculate_interface_1(self):
        ip = self.ip_input_1.text()
        mask = self.mask_input_1.text()

        if ip.startswith("127"):
            QMessageBox.warning(self, "Erreur", "Adresse IP invalide")
            return

        if not validate_ip(ip):
            self.result_label_1.setText("Adresse IP invalide. Format attendu : xxx.xxx.xxx.xxx (0-255 pour chaque octet)")
            return

        if not validate_mask(mask):
            self.result_label_1.setText("Masque invalide. Format attendu : xxx.xxx.xxx.xxx")
            return

        if mask == "255.255.255.255":
            QMessageBox.warning(self, "Erreur", "Non valide")
            return

        try:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            network_address = str(network.network_address)
            broadcast_address = str(network.broadcast_address)
            self.result_label_1.setText(f"Adresse réseau: {network_address}\nAdresse broadcast: {broadcast_address}")
        except ValueError as e:
            self.result_label_1.setText(f"Erreur : {str(e)}")
    
    def verify_interface_2(self):
        if self.ip_input_2.text().startswith("127"):
            QMessageBox.warning(self, "Erreur", "Adresse IP invalide")
            return

        if self.mask_input_2.text() == "255.255.255.255":
            QMessageBox.warning(self, "Erreur", "Non valide")
            return

        try:
            ip_address = ipaddress.IPv4Address(self.ip_input_2.text())
            mask = self.mask_input_2.text()
            network_address = self.network_input_2.text()
            
            # Calculer l'adresse réseau à partir de l'IP et du masque entrés
            calculated_network = ipaddress.IPv4Network(f"{ip_address}/{mask}", strict=False)
            
            # Vérifier si l'adresse réseau calculée correspond à celle entrée par l'utilisateur
            if str(calculated_network.network_address) == network_address:
                self.result_label_2.setText("L'adresse IP appartient au réseau.")
            else:
                self.result_label_2.setText("L'adresse IP n'appartient pas au réseau.")
        except ValueError as e:
            self.result_label_2.setText(f"Erreur : {str(e)}")
        except Exception as e:
            self.result_label_2.setText(f"Une erreur inattendue s'est produite : {str(e)}")

    def calculate_subnets_interface_4(self):
        if self.ip_input_4.text().startswith("127"):
            QMessageBox.warning(self, "Erreur", "Adresse IP invalide")
            return

        ip = self.ip_input_4.text()
        try:
            hosts_per_subnet = int(self.host_input_4.text())
            subnets_to_display = int(self.subnet_count_input_4.text())
            
            # Calculer le nombre maximum de sous-réseaux possibles
            network = ipaddress.IPv4Network(ip + self.get_default_mask(ip), strict=False)
            max_subnets = (2 ** (32 - network.prefixlen - math.ceil(math.log2(hosts_per_subnet + 2)))-1)
            
            if subnets_to_display > max_subnets:
                QMessageBox.warning(self, "Erreur", f"Le nombre de sous-réseaux demandé ({subnets_to_display}) dépasse le maximum possible ({max_subnets}).")
                return
            
            if network.prefixlen == 32:
                QMessageBox.warning(self, "Erreur", "Non valide")
                return
            
            subnets = self.calculate_subnets_by_hosts(ip, hosts_per_subnet, subnets_to_display)

            self.result_table_4.setRowCount(len(subnets))
            for i, subnet in enumerate(subnets):
                self.result_table_4.setItem(i, 0, QTableWidgetItem(str(subnet['numéro_du_sous_réseau'])))
                self.result_table_4.setItem(i, 1, QTableWidgetItem(subnet['adresse_de_sous_réseau']))
                self.result_table_4.setItem(i, 2, QTableWidgetItem(subnet['adresse_de_broadcast']))
                self.result_table_4.setItem(i, 3, QTableWidgetItem(subnet['1ère_ip']))
                self.result_table_4.setItem(i, 4, QTableWidgetItem(subnet['dernière_ip']))
                self.result_table_4.setItem(i, 5, QTableWidgetItem(subnet['pas']))
                self.result_table_4.setItem(i, 6, QTableWidgetItem(str(subnet['nombre_d_hôtes'])))

        except ValueError as e:
            self.result_table_4.setRowCount(0)
            self.result_table_4.setColumnCount(1)
            self.result_table_4.setItem(0, 0, QTableWidgetItem(f"Erreur : {e}"))
        except Exception as e:
            self.result_table_4.setRowCount(0)
            self.result_table_4.setColumnCount(1)
            self.result_table_4.setItem(0, 0, QTableWidgetItem(f"Erreur inattendue : {e}"))

    def calculate_subnets_by_hosts(self, ip_str, hosts_per_subnet, subnets_to_display):
        # Ajouter un masque par défaut si nécessaire
        if '/' not in ip_str:
            ip_str += self.get_default_mask(ip_str)

        # Convertir l'adresse IP en objet IPv4Network
        network = ipaddress.IPv4Network(ip_str, strict=False)

        # Calculer le nombre de bits nécessaires pour les hôtes
        host_bits = math.ceil(math.log2(hosts_per_subnet + 2))  # +2 pour l'adresse réseau et de broadcast
        
        # Nouvelle longueur de masque
        new_prefix = min(32, network.prefixlen + (32 - network.prefixlen - host_bits))
        
        # Créer le nouveau réseau avec le nouveau préfixe
        new_network = ipaddress.IPv4Network(f"{network.network_address}/{new_prefix}", strict=False)

        # Calculer le pas
        pas = 2 ** (32 - new_prefix)
        pas_ip = ipaddress.IPv4Address(pas)

        # Calculer et afficher les sous-réseaux
        subnets_info = []
        for i in range(subnets_to_display):
            subnet_address = new_network.network_address + (i * pas)
            subnet = ipaddress.IPv4Network(f"{subnet_address}/{new_prefix}", strict=False)
            
            # Déterminer sur quel octet le pas s'applique
            pas_octet = 4 - (32 - new_prefix) // 8
            pas_value = pas_ip.packed[pas_octet - 1]
            
            subnets_info.append({
                "numéro_du_sous_réseau": i + 1,
                "adresse_de_sous_réseau": str(subnet.network_address),
                "adresse_de_broadcast": str(subnet.broadcast_address),
                "1ère_ip": str(subnet.network_address + 1),
                "dernière_ip": str(subnet.broadcast_address - 1),
                "pas": f"{pas_value} sur le {pas_octet}ème octet",
                "nombre_d_hôtes": subnet.num_addresses - 2
            })

        return subnets_info