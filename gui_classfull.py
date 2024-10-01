from PyQt5.QtWidgets import (QWidget, QLabel, QFormLayout, QGroupBox, 
                             QLineEdit, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QApplication, QStackedWidget, 
                             QTableWidget, QTableWidgetItem)
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
        
        self.create_interface_1()
        self.create_interface_2()
        self.create_interface_3()
        
        self.stacked_widget.addWidget(self.interface_1)
        self.stacked_widget.addWidget(self.interface_2)
        self.stacked_widget.addWidget(self.interface_3)
        
        btn_group = QHBoxLayout()
        
        interface1_btn = QPushButton("Vérifier le masque et retour des adresses")
        interface1_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        btn_group.addWidget(interface1_btn)

        interface2_btn = QPushButton("Vérifier l'appartenance IP")
        interface2_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        btn_group.addWidget(interface2_btn)

        interface3_btn = QPushButton("Réaliser une découpe VLSM")
        interface3_btn.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(2))
        btn_group.addWidget(interface3_btn)

        main_layout.addLayout(btn_group)
        main_layout.addWidget(self.stacked_widget)

        self.setLayout(main_layout)

    def create_interface_1(self):
        self.interface_1 = QWidget()
        layout = QVBoxLayout()

        form_group = QGroupBox('Vérifier le masque et calculer réseau/broadcast:')
        form_layout = QFormLayout()

        self.ip_input_1 = QLineEdit()
        self.ip_input_1.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.0.1)")
        form_layout.addRow(QLabel("Adresse IP:"), self.ip_input_1)

        self.mask_input_1 = QLineEdit()
        self.mask_input_1.setPlaceholderText("Entrer le masque (ex: 255.255.255.0)")
        form_layout.addRow(QLabel("Masque:"), self.mask_input_1)

        self.result_label_1 = QLabel()
        form_layout.addRow(QLabel("Résultat:"), self.result_label_1)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        calculate_btn = QPushButton("Calculer")
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
        form_layout.addRow(QLabel("Adresse IP:"), self.ip_input_2)

        self.mask_input_2 = QLineEdit()
        self.mask_input_2.setPlaceholderText("Entrer le masque")
        form_layout.addRow(QLabel("Masque:"), self.mask_input_2)

        self.network_input_2 = QLineEdit()
        self.network_input_2.setPlaceholderText("Entrer l'adresse réseau")
        form_layout.addRow(QLabel("Adresse réseau:"), self.network_input_2)

        self.result_label_2 = QLabel()
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

        form_group = QGroupBox('Découper en sous-réseaux VLSM:')
        form_layout = QFormLayout()

        self.ip_input_3 = QLineEdit()
        self.ip_input_3.setPlaceholderText("Entrer l'adresse IP (ex: 192.168.1.0)")
        form_layout.addRow(QLabel("Adresse IP:"), self.ip_input_3)

        self.mask_input_3 = QLineEdit()
        self.mask_input_3.setPlaceholderText("Entrer le masque (ex: 255.255.255.0)")
        form_layout.addRow(QLabel("Masque:"), self.mask_input_3)

        self.hoster_input_3 = QLineEdit()
        self.hoster_input_3.setPlaceholderText("Entrer le nombre d'hôtes maximum pour tous les sous-réseaux (ex: 10)")
        form_layout.addRow(QLabel("Hôtes maximum par sous-réseau:"), self.hoster_input_3)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        # Create a table to display VLSM results
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(7)
        self.result_table.setHorizontalHeaderLabels(["Sous-réseau", "Masque", "Premier hôte", "Dernier hôte", "Broadcast", "Plage d'adresses", "Nombre d'hôtes"])
        layout.addWidget(self.result_table)

        vlsm_btn = QPushButton("Découper")
        vlsm_btn.clicked.connect(self.calculate_vlsm_interface_3)
        layout.addWidget(vlsm_btn)

        clear_btn = QPushButton("Vider les champs")
        clear_btn.clicked.connect(self.clear_fields_interface_3)
        layout.addWidget(clear_btn)

        # Adding result label for displaying messages
        self.result_label_3 = QLabel()
        layout.addWidget(self.result_label_3)

        self.interface_3.setLayout(layout)

    def clear_fields_interface_3(self):
        self.ip_input_3.clear()
        self.mask_input_3.clear()
        self.hoster_input_3.clear()
        self.result_table.setRowCount(0)

    def calculate_interface_1(self):
        ip = self.ip_input_1.text()
        mask = self.mask_input_1.text()

        if not validate_ip(ip):
            self.result_label_1.setText("Adresse IP invalide.")
            return
        if not validate_mask(mask):
            self.result_label_1.setText("Masque invalide.")
            return

        network, broadcast = self.calculate_subnet(ip, mask)
        self.result_label_1.setText(f"Adresse réseau: {network}, Adresse broadcast: {broadcast}")

    def verify_interface_2(self):
        ip = self.ip_input_2.text()
        mask = self.mask_input_2.text()
        network = self.network_input_2.text()

        if not validate_ip(ip) or not validate_ip(network):
            self.result_label_2.setText("Adresse IP ou réseau invalide.")
            return
        if not validate_mask(mask):
            self.result_label_2.setText("Masque invalide.")
            return

        network_ip, _ = self.calculate_subnet(network, mask)
        belongs = ipaddress.ip_address(ip) in ipaddress.ip_network(f"{network_ip}/{mask}", strict=False)
        self.result_label_2.setText(f"L'IP appartient au réseau." if belongs else f"L'IP n'appartient pas au réseau.")

    def calculate_vlsm_interface_3(self):
        ip = self.ip_input_3.text()
        mask = self.mask_input_3.text()
        max_hosts_input = self.hoster_input_3.text()

        if not validate_ip(ip):
            self.result_label_3.setText("Adresse IP invalide.")
            return

        if not validate_mask(mask):
            self.result_label_3.setText("Masque invalide.")
            return

        try:
            max_hosts = int(max_hosts_input)
            if max_hosts <= 0:
                self.result_label_3.setText("Le nombre d'hôtes maximum doit être un entier positif.")
                return

            result = self.vlsm_fixed_hosts(ip, mask, max_hosts)
            self.result_table.setRowCount(len(result))  # Définir dynamiquement le nombre de lignes
            self.display_results_in_table(result)
            print(result)

        except ValueError:
            self.result_label_3.setText("Le nombre d'hôtes maximum doit être un entier.")

    def display_results_in_table(self, subnets):
        for row, subnet in enumerate(subnets):
            for col, value in enumerate(subnet):
                self.result_table.setItem(row, col, QTableWidgetItem(str(value)))

    def calculate_subnet(self, ip, mask):
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(net.network_address), str(net.broadcast_address)

    def vlsm_fixed_hosts(self, ip, mask, max_hosts):
        # Utiliser le masque fourni par l'utilisateur pour créer le réseau
        base_network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        result = []
        
        # Calculer le masque nécessaire pour le nombre d'hôtes
        needed_bits = self.calculate_mask_for_hosts(max_hosts)
        
        # Commencer avec le réseau de base
        current_network = base_network.network_address
        
        # Boucle pour découper le réseau en sous-réseaux
        while current_network < base_network.broadcast_address:
            new_mask = base_network.max_prefixlen - needed_bits
            new_subnet = ipaddress.IPv4Network(f"{current_network}/{new_mask}", strict=False)

            # Vérifier si le sous-réseau est en dehors de l'espace d'adresses
            if new_subnet.broadcast_address > base_network.broadcast_address:
                break
            
            first_host = new_subnet.network_address + 1
            last_host = new_subnet.broadcast_address - 1

            result.append([
                str(new_subnet.network_address),
                str(new_subnet.netmask),
                str(first_host),
                str(last_host),
                str(new_subnet.broadcast_address),
                f"{first_host} - {last_host}",
                max_hosts
            ])

            # Passer au sous-réseau suivant
            current_network = new_subnet.broadcast_address + 1

        return result

    def calculate_mask_for_hosts(self, host_count):
        return (host_count + 2).bit_length()  # +2 for network and broadcast addresses

