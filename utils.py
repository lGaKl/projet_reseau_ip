#utils.py
#Classe pour les traitements
import ipaddress

# Validation de l'adresse IP
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Validation du masque (notation CIDR ou décimale)
def validate_mask(mask):
    try:
        if mask.startswith('/'):
            # Valider le format CIDR
            ipaddress.ip_network(f"0.0.0.0{mask}", strict=False)
        else:
            # Valider le format décimal en le convertissant en réseau
            ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
        return True
    except ValueError:
        return False

# Conversion de masque décimal vers CIDR
def mask_to_cidr(mask):
    try:
        # Créer un réseau fictif et en extraire la longueur du préfixe CIDR
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
        return f"/{network.prefixlen}"
    except ValueError:
        return None  # Retourner None si le masque est invalide

# Conversion de CIDR en masque décimal
def cidr_to_mask(cidr):
    try:
        # Créer un réseau fictif et obtenir le masque de sous-réseau
        network = ipaddress.IPv4Network(f"0.0.0.0/{cidr}", strict=False)
        return str(network.netmask)
    except ValueError:
        return None  # Retourner None si la notation CIDR est invalide
