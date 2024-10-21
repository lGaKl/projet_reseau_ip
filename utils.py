#utils.py
#Classe pour les traitements
import re
import ipaddress

# Validation de l'adresse IP
def validate_ip(ip):
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return False
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets) and len(octets) == 4

# Validation du masque (notation CIDR ou décimale)
def validate_mask(mask):
    if mask.startswith('/'):
        cidr_pattern = r'^/([1-9]|[12][0-9]|3[0-2])$'
        return bool(re.match(cidr_pattern, mask))
    else:
        return validate_ip(mask)

# Conversion de masque décimal vers CIDR
def mask_to_cidr(mask):
    try:
        # Créer un réseau fictif et en extraire la longueur du préfixe CIDR
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
        return network.prefixlen  # Renvoie la longueur du préfixe CIDR comme un entier
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

# Validation de la notation CIDR
def validate_cidr(cidr):
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/([1-9]|[12][0-9]|3[0-2])$'
    return bool(re.match(cidr_pattern, cidr))