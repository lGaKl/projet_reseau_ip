#utils.py
import ipaddress

# validation de l'adresse IP
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# validation du masque 
def validate_mask(mask):
    try:
        if mask.startswith('/'):
            ipaddress.ip_network(f"0.0.0.0{mask}", strict=False)
        else:
            ipaddress.ip_network(f"0.0.0.0/{mask_to_cidr(mask)}", strict=False)
        return True
    except ValueError:
        return False

# transormation du masque en CIDR
def mask_to_cidr(mask):
    return ipaddress.ip_network(f"0.0.0.0{mask}", strict=False).prefixlen

# processus à éffectuer pour le classfull
def process_classfull(ip_address, mask):
    try:
        network = ipaddress.ip_network(f"{ip_address}/{mask_to_cidr(mask)}", strict=False)
        network_address = network.network_address
        broadcast_address = network.broadcast_address
        return (f"Mode: Classfull\n"
                f"IP Adresse: {ip_address}\n"
                f"Masque: {mask}\n"
                f"Adresse de réseau: {network_address}\n"
                f"Adresse de broadcast: {broadcast_address}")
    except ValueError:
        return "Adresse IP ou masque invalide"

# processus à éffectuer pour le classless
def process_classless(ip_address, mask):
    try:
        network = ipaddress.ip_network(f"{ip_address}/{mask_to_cidr(mask)}", strict=False)
        network_address = network.network_address
        broadcast_address = network.broadcast_address
        return (f"Mode: Classless\n"
                f"IP Adresse: {ip_address}\n"
                f"Masque: {mask}\n"
                f"Adresse de sous-réseau: {network_address}\n"
                f"Adresse de broadcast: {broadcast_address}")
    except ValueError:
        return "Adresse IP ou masque invalide"
