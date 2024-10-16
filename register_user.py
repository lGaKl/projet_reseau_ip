# register_user.py
# Classe pour la protection du mdp du user et pour la vérification de s'il est déjà présent dans la db
import sqlite3
import bcrypt

def register_user(username, password):
    connector = sqlite3.connect('D:/USB/ECOLE/BAC3/ReseauIP/projet_bis/users.db')
    cursor = connector.cursor()  # Correction ici

    # Vérifie si le user est déjà dans la db
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))  # Correction ici
    if cursor.fetchone():
        print(f"L'utilisateur {username} existe déjà.")
        return False
    
    # Hasher le mdp
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(16))

    # Insérer le nouveau user
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    connector.commit()
    connector.close()

    print(f"L'utilisateur {username} a été enregistré avec succès.")
    return True