# register_user.py
import sqlite3
import bcrypt

def register_user(username,password):
    connector = sqlite3.connect('users.db')
    cursor = connector.cursor

    # Vérifie si le user est déjà dans la db
    cursor.execute("SELECT * FROM users WHERE username = ?", (username))
    if cursor.fetchone():
        print(f"L'utilisateur {username} existe déjà.")
        return False
    
    # Hasher le mdp
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insérer le nouveau user
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    connector.commit()
    connector.close()

    print(f"L'utilisateur {username} a été enregistré avec succès.")
    return True

# Utilisation
if __name__ == '__main__':
    username = input("Entrez le nom d'utilisateur: ")
    password = input("Entrez le mot de passe: ")
    register_user(username, password)