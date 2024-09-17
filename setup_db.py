# setup_db.py
import sqlite3
import bcrypt

#création de la db
def create_db():
    conn = sqlite3.connect('users.db')
    #curseur permettant d'exécuter les commandes sql
    cursor = conn.cursor()
    
    #création table users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Ajouter un utilisateur de test avec un mot de passe sécurisé
    username = 'admin'
    password = 'admin123'  # Mot de passe de test
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    #insertion du user dans la table users 
    cursor.execute('''
    INSERT OR IGNORE INTO users (username, password)
    VALUES (?, ?)
    ''', (username, hashed_pw))
    
    #valider les modif dans la db
    conn.commit()
    #fermetur de la db
    conn.close()

if __name__ == '__main__':
    create_db()
