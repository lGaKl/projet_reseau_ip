# setup_db.py
# Classe pour la création de la db
import sqlite3

# création de la db
def create_db():
    conn = sqlite3.connect('D:/USB/ECOLE/BAC3/ReseauIP/projet_bis/users.db')
    # curseur permettant d'exécuter les commandes sql
    cursor = conn.cursor()
    
    # création table users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # valider les modif dans la db
    conn.commit()
    # fermeture de la db
    conn.close()

if __name__ == '__main__':
    create_db()
