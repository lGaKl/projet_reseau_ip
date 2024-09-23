# view_db.py
# Classe pour voir les éléments de la db
import sqlite3

def view_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Récupérer tous les utilisateurs
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()

    if users:
        print("Liste des utilisateurs :")
        for user in users:
            print(f"ID: {user[0]}, Username: {user[1]}, Password (hashed): {user[2]}")
    else:
        print("La base de données est vide.")

    conn.close()

if __name__ == '__main__':
    view_users()
