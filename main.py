#main.py
import sys
from PyQt5.QtWidgets import QApplication, QDialog
from gui import IPSubnetApp
from login import LoginDialog

def main():
    #crée une instance de l'application 
    app = QApplication(sys.argv)

    #crée et affiche la page de login
    login_dialog = LoginDialog()

    #vérification et affichage si ok
    if login_dialog.exec_() == QDialog.Accepted:
        window = IPSubnetApp()
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit()

if __name__ == '__main__':
    main()
