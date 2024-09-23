# main.py
# Classe pour lancer l'application
import sys
from PyQt5.QtWidgets import QApplication,QDialog
from gui_main import GuiMain
from login import LoginDialog


def main():
    app = QApplication(sys.argv)

    with open('style.qss','r') as file : 
        style_sheet = file.read()
        app.setStyleSheet(style_sheet)
    
    login_dialog = LoginDialog()

    if login_dialog.exec_() == QDialog.Accepted:
        window = GuiMain()
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit()


if __name__ == '__main__':
    main()
# test