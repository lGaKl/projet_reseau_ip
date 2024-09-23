# gui_main.py
# Interface principale avec un stackpane
from PyQt5.QtWidgets import QMainWindow, QToolBar, QAction, QStackedWidget
from PyQt5.QtCore import Qt
from gui_classfull import GuiClassFull
from gui_classless import GuiClassLess 

class GuiMain(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('Projet RéseauIP Groupe 9')
        self.resize(1000, 800)
        self.showMaximized()

        # Création du QStackedWidget pour gérer les différentes interfaces
        self.central_widget = QStackedWidget()
        self.setCentralWidget(self.central_widget)

        # Ajout des widgets ClassFull et ClassLess au QStackedWidget
        self.classfull_widget = GuiClassFull(self)
        self.classless_widget = GuiClassLess(self)

        self.central_widget.addWidget(self.classfull_widget)  # Index 0
        self.central_widget.addWidget(self.classless_widget)  # Index 1

        # Création de la ToolBar en haut de l'interface
        toolbar = QToolBar("Toolbar")
        toolbar.setObjectName("toolBarTop")
        self.addToolBar(Qt.TopToolBarArea, toolbar)

        # Ajout du bouton ClassFull
        classfullBtn = QAction("ClassFull", self)
        classfullBtn.setObjectName("classfullBtn")
        classfullBtn.setStatusTip("Bouton ClassFull")
        classfullBtn.triggered.connect(self.showClassFullWidget)
        toolbar.addAction(classfullBtn)

        # Ajout d'un séparateur pour une meilleure lisibilité
        toolbar.addSeparator()

        # Ajout du bouton ClassLess
        classlessBtn = QAction("ClassLess", self)
        classlessBtn.setStatusTip("Bouton ClassLess")
        classlessBtn.setObjectName("classlessBtn")
        classlessBtn.triggered.connect(self.showClassLessWidget)
        toolbar.addAction(classlessBtn)

        # Ajout d'un séparateur
        toolbar.addSeparator()

    def showClassFullWidget(self):
        # Affichage de la fenêtre ClassFull
        self.central_widget.setCurrentIndex(0)

    def showClassLessWidget(self):
        # Affichage de la fenêtre ClassLess
        self.central_widget.setCurrentIndex(1)
