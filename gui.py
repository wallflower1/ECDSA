import os, sys 
from PyQt4 import QtGui, QtCore 
import collections
from hashlib import md5
import hashlib
import ellipticCurve
import func
import ecdsa
import random

class MainWindow(QtGui.QWidget): 
    def __init__(self): 
        QtGui.QWidget.__init__(self) 

        #Window propoerties         
        self.setGeometry(0,0,500,550) 
        self.setWindowTitle("Elliptic Curve Cryptography - ECDSA") 
        self.setWindowIcon(QtGui.QIcon("icon.png")) 
        self.resize(500,550) 
        self.setMinimumSize(500,550) 
        self.center() 

        #init labels
        self.tab_widget = QtGui.QTabWidget() 
        tab1 = QtGui.QWidget() 
        tab2 = QtGui.QWidget() 

        #box layout
        p1_vertical = QtGui.QVBoxLayout(tab1) 
        p2_vertical = QtGui.QVBoxLayout(tab2)
        
        #add tab widgets
        self.tab_widget.addTab(tab1, "ECC Curve") 
        self.tab_widget.addTab(tab2, "ECDSA")

        #widgets for tab1
        label_a = QtGui.QLabel("enter parameter a:")
        label_b = QtGui.QLabel("enter parameter b:")
        label_n = QtGui.QLabel("enter parameter n (prime number):")

        self.val_a = QtGui.QTextEdit()
        self.val_a.setTabChangesFocus(True)
        self.val_b = QtGui.QTextEdit()
        self.val_b.setTabChangesFocus(True)
        self.val_n = QtGui.QTextEdit()
        self.val_n.setTabChangesFocus(True)

        button_curve = QtGui.QPushButton("Generate curve") 
        button_curve.clicked.connect(self.generate_curve)
        
        self.go_ahead = QtGui.QLabel("Curve defined. Switch Tab to ECDSA.")
        self.go_ahead.hide()

        self.val_a.setMaximumHeight(label_a.sizeHint().height()*2)
        self.val_b.setMaximumHeight(label_b.sizeHint().height()*2)
        self.val_n.setMaximumHeight(label_n.sizeHint().height()*2)
       
        #tab for curve
        p1_vertical.addWidget(label_a)
        p1_vertical.addWidget(self.val_a)
        p1_vertical.addWidget(label_b)
        p1_vertical.addWidget(self.val_b)
        p1_vertical.addWidget(label_n)
        p1_vertical.addWidget(self.val_n) 
        p1_vertical.addStretch(1)
        p1_vertical.addWidget(self.go_ahead)
        p1_vertical.addWidget(button_curve)

        #labels for ECDSA tab
        label_privKey = QtGui.QLabel("enter private key:")
        label_pubKey = QtGui.QLabel("public key:")

        button_pubKey = QtGui.QPushButton("generate public key") 
        button_pubKey.clicked.connect(self.generatePublicKey)

        label_msg = QtGui.QLabel("enter message:")
        label_signature = QtGui.QLabel("Signature:")

        button_gen_sign = QtGui.QPushButton("generate signature")
        button_gen_sign.clicked.connect(self.generateSignature)

        button_verify = QtGui.QPushButton("verify")
        button_verify.clicked.connect(self.verifySignature)
         
        self.val_priv = QtGui.QTextEdit()
        self.val_priv.setTabChangesFocus(True)

        self.val_pub = QtGui.QTextEdit()
        self.val_pub.setTabChangesFocus(True)
        self.val_pub.setReadOnly(True)

        self.val_msg = QtGui.QTextEdit()
        self.val_msg.setTabChangesFocus(True)

        self.val_sign = QtGui.QTextEdit()
        self.val_sign.setTabChangesFocus(True)

        self.val_verify = QtGui.QTextEdit()
        self.val_verify.setTabChangesFocus(True)

        self.val_priv.setMaximumHeight(label_privKey.sizeHint().height()*2)
        self.val_pub.setMaximumHeight(label_pubKey.sizeHint().height()*2)
        self.val_msg.setMaximumHeight(label_privKey.sizeHint().height()*7)
        self.val_sign.setMaximumHeight(label_privKey.sizeHint().height()*7)
        
        #add widgets to ecdsa tab
        p2_vertical.addWidget(label_privKey)
        p2_vertical.addWidget(self.val_priv)
        p2_vertical.addWidget(button_pubKey)
        p2_vertical.addWidget(label_pubKey)
        p2_vertical.addWidget(self.val_pub)
        p2_vertical.addWidget(label_msg)
        p2_vertical.addWidget(self.val_msg)
        p2_vertical.addWidget(button_gen_sign)
        p2_vertical.addWidget(label_signature)
        p2_vertical.addWidget(self.val_sign)
        p2_vertical.addStretch(1)
        p2_vertical.addWidget(button_verify)
        p2_vertical.addWidget(self.val_verify)
        

        vbox = QtGui.QVBoxLayout() 
        vbox.addWidget(self.tab_widget) 
        self.setLayout(vbox) 
    #Start window in the center of the screen
    def center(self): 
        screen = QtGui.QDesktopWidget().screenGeometry() 
        size = self.geometry() 
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2) 

    def generate_curve(self):
        global ec, g, dsa, r
        a = int(self.val_a.toPlainText())
        b = int(self.val_b.toPlainText())
        q = int(self.val_n.toPlainText())
        r = random.randint(1,q)
        ec = ellipticCurve.EC(a, b, q)
        # produce generator point 
        g, _ = ec.at(r)
        assert ec.order(g) <= ec.q
        dsa = ecdsa.DSA(ec, g)
        self.go_ahead.show()

    def generatePublicKey(self):
        global privKey, pub
        privKey = int(self.val_priv.toPlainText())
        pub = dsa.gen(privKey)
        self.val_pub.setText(str(pub))
        pass

    def generateSignature(self):
        global sig
        data = str(self.val_msg.toPlainText())
        hash_datahex = hashlib.sha224(data).hexdigest()
        hashval = int("0x"+hash_datahex, 16)
        sig = dsa.sign(hashval, privKey, r)
        self.val_sign.setText(str(sig))
        pass

    def verifySignature(self):
        msg_rec = str(self.val_msg.toPlainText())
        hash_datahex = hashlib.sha224(msg_rec).hexdigest()
        hashval = int("0x"+hash_datahex, 16)
        ver = dsa.validate(hashval, sig, pub)
        if ver == True:
            self.val_verify.setText("Message verified to be authentic.")
        else :
            self.val_verify.setText("Message not authentic!")
        pass

app = QtGui.QApplication(sys.argv) 
frame = MainWindow() 
frame.show() 
sys.exit(app.exec_())