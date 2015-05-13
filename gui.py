import os, sys 
from PyQt4 import QtGui, QtCore 
import collections
from hashlib import md5
import hashlib

def inv(n, q):
    """div on PN modulo a/b mod q as a * inv(b, q) mod q
    >>> assert n * inv(n, q) % q == 1
    """
    for i in range(q):
        if (n * i) % q == 1:
            return i
        pass
    assert False, "unreached"
    pass


def sqrt(n, q):
    """sqrt on PN modulo: returns two numbers or exception if not exist
    >>> assert (sqrt(n, q)[0] ** 2) % q == n
    >>> assert (sqrt(n, q)[1] ** 2) % q == n
    """
    assert n < q
    for i in range(1, q):
        if i * i % q == n:
            return (i, q - i)
        pass
    raise Exception("not found")


Coord = collections.namedtuple("Coord", ["x", "y"])


class EC(object):
    """System of Elliptic Curve"""
    def __init__(self, a, b, q):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        self.a = a
        self.b = b
        self.q = q
        # just as unique ZERO value representation for "add": (not on curve)
        self.zero = Coord(0, 0)
        pass

    def is_valid(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        """find points on curve at x
        - x: int < q
        - returns: ((x, y), (x,-y)) or not found exception
        >>> a, ma = ec.at(x)
        >>> assert a.x == ma.x and a.x == x
        >>> assert a.x == ma.x and a.x == x
        >>> assert ec.neg(a) == ma
        >>> assert ec.is_valid(a) and ec.is_valid(ma)
        """
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        """negate p
        >>> assert ec.is_valid(ec.neg(p))
        """
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        """<add> of elliptic curve: negate of 3rd cross point of (p1,p2) line
        >>> d = ec.add(a, b)
        >>> assert ec.is_valid(d)
        >>> assert ec.add(d, ec.neg(b)) == a
        >>> assert ec.add(a, ec.neg(a)) == ec.zero
        >>> assert ec.add(a, b) == ec.add(b, a)
        >>> assert ec.add(a, ec.add(b, c)) == ec.add(ec.add(a, b), c)
        """
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            # p1 + -p1 == 0
            return self.zero
        if p1.x == p2.x:
            # p1 + p1: use tangent line of p1 as (p1,p1) line
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * inv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        """n times <mul> of elliptic curve
        >>> m = ec.mul(p, n)
        >>> assert ec.is_valid(m)
        >>> assert ec.mul(p, 0) == ec.zero
        """
        r = self.zero
        m2 = p
        # O(log2(n)) add
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
                pass
            n, m2 = n >> 1, self.add(m2, m2)
            pass
        # [ref] O(n) add
        #for i in range(n):
        #    r = self.add(r, p)
        #    pass
        return r

    def order(self, g):
        """order of point g
        >>> o = ec.order(g)
        >>> assert ec.is_valid(a) and ec.mul(a, o) == ec.zero
        >>> assert o <= ec.q
        """
        assert self.is_valid(g) and g != self.zero
        for i in range(1, self.q + 1):
            if self.mul(g, i) == self.zero:
                return i
            pass
        raise Exception("Invalid order")
    pass

class DSA(object):
    """ECDSA
    - ec: elliptic curve
    - g: a point on ec
    """
    def __init__(self, ec, g):
        self.ec = ec
        self.g = g
        self.n = ec.order(g)
        pass

    def gen(self, priv):
        """generate pub key"""
        assert 0 < priv and priv < self.n
        return self.ec.mul(self.g, priv)

    def sign(self, hashval, priv, r):
        """generate signature
        - hashval: hash value of message as int
        - priv: priv key as int
        - r: random int 
        - returns: signature as (int, int)
        """
        assert 0 < r and r < self.n
        m = self.ec.mul(self.g, r)
        return (m.x, inv(r, self.n) * (hashval + m.x * priv) % self.n)

    def validate(self, hashval, sig, pub):
        """validate signature
        - hashval: hash value of message as int
        - sig: signature as (int, int)
        - pub: pub key as a point on ec
        """
        assert self.ec.is_valid(pub)
        assert self.ec.mul(pub, self.n) == self.ec.zero
        w = inv(sig[1], self.n)
        u1, u2 = hashval * w % self.n, sig[0] * w % self.n
        p = self.ec.add(self.ec.mul(self.g, u1), self.ec.mul(pub, u2))
        return p.x % self.n == sig[0]
    pass

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
        
        self.tab_widget.addTab(tab1, "ECC Curve") 
        self.tab_widget.addTab(tab2, "ECDSA")

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
        
        self.go_ahead = QtGui.QLabel("Curve defined. Please select a tab based on your need.")
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

        #labels for ECDSA
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
        r = 7
        ec = EC(a, b, q)
        # produce generator point 
        g, _ = ec.at(7)
        assert ec.order(g) <= ec.q
        dsa = DSA(ec, g)
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