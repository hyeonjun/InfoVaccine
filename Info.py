# -*- coding:utf-8 -*-
import sys

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import * # 기본적인 UI 구성요소를 제공하는 위젯(클래스)
from PyQt5 import QtGui, QtSvg

class InfoWindow(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Information')
        self.setWindowIcon(QIcon(".\image\Icon.jpg"))
        self.setFixedSize(580, 380)  # 위젯의 크기를 너비 450px, 높이 300px로 조절
        self.center()  # 중앙에 위치

        info = QLabel(self)
        info.setGeometry(QRect(0, 0, 580, 380))
        info.setText("")
        info.setPixmap(QPixmap(".\InformationImage\Info.png"))

    def center(self):
        qr = self.frameGeometry() # 창의 위치와 크기 정보를 가져옴
        # 사용하는 모니터 화면의 가운데 위치를 파악
        cp = QDesktopWidget().availableGeometry().center()
        # 창의 직사강형 위치를 화면의 중심의 위치로 이동
        qr.moveCenter(cp)
        # 현재 창을 화면의 중심으로 이동했던 직사각형(qr)의 위치로 이동
        # 현재 창의 중심이 화면의 중심과 일치하게 돼서 창이 가운데에 나타남
        self.move(qr.topLeft())


