# -*- coding:utf-8 -*-
import sys

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import * # 기본적인 UI 구성요소를 제공하는 위젯(클래스)


class SettingWindow(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        self.Settings = QLabel(self)
        self.fileSet = QCheckBox(self)
        self.disinfectSet = QCheckBox(self)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Settings')
        self.setWindowIcon(QIcon(".\image\Icon.jpg"))
        self.setFixedSize(580, 380)  # 위젯의 크기를 너비 450px, 높이 300px로 조절
        self.center()  # 중앙에 위치

        self.Settings.setGeometry(QRect(0, 0, 580, 380))
        self.Settings.setText("")
        self.Settings.setPixmap(QPixmap(".\SetImage\SetMain.png"))

        self.fileSet.setGeometry(QRect(232, 191, 20, 20))
        self.fileSet.setStyleSheet("QCheckBox:indicator:unchecked {"
                                   "border: 1px solid #B3B3B3; border-radius: 1px;"
                                   "width: 13px; height: 13px }"
                                   
                                   "QCheckBox:indicator:unchecked:hover {"
                                   "border: 1px solid #0035FF; border-radius: 1px;"
                                   "width: 13px; height: 13px }"
                                   
                                   "QCheckBox:indicator:checked {"
                                   "border: 0; background: #0046FF; border-radius: 2px;"
                                   "width: 14px; height: 14px }")

        self.disinfectSet.setGeometry(QRect(232, 268, 20, 20))
        self.disinfectSet.setStyleSheet("QCheckBox:indicator:unchecked {"
                                        "border: 1px solid #B3B3B3; border-radius: 1px;"
                                        "width: 13px; height: 13px }"

                                        "QCheckBox:indicator:unchecked:hover {"
                                        "border: 1px solid #0035FF; border-radius: 1px;"
                                        "width: 13px; height: 13px }"

                                        "QCheckBox:indicator:checked {"
                                        "border: 0; background: #0046FF; border-radius: 2px;"
                                        "width: 14px; height: 14px }")

    def center(self):
        qr = self.frameGeometry() # 창의 위치와 크기 정보를 가져옴
        # 사용하는 모니터 화면의 가운데 위치를 파악
        cp = QDesktopWidget().availableGeometry().center()
        # 창의 직사강형 위치를 화면의 중심의 위치로 이동
        qr.moveCenter(cp)
        # 현재 창을 화면의 중심으로 이동했던 직사각형(qr)의 위치로 이동
        # 현재 창의 중심이 화면의 중심과 일치하게 돼서 창이 가운데에 나타남
        self.move(qr.topLeft())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    SetOptions = SettingWindow()
    SetOptions.show()
    app.exec_()