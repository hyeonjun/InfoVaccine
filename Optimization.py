# -*- coding:utf-8 -*-

import sys

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *  # 기본적인 UI 구성요소를 제공하는 위젯(클래스)


class Ui_OptimalWindow(object):
    def initUI(self, OptimalWindow):
        OptimalWindow.setObjectName("OptimalWindow")
        OptimalWindow.setWindowTitle('Optimization')
        OptimalWindow.setWindowIcon(QIcon(".\image\Icon.jpg"))
        OptimalWindow.resize(600, 579)  # 위젯의 크기를 너비 800px, 높이 500px로 조절
        OptimalWindow.center()  # 중앙에 위치

        self.title = QLabel(OptimalWindow)
        self.title.setGeometry(QRect(0, 0, 600, 579))
        self.title.setText("")
        self.title.setPixmap(QPixmap(".\OptimalImage\\Optimization.png"))

        self.ScanInfo = QListWidget(OptimalWindow)
        self.ScanInfo.setGeometry(QRect(40, 70, 510, 450))
        self.ScanInfo.setStyleSheet("QScrollBar:vertical {"
                                    "border: 0; background-color: #FFFFFF; padding: 7px }"

                                    "QScrollBar:handle:vertical {"
                                    "background-color: #CCCCCC;"
                                    "border-radius: 3px; min-height: 50px; }"

                                    "QScrollBar:add-line:vertical {"
                                    "border: 0px }"

                                    "QScrollBar:sub-line:vertical {"
                                    "border: 0px }"

                                    "QScrollBar:horizontal {"
                                    "border: 0; background-color: #FFFFFF; padding: 7px }"

                                    "QScrollBar:handle:horizontal {"
                                    "background-color: #CCCCCC; min-height: 50px;"
                                    "border-radius: 3px }"

                                    "QScrollBar:add-line:horizontal {"
                                    "border: 0px }"

                                    "QScrollBar:sub-line:horizontal {"
                                    "border: 0px }"

                                    "QTextEdit {"
                                    "background: #FFFFFF; border: 1px solid #CCCCCC }")

    def center(self):
        qr = self.frameGeometry()  # 창의 위치와 크기 정보를 가져옴
        # 사용하는 모니터 화면의 가운데 위치를 파악
        cp = QDesktopWidget().availableGeometry().center()
        # 창의 직사강형 위치를 화면의 중심의 위치로 이동
        qr.moveCenter(cp)
        # 현재 창을 화면의 중심으로 이동했던 직사각형(qr)의 위치로 이동
        # 현재 창의 중심이 화면의 중심과 일치하게 돼서 창이 가운데에 나타남
        self.move(qr.topLeft())


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    OptimalWindow = QWidget()
    ui = Ui_OptimalWindow()
    ui.initUI(OptimalWindow)
    OptimalWindow.show()
    app.exec_()