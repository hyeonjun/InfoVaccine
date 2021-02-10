# -*- coding:utf-8 -*-

import sys, os, shutil
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from InfonetVaccine.IV import *

class SelectionPath(QWidget):
    def __init__(self, set1, set2):
        QWidget.__init__(self)

        self.set1 = set1
        self.set2 = set2

        self.path = "C:"  # 경로
        self.index = None  # 위치

        self.tv = QTreeView(self)  # 트리형으로 보기
        self.tv.resize(500, 200)
        # self.tv.setStyleSheet("background: #FFFFFF; border: 1px solid #CCCCCC")
        self.tv.setStyleSheet("QScrollBar:horizontal {"
                              "border: 0; background-color: #FFFFFF; padding: 7px }"
                              
                              "QScrollBar:handle:horizontal {"
                              "background-color: #CCCCCC; min-width: 50px;"
                              "border-radius: 3px }"
                              
                              "QScrollBar:add-line:horizontal {"
                              "border: 0px }"
                              
                              "QScrollBar:sub-line:horizontal {"
                              "border: 0px }"
                              
                              "QScrollBar:vertical {"
                              "border: 0; background-color: #FFFFFF; padding: 7px }"
                              
                              "QScrollBar:handle:vertical {"
                              "background-color: #CCCCCC; min-height: 50px;"
                              "border-radius: 3px }"
                              
                              "QScrollBar:add-line:vertical {"
                              "border: 0px }"
                              
                              "QScrollBar:sub-line:vertical {"
                              "border: 0px }")

        self.model = QFileSystemModel()  # 로컬 파일 시스템에 대한 데이터 모델 제공

        self.setStyleSheet("background: #FFFFFF; border: 1px solid #CCCCCC")

        self.Append_btn = QPushButton("Add")  # 추가버튼
        self.Append_btn.setCheckable(True)
        self.Append_btn.setStyleSheet("QPushButton {"
                                      "background: #FFFFFF; color: #0046FF; font-size: 13px; font-weight: bold;"
                                      "border: 1px solid; border-color: #0046FF; border-radius: 3px;"
                                      "padding: 12px; margin: 10px 10px 10px 160px }"

                                      "QPushButton:pressed {"
                                      "background: #0046FF; color: #FFFFFF; font-size: 13px;"
                                      "border: 0; border-radius: 3px;"
                                      "padding: 12px; margin: 10px 10px 10px 160px }")

        self.delete_btn = QPushButton("Delete")  # 삭제버튼
        self.delete_btn.setCheckable(True)
        self.delete_btn.setStyleSheet("QPushButton {"
                                      "background: #FFFFFF; color: #0046FF; font-size: 13px; font-weight: bold;"
                                      "border: 1px solid; border-color: #0046FF; border-radius: 3px;"
                                      "padding: 12px; margin: 10px 160px 10px 10px }"

                                      "QPushButton:pressed {"
                                      "background: #0046FF; color: #FFFFFF; font-size: 13px;"
                                      "border: 0; border-radius: 3px;"
                                      "padding: 12px; margin: 10px 160px 10px 10px }")

        self.select_list = QListWidget(self)  # 선택한 경로 추가

        self.Confirm_btn = QPushButton("Check")  # 선택한 경로 추가
        self.Confirm_btn.setCheckable(True)
        self.Confirm_btn.setStyleSheet("QPushButton {"
                                       "background: #0046FF; color: #FFFFFF; font-size: 13px; font-weight: bold;"
                                       "border: 0; border-radius: 3px;"
                                       "padding: 12px; margin: 10px 240px 10px }"

                                       "QPushButton:pressed {"
                                       "background: #FFFFFF; color: #0046FF; font-size: 13px; font-weight: bold;"
                                       "border: 1px solid; border-color: #0046FF; border-radius: 3px;"
                                       "padding: 12px; margin: 10px 240px 10px }")

        # self.layout = QVBoxLayout() # 버튼을 추가하기 위해 Layout을 Box형을 변경시켜
        #                            # TreeView와 Button이 같이 보이게 함

        self.filepathP = []
        self.initUI()
        self.setSlot()

    def initUI(self):
        self.setWindowTitle('Dir View')
        self.setWindowIcon(QIcon(".\image\Icon.jpg"))
        self.setFixedSize(700, 800)
        self.center()
        self.model.setRootPath(self.path)
        self.tv.setModel(self.model)  # 트리뷰에서 보여줄 모델 설정
        self.tv.setColumnWidth(0, 250)  # name의 길이 설정(짤리지않게)

        self.layout = QVBoxLayout()  # 버튼을 추가하기 위해 Layout을 Box형을 변경시켜 TreeView와 Button이 같이 보이게 함
        self.layout.addWidget(self.tv)  # 트리뷰 추가

        self.layout2 = QHBoxLayout()
        self.layout2.addWidget(self.Append_btn)  # 버튼 추가
        self.layout2.addWidget(self.delete_btn)  # 버튼 추가

        self.layout3 = QVBoxLayout()
        self.layout3.addWidget(self.select_list)  # 선택한 목록 추가
        self.layout3.addWidget(self.Confirm_btn)  # 버튼 추가

        self.layout4 = QVBoxLayout()
        self.layout4.addLayout(self.layout)
        self.layout4.addLayout(self.layout2)
        self.layout4.addLayout(self.layout3)
        self.setLayout(self.layout4)  # 설정된 layout을 설정

    def setSlot(self):
        self.tv.clicked.connect(self.setIndex)  # 요소 클릭 시 setIndex 호출
        self.Append_btn.clicked.connect(self.append)  # 추가 버튼 클릭 ren 호출
        self.Confirm_btn.clicked.connect(self.confirm)  # 확인 버튼 클릭 ren 호출
        self.delete_btn.clicked.connect(self.delete)  # 삭제 버튼 클릭 ren 호출

    def setIndex(self, index):  # 클릭한 폴더 또는 파일을 index에 넣음
        self.index = index

    def append(self):
        Cpath = self.model.filePath(self.index)
        Ppath = self.model.filePath(self.model.parent(self.index))
        if not self.filepathP:  # filepathP 배열이 비어있으면
            self.filepathP.append(Cpath)  # 추가
            self.select_list.addItem('path : {0}'.format(Cpath))
        else:
            if Cpath in self.filepathP or Ppath in self.filepathP:
                msg = QMessageBox()
                msg.setWindowTitle("Error")
                msg.setWindowIcon(QIcon(".\image\Icon.jpg"))
                msg.setText("<span style='font-size: 11pt; color: #444444'>"
                            "<b>이미 선택된 경로입니다.</span>")
                msg.setInformativeText("<span style='font-size: 7pt; color: #A0A0A0'>"
                                       "다른 경로를 선택해주세요.</span>")
                msg.addButton(QPushButton("Close"), QMessageBox.RejectRole)
                msg.setStyleSheet("QMessageBox {background-color: #FFFFFF}"
                                  "QLabel {min-width: 350 px}"
                                  "QPushButton {"
                                  "background: #0046FF; color: #FFFFFF;"
                                  "border: 0; border-radius: 3px; font-weight: bold; font-size: 12px;"
                                  "width: 140px; height: 35px; margin: 0px 15px 10px}"
                                  "QPushButton:pressed {"
                                  "background: #FFFFFF; color: #0046FF; font-size: 12px; font-weight: bold;"
                                  "border: 1px solid; border-color: #0046FF; border-radius: 3px;"
                                  "width: 140px; height: 35px; margin: 0px 15px 10px }")
                msg.exec_()
            else:
                self.filepathP.append(Cpath)
                self.select_list.addItem('path : {0}'.format(Cpath))

    def delete(self):
        # ListWidget에서 현재 선택한 항목을 삭제할 때는 선택한 항목의 줄을 반환한 후, takeItem함수를 이용해 삭제합니다.
        self.removeItemRow = self.select_list.currentRow()
        try:
            temp = self.select_list.currentItem().text()
            cnt = 0
            for i in self.filepathP:
                if temp[7:] == i:
                    del self.filepathP[cnt]
                cnt += 1
            self.select_list.takeItem(self.removeItemRow)
        except AttributeError:
            msg = QMessageBox()
            msg.setWindowTitle("Error")
            msg.setWindowIcon(QIcon(".\image\Icon.jpg"))
            msg.setText("<span style='font-size: 11pt; color: #444444'>"
                        "<b>경로가 선택되지 않았습니다.</span>")
            msg.setInformativeText("<span style='font-size: 7pt; color: #A0A0A0'>"
                                   "새로운 경로를 선택해주세요.</span>")
            msg.addButton(QPushButton("Close"), QMessageBox.RejectRole)
            msg.setStyleSheet("QMessageBox {background-color: #FFFFFF}"
                              "QLabel {min-width: 370 px}"
                              "QPushButton {"
                              "background: #0046FF; color: #FFFFFF;"
                              "border: 0; border-radius: 3px; font-weight: bold; font-size: 12px;"
                              "width: 130px; height: 35px; margin: 0px 15px 10px }"
                              "QPushButton:pressed {"
                              "background: #FFFFFF; color: #0046FF; font-size: 12px; font-weight: bold;"
                              "border: 1px solid; border-color: #0046FF; border-radius: 3px;"
                              "width: 130px; height: 35px; margin: 0px 15px 10px }")
            msg.exec_()

    def confirm(self):

        self.hide()
        self.iv = InfonetV(self.filepathP, self.set1, self.set2)
        self.window = ScanForm()
        self.iv.started.connect(self.window.show)
        self.iv.logSignal1.connect(self.window.ScanInfo.addItem)
        self.iv.logSignal1.connect(self.window.ScanInfo.scrollToBottom)
        self.iv.logSignal2.connect(self.window.ResultInfo.addItem)
        self.iv.scan()

    def center(self):
        qr = self.frameGeometry()  # 창의 위치와 크기 정보를 가져옴
        # 사용하는 모니터 화면의 가운데 위치를 파악
        cp = QDesktopWidget().availableGeometry().center()
        # 창의 직사강형 위치를 화면의 중심의 위치로 이동
        qr.moveCenter(cp)
        # 현재 창을 화면의 중심으로 이동했던 직사각형(qr)의 위치로 이동
        # 현재 창의 중심이 화면의 중심과 일치하게 돼서 창이 가운데에 나타남
        self.move(qr.topLeft())


if __name__ == '__main__':
    app = QApplication(sys.argv)
    selectPath = SelectionPath()
    selectPath.show()
    app.exec_()
