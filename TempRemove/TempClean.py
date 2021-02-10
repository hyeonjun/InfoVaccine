# -*- coding:utf-8 -*-

import os
import sys
import shutil
import getpass
import Optimization
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import * # 기본적인 UI 구성요소를 제공하는 위젯(클래스)
import time

tmp = ""
deleteFileCount = 0
deleteFolderCount = 0

class TempRemove(QMainWindow, Optimization.Ui_OptimalWindow):
    def __init__(self, parent = None):
        super(QMainWindow, self).__init__(parent)
        self.initUI(self)
        self.Clean()

    def Task(self, folderName):
        global tmp, deleteFileCount, deleteFolderCount
        for the_file in os.listdir(folderName):
            file_path = os.path.join(folderName, the_file)
            indexNo = file_path.find('\\')
            itemName = file_path[indexNo + 1:]
            try:
                self.show()
                self.ScanInfo.repaint()
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    self.ScanInfo.append(str(tmp + ('%s file deleted' % itemName)))
                    deleteFileCount = deleteFileCount + 1


                elif os.path.isdir(file_path):
                    if file_path.__contains__('chocolatey'):
                        continue
                    shutil.rmtree(file_path)
                    self.ScanInfo.append(str(tmp + ('%s folder deleted' % itemName)))
                    deleteFolderCount = deleteFolderCount + 1

            except Exception as e:
                self.ScanInfo.append(str(tmp + ('Access Denied: %s' % itemName)))
            # self.ScanInfo.append(str(tmp))

    def Clean(self):
        self.show()
        self.ScanInfo.setText("")

        folder = 'C:/Users/' + getpass.getuser() + '\AppData\Local\Temp'
        self.Task(folder)

        # 크롬 임시 파일
        folder = 'C:/Users/' + getpass.getuser() + '\AppData\Local\Google\Chrome\User Data\Default\Cache'
        self.Task(folder)

        # 인터넷 익스플로러 임시 파일
        folder = 'C:/Users/' + getpass.getuser() + '\AppData\Local\Microsoft\Windows\INetCache'
        self.Task(folder)

        # 엣지 임시 파일
        folder = 'C:/Users/' + getpass.getuser() + '\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\Temp'
        self.Task(folder)


        global deleteFileCount, deleteFolderCount
        result = (str(deleteFileCount) + ' files and ' + str(deleteFolderCount) + ' folders deleted.') + '\n'
        self.ScanInfo.append(str(result))


if __name__ == '__main__':
    a = QApplication(sys.argv)
    app = TempRemove()
    app.show()
    a.exec_()




