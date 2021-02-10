# -*- coding:utf-8 -*-

import os
import sys
import shutil
import getpass
import Optimization

import threading

from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtWidgets import QApplication, QMainWindow


class CleanWorker(QObject):
    started = pyqtSignal()
    finished = pyqtSignal()
    logSignal = pyqtSignal(str)

    def __init__(self, parent=None):
        super(CleanWorker, self).__init__(parent)

        self.delete_file_count = 0
        self.delete_folder_count = 0

    def clean(self):
        threading.Thread(target=self._execute).start()

    def _execute(self):
        self.delete_file_count = 0
        self.delete_folder_count = 0
        self.started.emit()

        folders = (
            os.path.join("C:/Users", getpass.getuser(), "AppData/Local/Temp"),
            os.path.join(
                "C:/Users/",  # Chrome
                getpass.getuser(),
                r"AppData/Local/Google/Chrome/User Data/Default/Cache",
            ),
            os.path.join(
                "C:/Users/",  # Internet Explorer
                getpass.getuser(),
                r"AppData/Local/Microsoft/Windows/INetCache",
            ),
            os.path.join(
                "C:/Users/",  # Edge
                getpass.getuser(),
                r"AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/Temp",
            ),
        )

        for folder in folders:
            if os.path.isdir(folder):
                self.task(folder)

        self.logSignal.emit(
            "%d files and %d folders deleted.\n"
            % (self.delete_file_count, self.delete_folder_count)
        )

        self.finished.emit()

    def task(self, folder):
        for file in os.listdir(folder):
            file_path = os.path.join(folder, file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    self.logSignal.emit("%s file deleted" % file)
                    self.delete_file_count += 1
                elif os.path.isdir(file_path):
                    if "chocolatey" in file_path:
                        continue
                    shutil.rmtree(file_path)
                    self.logSignal.emit("%s folder deleted" % file)
                    self.delete_folder_count += 1
            except Exception as e:
                self.logSignal.emit("Access Denied: %s" % file)


class TempRemove(QMainWindow, Optimization.Ui_OptimalWindow):
    def __init__(self, parent=None):
        super(QMainWindow, self).__init__(parent)
        self.initUI(self)


if __name__ == "__main__":
    a = QApplication(sys.argv)

    w = TempRemove()
    o = CleanWorker()
    o.started.connect(w.show)
    o.logSignal.connect(w.ScanInfo.append)
    o.clean()

    sys.exit(a.exec_())