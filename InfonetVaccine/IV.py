# -*- coding:utf-8 -*-
import datetime
import os
import sys
import types
import IVconst
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

import AllScan

import threading
from multiprocessing import Pool
import time



auto_setting = ""
infect_filePath = []

disinfect = None
delete = None
ignore = None



class InfonetV(QObject):
    started = pyqtSignal()
    finished = pyqtSignal()
    logSignal1 = pyqtSignal(str)
    logSignal2 = pyqtSignal(str)

    def __init__(self, path, set1, set2, parent = None):
        super(InfonetV, self).__init__(parent)

        self.path = path
        self.arc_scan = set1  # arc_file scan?
        self.auto_option = set2  # automatic treatment?
        global auto_setting
        auto_setting = self.auto_option

        self.g_scan_time = None

        self.count = 0

    def scan(self):
        threading.Thread(target=self.main).start()


    def define_options(self):
        global arc_option, auto_option
        options = []
        if self.arc_scan == 2:
            options.append(True)
        else:
            options.append(False)
        if self.auto_option == 2:
            options.append(True)
        else:
            options.append(False)
        options.append(False)

        return options

    # -----------------------------------------------------------
    # 악성코드 결과를 한 줄 에 출력하기 위한 함수
    # -----------------------------------------------------------
    def convert_display_filename(self, real_filename):
        # 출력용 이름
        fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
        if isinstance(real_filename, types.UnicodeType):
            display_filename = real_filename.encode(sys.stdout.encoding, 'replace')
        else:
            display_filename = unicode(real_filename, fsencoding).encode(sys.stdout.encoding, 'replace')

        if display_filename[0] == '/' or display_filename[0] == '\\':
            return display_filename[1:]
        else:
            return display_filename


    def display_line(self, filename, message):
        filename += ' '
        filename = self.convert_display_filename(filename)
        len_fname = len(filename)
        len_msg = len(message)

        if len_fname + 1 + len_msg < 74:
            fname = '%s' % filename
        else:
            able_size = 74 - len_msg
            able_size -= 5  # ...
            min_size = able_size / 2
            if able_size % 2 == 0:
                fname1 = filename[:min_size - 1]
            else:
                fname1 = filename[:min_size]
            fname2 = filename[len_fname - min_size:]
            fname = '%s ... %s' % (fname1, fname2)
        # print fname + ' ' + message
        # return fname + ' ' + message
        time.sleep(0.02)
        self.logSignal1.emit(str(fname+ " " +message))

    # -----------------------------------------------------------
    # scan의 콜백 함수
    # -----------------------------------------------------------
    def scan_callback(self, ret_value):
        fs = ret_value['file_struct']

        if len(fs.get_additional_filename()) != 0:
            disp_name = '%s (%s)' % (fs.get_master_filename(),
                                     fs.get_additional_filename())
        else:
            disp_name = '%s' % (fs.get_master_filename())

        if ret_value['result']:
            state = 'infected'

            vname = ret_value['virus_name']
            message = '%s : %s' % (state, vname)
        else:
            message = 'ok'
        self.display_line(disp_name, message)

        if self.auto_option == 0: # 자동 치료 취소
            while ret_value['result'] is True or ret_value['result'] is False:
                global disinfect, delete, ignore
                if disinfect == IVconst.K2_ACTION_DISINFECT:
                    return IVconst.K2_ACTION_DISINFECT
                elif delete == IVconst.K2_ACTION_DELETE:
                    return IVconst.K2_ACTION_DELETE
                elif ignore == IVconst.K2_ACTION_IGNORE:
                    return IVconst.K2_ACTION_IGNORE

        elif self.auto_option == 2: # 치료 옵션
            return IVconst.K2_ACTION_DISINFECT

        return IVconst.K2_ACTION_IGNORE

    # -----------------------------------------------------------
    # disinfect의 콜백 함수
    # -----------------------------------------------------------
    def disinfect_callback(self, ret_value, action_type):
        fs = ret_value['file_struct']
        message = ''

        if len(fs.get_additional_filename()) != 0:
            disp_name = '%s (%s)' % (fs.get_master_filename(),
                                     fs.get_additional_filename())
        else:
            disp_name = '%s' % (fs.get_master_filename())

        if fs.is_modify():  # 수정 성공?
            if action_type == IVconst.K2_ACTION_DISINFECT:
                message = 'disinfected'
            elif action_type == IVconst.K2_ACTION_DELETE:
                message = 'deleted'

        else:  # 수정 실패
            if action_type == IVconst.K2_ACTION_DISINFECT:
                message = 'disinfected failed'
            elif action_type == IVconst.K2_ACTION_DELETE:
                message = 'deleted failed'
        self.display_line(disp_name, message)

    # -----------------------------------------------------------
    # update의 콜백 함수
    # -----------------------------------------------------------
    def update_callback(self, ret_file_info):
        if ret_file_info.is_modify():  # 수정되었다면 결과 출력
            disp_name = ret_file_info.get_filename()

            message = 'updated'
            self.display_line(disp_name, message)


    # -----------------------------------------------------------
    # print_result(result)
    # 악성코드 검사 결과를 출력한다.
    # 입력값 : result - 악성코드 검사 결과
    # -----------------------------------------------------------
    def print_result(self, result):
        self.logSignal2.emit('Results:')
        self.logSignal2.emit('Folders               :%d' % result['Folders'])
        self.logSignal2.emit('Files                 :%d' % result['Files'])
        self.logSignal2.emit('Packed                :%d' % result['Packed'])
        self.logSignal2.emit('Infected files        :%d' % result['Infected_files'])
        self.logSignal2.emit('Identified viruses    :%d' % result['Identified_viruses'])
        if result['Disinfected_files']:
            self.logSignal2.emit('Disinfected files      :%d' % result['Disinfected_files'])
        elif result['Deleted_files']:
            self.logSignal2.emit('Deleted files     :%d' % result['Deleted_files'])
        self.logSignal2.emit('I/O errors            :%d' % result['IO_errors'])

        # 검사 시간 출력
        t = str(self.g_scan_time).split(':')
        t_h = int(float(t[0]))
        t_m = int(float(t[1]))
        t_s = int(float(t[2]))
        self.logSignal2.emit('Scan time         :%02d:%02d:%02d\n' % (t_h, t_m, t_s))




    # --------------------------------------------------------------------------------
    # main()
    # --------------------------------------------------------------------------------
    def main(self):
        self.started.emit()
        import IVengine
        IV = IVengine.Engine()
        iv_pwd = os.path.abspath(os.path.split(sys.argv[0])[0])  # 프로그램이 실행중인 폴더
        plugins_path = os.path.join(iv_pwd + os.sep + 'InfonetVaccine')

        if not IV.set_plugins(plugins_path):  # 플러그인 엔진 경로 설정
            return 0

        InfoV = IV.create_instance()  # 백신 엔진 인스턴스 생성
        if not InfoV:
            return 0

        options = self.define_options()
        InfoV.set_options(options)

        if not InfoV.init():  # 전체 플러그인 엔진 초기화
            return 0

        if self.path:
            InfoV.set_result()  # 악성코드 검사 결과 초기화

            # 검사 시작 시간 체크
            start_time = datetime.datetime.now()

            # 검사용 path (다중 경로 지원을 위해)
            if isinstance(self.path, str):
                path = os.path.abspath(self.path)
                if os.path.exists(path):  # 폴더 혹은 파일이 존재하는가?
                    InfoV.scan(path, self.scan_callback, self.disinfect_callback, self.update_callback)
                else:
                    print 'error'
            else:
                for scan_path in self.path:
                    if isinstance(scan_path, unicode):
                        scan_path = scan_path.encode("utf-8")
                    scan_path = os.path.abspath(scan_path)
                    if os.path.exists(scan_path):  # 폴더 혹은 파일이 존재하는가?
                        InfoV.scan(scan_path, self.scan_callback, self.disinfect_callback, self.update_callback)
                    else:
                        print 'error'
            # 검사 종료 시간 체크
            end_time = datetime.datetime.now()

            self.g_scan_time = end_time - start_time

            # 검사 결과 출력
            ret = InfoV.get_result()
            self.print_result(ret)

        self.finished.emit()

        InfoV.uninit()

class ScanForm(QMainWindow, AllScan.Ui_AllScanWindow):
    def __init__(self, parent=None):
        super(QMainWindow, self).__init__(parent)
        global auto_setting
        set2 = auto_setting

        self.initUI(self)

        self.disinfect = ""
        self.delete = ""
        self.ignore = ""

        self.form(set2)

    def form(self, state):
        if state == 2:
            self.close_btn = QPushButton("close", self)  # 버튼
            self.close_btn.resize(279, 38)  # 종료 버튼
            self.close_btn.move(186, 810)
            self.close_btn.setStyleSheet("QPushButton {"
                                         "background: #FFFFFF; color: #0046FF;"
                                         "font-size: 13px; font-weight: bold; border: 1px solid;"
                                         "border-color: #0046FF; border-radius: 3px }"
                                         "QPushButton:pressed {"
                                         "background: #0046FF; color: #FFFFFF; font-size: 13px;"
                                         "border: 0; border-radius: 3px }")
            self.close_btn.clicked.connect(lambda state, btn=self.close_btn: self.btn_clicked(state, btn))
        elif state == 0:
            self.disinfect_btn = QPushButton("disinfect", self)  # 버튼
            self.delete_btn = QPushButton("delete", self)  # 버튼
            self.ignore_btn = QPushButton("ignore", self)  # 버튼
            self.quit_btn = QPushButton("quit", self)  # 버튼

            self.disinfect_btn.resize(136, 38)  # 치료 버튼
            self.disinfect_btn.move(40, 810)
            self.disinfect_btn.setStyleSheet("QPushButton {"
                                         "background: #FFFFFF; color: #0046FF;"
                                         "font-size: 13px; font-weight: bold; border: 1px solid;"
                                         "border-color: #0046FF; border-radius: 3px }"
                                         "QPushButton:pressed {"
                                         "background: #0046FF; color: #FFFFFF; font-size: 13px;"
                                         "border: 0; border-radius: 3px }")

            self.delete_btn.resize(136, 38)  # 삭제 버튼
            self.delete_btn.move(186, 810)
            self.delete_btn.setStyleSheet("QPushButton {"
                                          "background: #FFFFFF; color: #0046FF;"
                                          "font-size: 13px; font-weight: bold; border: 1px solid;"
                                          "border-color: #0046FF; border-radius: 3px }"
                                          "QPushButton:pressed {"
                                          "background: #0046FF; color: #FFFFFF; font-size: 13px;"
                                          "border: 0; border-radius: 3px }")

            self.ignore_btn.resize(136, 38)  # 무시 버튼
            self.ignore_btn.move(331, 810)
            self.ignore_btn.setStyleSheet("QPushButton {"
                                         "background: #FFFFFF; color: #0046FF;"
                                         "font-size: 13px; font-weight: bold; border: 1px solid;"
                                         "border-color: #0046FF; border-radius: 3px }"
                                         "QPushButton:pressed {"
                                         "background: #0046FF; color: #FFFFFF; font-size: 13px;"
                                         "border: 0; border-radius: 3px }")


            self.quit_btn.resize(136, 38)  # 종료 버튼
            self.quit_btn.move(475, 810)
            self.quit_btn.setStyleSheet("QPushButton {"
                                         "background: #FFFFFF; color: #0046FF;"
                                         "font-size: 13px; font-weight: bold; border: 1px solid;"
                                         "border-color: #0046FF; border-radius: 3px }"
                                         "QPushButton:pressed {"
                                         "background: #0046FF; color: #FFFFFF; font-size: 13px;"
                                         "border: 0; border-radius: 3px }")


            global disinfect, delete, ignore

            disinfect = self.disinfect_btn.clicked.connect(lambda state, btn=self.disinfect_btn: self.btn_clicked(state, btn))
            delete = self.delete_btn.clicked.connect(lambda state, btn=self.delete_btn : self.btn_clicked(state, btn))
            ignore = self.ignore_btn.clicked.connect(lambda state, btn=self.ignore_btn : self.btn_clicked(state, btn))
            self.quit_btn.clicked.connect(lambda state, btn=self.quit_btn : self.btn_clicked(state, btn))

    def btn_clicked(self, state, btn):
        btn_text = btn.text()
        if btn_text == "disinfect":
            global disinfect
            disinfect = IVconst.K2_ACTION_DISINFECT
        elif btn_text == "delete":
            global delete
            delete = IVconst.K2_ACTION_DELETE
        elif btn_text == "ignore":
            global ignore
            ignore = IVconst.K2_ACTION_IGNORE
        elif btn_text == "quit":
            msg = QMessageBox()
            msg.setWindowTitle("Error")
            msg.setWindowIcon(QIcon(".\image\Icon.jpg"))
            msg.setText("<span style='font-size: 11pt; color: #444444'>"
                        "<b>확인 버튼을 누르시면 3초 후 종료됩니다.</span>")
            msg.addButton(QPushButton("확인"), QMessageBox.RejectRole)
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
            time.sleep(3)
            self.hide()
        elif btn_text == "close":
            self.hide()


if __name__ == '__main__':
    a = QApplication(sys.argv)
    window = ScanForm()
    app = InfonetV()
    app.started.connect(window.show)
    app.logSignal1.connect(window.ScanInfo.append)
    app.logSignal2.connect(window.ResultInfo.append)
    app.scan()
    sys.exit(a.exec_())