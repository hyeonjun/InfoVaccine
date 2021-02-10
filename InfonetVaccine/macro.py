# -*- coding:utf-8 -*-
import hashlib
import os
import re
from InfonetVaccine import kavutil





# -------------------------------------------------------------------------
# KavMain 클래스
# -------------------------------------------------------------------------
from InfonetVaccine import kernel


class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 입력값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path): # 플러그인 엔진 초기화
        self.p_vba = re.compile(r'^\s*Attribute\s+VB_Name.+|^\s*Attribute\s+.+VB_Invoke_Func.+|\s+_\r?\n', re.IGNORECASE | re.MULTILINE)
        self.p_vba_cmt = re.compile(r'(\'|\bREM\b).*', re.IGNORECASE)
        self.p_space = re.compile(r'\s')

        # 변종 바이러스 패턴
        laroux_strings = [
            'auto_open()',
            'application.onsheetactivate',
            'activeworkbook.modules.count',
            'c4$=curdir()',
            'workbooks(n4$).sheets'
        ]

        self.aho_laroux = kavutil.AhoCorasick()
        self.aho_laroux.make_tree(laroux_strings)

        return 0 # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        pmd5 = kavutil.PatternMD5('.')
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Hyeon Jun'  # 제작자
        info['version'] = '1.0'  # 버전
        info['title'] = 'Macro Engine'  # 엔진 설명
        info['kmd_name'] = 'macro'  # 엔진 파일 이름
        info['sig_num'] = pmd5.get_sig_num('macro')+1  # 진단/치료 가능한 악성코드 수

        return info

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        pmd5 = kavutil.PatternMD5('.')
        vlist = pmd5.get_sig_vlist('macro')
        vlist.append('Virus.MSExcel.Laroux.Gen')
        vlist.sort()
        return vlist

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #         filename - 파일 이름
    #         filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        fileformat = {} # 포맷 정보를 담을 공간
        ret = {}

        mm = filehandle

        if mm[:17] == 'Attribute VB_Name': # 매크로 소스와 동일
            ret['ff_macro'] = 'MACRO'

        return ret

    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat)
    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    #         fileformat  - 파일 포맷
    #         filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex): # 악성코드 검사
        pmd5 = kavutil.PatternMD5('.')
        try:
            mm = filehandle

            # 미리 분석된 파일 포맷 중에 Macro 포맷이 있는가?
            if 'ff_macro' in fileformat:
                buf = mm[:]

                buf = self.p_vba_cmt.sub('', buf) # 주석문 제거
                buf = self.p_vba.sub('', buf) # 불필요한 정보 제거
                buf = self.p_space.sub('', buf) # 공백 제거
                buf = buf.lower() # 영어 소문자로 통일

                # fmd5 = crytolib.md5(buf)
                fsize = len(buf)
                if pmd5.match_size('macro', fsize):
                    fmd5 = hashlib.md5(buf).hexdigest() # MD5 해시 구하기
                    vname = pmd5.scan('macro', fsize, fmd5)
                    if vname:
                        return True, vname, 0, kernel.INFECTED
                    else:
                        vstring = []
                        ret = self.aho_laroux.search(buf)
                        for n in ret:
                            vstring.append(n[1])
                        if len(set(vstring)) == 5:
                            return True, 'Virus.MSExcel.Laroux.Gen', 0, kernel.SUSPECT
        except IOError:
            pass

        # 악성코드 발견하지 못했음
        return False, '', -1, kernel.NOT_FOUND

    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id)
    # 악성코드를 치료한다.
    # 입력값 : filename    - 파일 이름
    #        : malware_id - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    # ---------------------------------------------------------------------
    def disinfect(self, filename, malware_id):  # 악성코드 치료
        try:
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if malware_id == 0:
                os.remove(filename)  # 파일 삭제
                return True  # 치료 완료 리턴
        except IOError:
            pass

        return False  # 치료 실패 리턴