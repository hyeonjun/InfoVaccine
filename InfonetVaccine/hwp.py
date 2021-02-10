# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import zlib


# -------------------------------------------------------------------------
# get_hwp_recoard(val)
# 입력된 4Byte 값을 HWP 레코드 구조에 맞게 변환하여 추출한다.
# 입력값 : val - DWORD
# 리턴값 : tag_id, level, size
# -------------------------------------------------------------------------
def get_hwp_recoard(val):
    b = 0b1111111111
    c = 0b111111111111

    tag_id = (val & b)
    level = ((val >> 10) & b)
    size = (val >> 20) & c

    return tag_id, level, size

# -------------------------------------------------------------------------
# scan_hwp_recoard(buf, lenbuf)
# 주어진 버퍼를 HWP 레코드 구조로 해석한다.
# 입력값 : buf - 버퍼
#         lenbuf - 버퍼 크기
# 리턴값 : True or False (HWP 레코드 추적 성공 여부) 및 문제의 tagid
# -------------------------------------------------------------------------
def scan_hwp_recoard(buf, lenbuf):
    from InfonetVaccine import kavutil
    pos = 0

    while pos < lenbuf:
        extra_size = 4
        val = kavutil.get_uint32(buf, pos)
        tagid, level, size = get_hwp_recoard(val)

        if size == 0xfff:
            extra_size = 8
            size = kavutil.get_uint32(buf, pos + 4)

        pos += (size + extra_size)

    if pos == lenbuf:
        return True

    return False




# -------------------------------------------------------------------------
# KavMain 클래스
# -------------------------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path):  # 플러그인 엔진 초기화
        self.handle = {}
        self.hwp_ole = re.compile('bindata/bin\d+\.ole$', re.IGNORECASE)

        s = r'n\x00e\x00w\x00(\x20\x00)+A\x00c\x00t\x00i\x00v\x00e\x00X\x00O\x00b\x00j\x00e\x00c\x00t\x00'
        self.hwp_js = re.compile(s, re.IGNORECASE)
        return 0  # 플러그인 엔진 초기화 성공

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
        from InfonetVaccine import kernel
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Hyeon Jun'  # 제작자
        info['version'] = '1.1'  # 버전
        info['title'] = 'HWP Engine'  # 엔진 설명
        info['kmd_name'] = 'hwp'  # 엔진 파일 이름
        info['make_arc_type'] = kernel.MASTER_DELETE # 악성코드 치료는 삭제
        info['sig_num'] = len(self.listvirus())  # 진단/치료 가능한 악성코드 수

        return info

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = list()  # 리스트형 변수 선언

        vlist.append('Exploit.HWP.Generic')  # 진단/치료하는 악성코드 이름 등록

        return vlist

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #          filename   - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        from InfonetVaccine import ole
        fileformat = {}  # 포맷 정보를 담을 공간
        ret = {}

        mm = filehandle

        if mm[:8] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':  # OLE 헤더와 동일
            o = None
            try:
                o = ole.OleFile(filename)
                pics = o.openstream('FileHeader')
                data = pics.read()
                if data[:0x11] == 'HWP Document File':
                    ret['ff_hwp'] = 'HWP'
            except ole.Error:
                pass

            if o:
                o.close()

        # HWP 파일 내부에 첨부된 OLE 파일인가?
        if self.hwp_ole.search(filename_ex):
            ret['ff_hwp_ole'] = 'HWP_OLE'

        return ret

    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat)
    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    #         fileformat  - 파일 포맷
    #         filename_ex - 파일 이름 (압축 내부 파일 이름)
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex):  # 악성코드 검사
        from InfonetVaccine import kernel
        mm = filehandle

        if filename_ex.lower().find('bodytext/section') >= 0:
            buf = mm[:]
            try:
                buf = zlib.decompress(buf, -15)
            except zlib.error:
                pass
            if scan_hwp_recoard(buf, len(buf)) is False: # 레코드 추적 실패 -> 악성코드!
                return True, 'Exploit.HWP.Generic', 0, kernel.SUSPECT

        # 악성코드를 발견하지 못했음을 리턴한다.
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