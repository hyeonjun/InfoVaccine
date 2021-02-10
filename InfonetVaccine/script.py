# -*- coding:utf-8 -*-

import hashlib
import os
import re

# --------------------------------------------------------
# KavMain 클래스
# --------------------------------------------------------

class KavMain:
    # --------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화한다.
    # 입력값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # --------------------------------------------------------
    def init(self, plugins_path): # 플러그인 엔진 초기화
        # 파일 시작이 <script, <ifname인지 확인하는 정규표현식
        self.p_script_head = re.compile(r'\s*<\s*(script|iframe)', re.IGNORECASE)

        # script/iframe 정보가 html 내부에 있는지 확인하는 정규표현식
        s = r'<\s*(script|iframe).*?>([\d\D]*?)<\s*/(script|iframe)\s*>'
        self.p_script_in_html = re.compile(s, re.IGNORECASE)

        # 주석문 및 공백 제거를 위한 정규표현식
        self.p_http = re.compile(r'https?://')
        self.p_script_cmt1 = re.compile(r'//.*|/\*[\d\D]*?\*/')
        self.p_script_cmt2 = re.compile(r'(#|\bREM\b).*', re.IGNORECASE)
        self.p_space = re.compile(r'\s')

        return 0

    # --------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # --------------------------------------------------------
    def uninit(self): # 플러그인 엔진 종료
        return 0

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        from InfonetVaccine import kavutil
        pmd5 = kavutil.PatternMD5('.')
        vlist = pmd5.get_sig_vlist('script')
        vlist.sort()
        return vlist

    # --------------------------------------------------------
    # format(slef, filehandle, filename)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #         filename - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # --------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        from InfonetVaccine import kavutil
        fileforamt = {} # 포맷 정보를 담을 공간

        mm = filehandle
        buf = mm[:4096]


        if kavutil.is_textfile(buf): # Text 파일인가?
            obj = self.p_script_head.match(buf) # 스크립트 태그가 존재하나?
            if obj:
                # 내부 스크립트가 존재하나?
                obj_script = self.p_script_in_html.search(mm[:])

                if obj_script:
                    buf_strip = obj_script.groups()[1].strip() # 내부 스크립트 추출
                    n_buf_strip = len(buf_strip)
                    fileforamt['size'] = n_buf_strip

                    if n_buf_strip: # 내부 스크립트
                        if obj_script.groups()[0].lower() == 'script':
                            ret = {'ff_script' : fileforamt}
                        else :
                            ret = {'ff_iframe' : fileforamt}
                    else : # 외부 스크립트
                        if obj_script.groups()[0].lower() == 'script':
                            ret = {'ff_script_external' : fileforamt}
                        else :
                            ret = {'ff_iframe_external' : fileforamt}
                else :
                    # 스크립트 태그만 발견
                    # 내부 스크립트를 발견하지 못했다면 외부 스크립트일 가능성이 크다.
                    fileforamt['size'] = 0 # 외부 스크립트

                    if obj.group().lower().find('script') != -1:
                        ret = {'ff_script_external' : fileforamt}
                    else :
                        ret = {'ff_iframe_external' : fileforamt}
                return ret
        return None

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 ff_script 포맷이 있는가?
        if 'ff_script' in fileformat:
            # TODO : VBScript에 대한 처리 필요함
            file_scan_list.append(['arc_script', 'JavaScript'])
        elif 'ff_iframe' in fileformat:
            file_scan_list.append(['arc_iframe', 'IFrame'])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_script' or arc_engine_id == 'arc_iframe':
            buf = ''

            try:
                with open(arc_name, 'rb') as fp:
                    buf = fp.read()
            except IOError:
                return None

            obj = self.p_script_in_html.search(buf) # 내부 스크립트인가?
            if obj:
                data = obj.groups()[1] # 스크립트 추출
                return data

        return None

    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat)
    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    #         fileformat  - 파일 포맷
    #         filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex):  # 악성코드 검사
        from InfonetVaccine import kavutil, kernel
        pmd5 = kavutil.PatternMD5('.')
        try:
            mm = filehandle

            if not ('ff_html' in fileformat or
                    'ff_script' in fileformat or
                    'ff_iframe' in fileformat or
                    'ff_script_external' in fileformat or
                    'ff_iframe_external' in fileformat):
                raise ValueError  # 해당 포맷이 포함되을때만 script 엔진 검사

            if kavutil.is_textfile(mm[:4096]):
                buf = mm[:]

                buf = self.p_http.sub('', buf)  # http:// 제거
                buf = self.p_script_cmt1.sub('', buf) # 주석문 제거
                buf = self.p_script_cmt2.sub('', buf) # 주석문 제거
                buf = self.p_space.sub('', buf)  # 공백 제거
                buf = buf.lower()  # 영어 소문자로 통일

                # script 패턴에 해당 크기가 존재하는가?
                size = len(buf)
                if pmd5.match_size('script', size):  # script 패턴에 해당 크기가 존재하는가?
                    fmd5 = hashlib.md5(buf).hexdigest()  # MD5 해시 구하기
                    # script 패턴에서 MD5 해시 검사
                    vname = pmd5.scan('script', size, fmd5)  # script 패턴에서 MD5 해시 검사
                    if vname:  # 악성코드 이름이 존재한다면 악성코드 발견
                        return True, vname, 0, kernel.INFECTED
        except IOError:
            pass
        except ValueError:
            pass

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

    # --------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다.
    # 리턴값 : 플러그인 엔진 정보
    # --------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        from InfonetVaccine import kavutil
        pmd5 = kavutil.PatternMD5('.')
        info = dict()  # 사전형 변수 선언
        info['author'] = 'Hyeon Jun'  # 제작자
        info['version'] = '1.0'  # 버전
        info['title'] = 'Script Engine'  # 엔진 설명
        info['kmd_name'] = 'script'  # 엔진 파일 이름
        info['sig_num'] = pmd5.get_sig_num('script')

        return info