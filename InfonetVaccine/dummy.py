# -*- coding:utf-8 -*-

import os


class KavMain :
    # ------------------------------------
    # 플러그인 엔진을 초기화한다.
    # 인자값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ------------------------------------
    def init(self, plugins_path): # 플러그인 엔진 초기화
        # 진단/치료하는 악성코드 이름
        self.visus_name = 'Dummy-Test-FIle (not a virus)'
        # 악성코드 패턴 등록
        self.dummy_pattern = 'exampleTestFile-INFONET-Anti-Virus-Project,2020,04,04'

        return 0 # 플러그인 엔진 초기화 성공

    # ------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ------------------------------------
    def uninit(self) : # 플러그인 엔진 종료
        del self.visus_name # 메모리 해제 (악성코드 이름 관련)
        del self.dummy_pattern # 메모리 해제 (악성코드 패턴)

        return 0 # 플러그인 엔진 종료 성공

    # ------------------------------------
    # scan(self, filehandle, filename)
    # 악성코드를 검사한다.
    # 인자값 : filehandle - 파일 핸들
    #         filename - 파일 이름
    #         filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    def scan(self, filehandle, filename, fileformat, filename_ex) :
        try :
            # 파일을 열어 악성코드 패턴만큼 파일에서 읽는다.
            fp = open(filename, 'rb')
            buf = fp.read(len(self.dummy_pattern)) # 패턴은 49 byte 크기
            fp.close()

            # 악성코드 패턴을 비교한다
            if buf == self.dummy_pattern :
                # 악성코드 패턴이 같다면 결과 값을 리턴한다.
                return True, self.visus_name, 0, 1
        except IOError :
            pass

        # 악성코드를 발견하지 못했음을 리턴한다.
        return False, '', -1, 0

    # ------------------------------------------
    # difinfect(self, filename, malware_id)
    # 악성코드를 치료한다.
    # 인자값 : filename - 파일 이름
    #       : malware_id - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    # -------------------------------------------
    def disinfect(self, filename, malware_id): # 악성코드 치료
        try:
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if malware_id == 0:
                os.remove(filename) # 파일 삭제
                return True # 치료 완료 리턴
        except IOError:
            pass

        return False # 치료 실패 리턴

    # -----------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 목록을 알려준다.
    # 리턴값 : 악성코드 목록
    # -----------------------------------------
    def listvirus(self): # 진단 가능한 악성코드 목록
        vlist = list() # 리스트형 변수 선언
        vlist.append(self.visus_name) # 진단/치료하는 악성코드 이름 등록

        return vlist

    # -----------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # -----------------------------------------
    def getinfo(self): # 플러그인 엔진의 주요 정보
        info = dict() # 사전형 변수 선언

        info['author'] = 'Hyeon Jun' # 제작자
        info['version'] = '1.1' # 버전
        info['title'] = 'Dummy Scan Engine' # 엔진 설명
        info['kmd_name'] = 'dummy' # 엔진 파일 이름
        info['sig_num'] = 1 # 진단/치료 가능한 악성코드 수

        return info