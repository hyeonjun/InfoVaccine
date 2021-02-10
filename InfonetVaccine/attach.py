# -*- coding:utf-8 -*-

# --------------------------------------------------------
# KavMain 클래스
# --------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path):  # 플러그인 엔진 초기화
        return 0  # 플러그인 엔진 초기화 성공

    # --------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # --------------------------------------------------------
    def uninit(self): # 플러그인 엔진 종료
        return 0

    # --------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다.
    # 리턴값 : 플러그인 엔진 정보
    # --------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        from InfonetVaccine import kernel
        info = dict()  # 사전형 변수 선언
        info['author'] = 'Hyeon Jun'  # 제작자
        info['version'] = '1.0'  # 버전
        info['title'] = 'Attach Engine'  # 엔진 설명
        info['kmd_name'] = 'attach'  # 엔진 파일 이름
        info['make_arc_type'] = kernel.MASTER_PACK # 악성코드 치료 후 재압축 유무

        return info


    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷 중에 첨부 파일 포맷이 있는가?
        if 'ff_attach' in fileformat:
            pos = fileformat['ff_attach']['Attached_Pos']
            file_scan_list.append(['arc_attach:%d' % pos, 'Attached'])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id.find('arc_attach:') != -1:
            pos = int(arc_engine_id[len('arc_attach:'):])

            try:
                with open(arc_name, 'rb') as fp:
                    fp.seek(pos)
                    data = fp.read()
            except IOError:
                return None
            return data
        return None