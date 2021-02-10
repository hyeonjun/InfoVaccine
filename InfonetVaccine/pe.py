# -*- coding:utf-8 -*-

# --------------------------------------------------------
# pe_parse(mm)
# PE 파일을 파싱하여 주요 정보를 리턴한다.
# 입력값 : mm - 파일 핸들
# 리턴값 : {PE 파일 분석 정보} or None
# --------------------------------------------------------
def pe_parse(mm):
    from InfonetVaccine import kavutil
    pe_format = {'PE_Position': 0, 'EntryPoint': 0, 'SectionNumber': 0,
                 'Sections': None, 'EntryPointRaw': 0, 'FileAlignment': 0}
    try:
        if mm[0:2] != 'MZ': # MZ로 시작하나?
            raise ValueError

        # PE 시그너처 위치 알아내기
        pe_pos = kavutil.get_uint32(mm, 0x3C)

        # PE 인가?
        if mm[pe_pos:pe_pos+4] != 'PE\x00\x00':
            raise ValueError

        pe_format['PE_Position'] = pe_pos

        # Optional Header의 Magic ID?
        if mm[pe_pos + 0x18:pe_pos + 0x18 + 2] != '\x0B\x01':
            raise ValueError

        # Entry Point 구하기
        pe_ep = kavutil.get_uint32(mm, pe_pos + 0x28)
        pe_format['EntryPoint'] = pe_ep

        # Image Base 구하기
        pe_img = kavutil.get_uint32(mm, pe_pos + 0x34)
        pe_format['ImageBase'] = pe_img

        # File Alignment 구하기
        pe_file_align = kavutil.get_uint32(mm, pe_pos + 0x3C)
        pe_format['FileAlignment'] = pe_file_align

        # Section 개수 구하기
        section_num = kavutil.get_uint16(mm, pe_pos + 0x6)
        pe_format['SectionNumber'] = section_num

        # Optional Header 크기 구하기
        opthdr_size = kavutil.get_uint16(mm, pe_pos + 0x14)
        pe_format['OptionalHeaderSize'] = opthdr_size

        # t 섹션 시작 위치
        section_pos = pe_pos + 0x18 + opthdr_size

        # 모든 섹션 정보 추출
        sections = [] # 모든 섹션 정보 담을 리스트

        for i in range(section_num):
            section = {}

            s = section_pos + (0x28 * i)

            section['Name'] = mm[s:s + 8].replace('\x00', '')
            section['VirtualSize'] = kavutil.get_uint32(mm, s+8)
            section['RVA'] = kavutil.get_uint32(mm, s+12)
            section['SizeRawData'] = kavutil.get_uint32(mm, s+16)
            section['PointerRawData'] = kavutil.get_uint32(mm, s+20)
            section['Characteristics'] = kavutil.get_uint32(mm, s+36)

            sections.append(section)

        pe_format['Sections'] = sections

        # 파일에서의 EntryPoint 위치 구하기
        for section in sections:
            size = section['VirtualSize']
            rva = section['RVA']

            if rva <= pe_ep < rva + size:
                foff = (section['PointerRawData'] / pe_file_align) * pe_file_align
                ep_raw = pe_ep - rva + foff

                pe_format['EntryPointRaw'] = ep_raw # EP의 Raw 위치
                pe_format['EntryPoint_in_Section'] = sections.index(section)
                                                        # EP가 포함된 섹션
                break
    except ValueError:
        return None

    return pe_format

# --------------------------------------------------------
# KavMain 클래스
# --------------------------------------------------------
class KavMain:
    # -------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화한다.
    # 입력값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # -------------------------------------------------------
    def init(self, plugins_path): # 플러그인 엔진 초기화
        return 0 # 플러그인 엔진 초기화 성공

    # -------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # -------------------------------------------------------
    def uninit(self): # 플러그인 엔진 종료
        return 0 # 플러그인 엔진 종료 성공

    # -------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다.
    # 리턴값 : 플러그인 엔진 정보
    # -------------------------------------------------------
    def getinfo(self): # 플러그인 엔진의 주요 정보
        from InfonetVaccine import kernel
        info = dict() # 사전형 변수 선언

        info['author'] = 'Hyeon Jun' # 제작자
        info['version'] = '1.0' # 버전
        info['title'] = 'PE Engine' # 엔진 설명
        info['kmd_name'] = 'pe' # 엔진 파일 이름
        # 리소스 파일에 악성코드가 존재하는 경우로 최상위 파일을 삭제한다.
        info['make_arc_type'] = kernel.MASTER_DELETE  # 악성코드 치료 후 재압축 유무
        return info

    # -------------------------------------------------------
    # format(self, filehandle, filename)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #         filename - 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # -------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        fileformat = {} # 포맷 정보를 담을 공간
        ret = {}

        pe_format = pe_parse(filehandle) # PE 파일 분석
        if pe_format is None:
            return None

        fileformat['pe'] = pe_format
        ret = {'ff_pe' : fileformat}

        # PE 파일 뒤쪽에 추가 정보가 있는지 검사한다.
        pe_size = 0

        pe_file_align = pe_format['FileAlignment']

        for sec in pe_format['Sections']:
            off = (sec['PointerRawData'] / pe_file_align) * pe_file_align
            size = sec['SizeRawData']
            if pe_size < off + size:
                pe_size = off + size

        file_size = len(filehandle)

        if pe_size < file_size:
            fformat = {} # 포맷 정보를 담을 공간
            fileformat = {'Attached_Pos' : pe_size}
            ret['ff_attach'] = fileformat

        return ret