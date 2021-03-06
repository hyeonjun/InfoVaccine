# -*- coding:utf-8 -*-

import os
import re
import struct
import glob
import marshal
import time

# -------------------------------------------------------------------------
# 메시지 출력 함수
# -------------------------------------------------------------------------
import zlib

def vprint(header, section=None, msg=None):
    if header:
        print '[*] %s' % header

    if section:
        if len(msg) > 50:
            new_msg = msg[:22] + ' ... ' + msg[-22:]
        else:
            new_msg = msg
        print '    [-] %-20s: %s' % (section, new_msg)

# -------------------------------------------------------------------------
# 악성코드 패턴 인스턴스
# -------------------------------------------------------------------------
handle_pattern_md5 = None  # 악성코드 패턴 핸들 (MD5 해시)

# -------------------------------------------------------------------------
# 정규표현식 컴파일
# -------------------------------------------------------------------------
# Text로 정의된 문자
p_text = re.compile(r'[\w\s!"#$%&\'()*+,\-./:;<=>?@\[\\\]\^_`{\|}~]')
p_md5_pattern_ext = re.compile(r'\.s(\d\d)$', re.IGNORECASE)

# ----------------------------------------------------------------------
# PatternMD5
# ----------------------------------------------------------------------
class PatternMD5:
    # ------------------------------------------------------------------
    # __init__(self, plugins_path)
    # 악성코드 패턴을 초기화한다.
    # 입력값 : plugins_path - 악성코드 패턴의 위치
    # ------------------------------------------------------------------
    def __init__(self, plugins_path):
        self.sig_sizes = {}
        self.sig_p1s = {}
        self.sig_p2s = {}
        self.sig_names = {}
        self.sig_times = {}  # 메모리 관리를 위해 시간 정보를 가짐
        self.plugins = plugins_path + os.sep + 'mdb'

        # 각 악성코드별 시그너처의 개수 : 예) adware:1개, emalware:39개
        # 이는 향후 (size % 개수) + 1을 해서 size가 어느 그룹에 존재하는지를 확인하게 됨
        self.sig_group_count = {}

        fl = glob.glob1(plugins_path, '*.s??')
        fl.sort()
        for name in fl:
            obj = p_md5_pattern_ext.search(name)
            if obj:
                idx = obj.groups()[0]  # ex:01
                sig_key = os.path.split(name)[1].lower().split('.')[0]
                sp = self.__load_sig(name)
                if sp is None:
                    continue

                if len(sp):  # 로딩된 패턴이 1개 이상이면...
                    # 그룹 개수 추가
                    self.sig_group_count[sig_key] = self.sig_group_count.get(sig_key, 0) + 1

                    # 악성코드 패턴 크기를 담는다.
                    if sig_key in self.sig_sizes:
                        self.sig_sizes[sig_key].update(dict.fromkeys(sp))
                    else:
                        self.sig_sizes[sig_key] = dict.fromkeys(sp)

    # ------------------------------------------------------------------
    # match_size(self,sig_key,sig_size)
    # 지정한 악성코드 패턴의 해당 크기가 존재하는지 확인한다.
    # 입력값 : sig_key - 지정한 악성코드 패턴
    #         sig_size - 크기
    # 리턴값 : 악성코드 패턴 내부에 해당 크기가 존재하는지 여부(True or False)
    # ------------------------------------------------------------------
    def match_size(self, sig_key, sig_size):
        sig_key = sig_key.lower()  # 대문자로 입력될 가능성 때문에 모두 소문자로 변환

        if sig_key in self.sig_sizes:  # sig_key가 로딩되어 있나?
            if sig_size in self.sig_sizes[sig_key]:
                return True

        return False

    # ------------------------------------------------------------------
    # scan(self, sig_key, sig_size, sig_md5)
    # 악성코드 패턴을 검사한다.
    # 입력값 : sig_key - 지정한 악성코드 패턴
    #         sig_size - 크기
    #         sig_md5 - MD5
    # 리턴값 : 발견한 악성코드 이름
    # ------------------------------------------------------------------
    def scan(self, sig_key, sig_size, sig_md5):
        sig_key = sig_key.lower()  # 대문자로 입력될 가능성 때문에 모두 소문자로 변환
        if self.match_size(sig_key, sig_size):  # 크기 존재?
            # idxs = self.sig_sizes[sig_key][sig_size]  # 어떤 파일에 1차 패턴이 존재하는지 확인
            idxs = ['%02d' % ((sig_size % self.sig_group_count[sig_key]) + 1)]

            fmd5 = sig_md5.decode('hex')
            sig_p1 = fmd5[:6]  # 1차 패턴
            sig_p2 = fmd5[6:]  # 2차 패턴

            for idx in idxs:
                # 1차 패턴 비교 진행
                # 1차 패턴이 로딩되어 있지 않다면...
                if self.__load_sig_ex(self.sig_p1s, 'i', sig_key, idx) is False:
                    continue

                if sig_p1 in self.sig_p1s[sig_key][idx]:  # 1차 패턴 발견
                    p2_offs = self.sig_p1s[sig_key][idx][sig_p1]

                    # 2차 패턴 비교 진행
                    # 2차 패턴이 로딩되어 있지 않다면...
                    if self.__load_sig_ex(self.sig_p2s, 'c', sig_key, idx) is False:
                        continue

                    for off in p2_offs:
                        offs = self.sig_p2s[sig_key][idx][off]
                        sig2 = offs[0] # 2차 패턴
                        name_off = offs[1] # 악성코드 이름 오프셋

                        if sig2 == sig_p2:  # 2차 발견
                            # 이름 패턴이 로딩되어 있지 않다면..
                            if self.__load_sig_ex(self.sig_names, 'n', sig_key, idx) is False:
                                continue

                            return self.sig_names[sig_key][idx][name_off]  # 악성코드 이름 리턴
        self.__save_mem()  # 메모리 용량을 낮추기 위해 사용
        return None

    # ------------------------------------------------------------------
    # __load_sig(self, fname)
    # 악성코드 패턴을 로딩한다.
    # 입력값 : fname - 악성코드 패턴 파일 이름
    # 리턴값 : 악성코드 패턴 자료구조
    # ------------------------------------------------------------------
    def __load_sig(self, fname):
        try:
            data = open(fname, 'rb').read()
            if data[0:4] == 'KAVS': # 헤더를 체크
                sp = marshal.loads(zlib.decompress(data[12:])) # 헤더 정보를 제외하고 데이터 읽음
                return sp
        except IOError:
            return None

    # ------------------------------------------------------------------
    # __load_sig_ex(self, sig_dict, sig_prefix, sig_key, idx
    # 악성코드 패턴을 로딩한다.
    # 단, 어떤 자료구조에 로딩되는지의 여부도 결정할 수 있다.
    # 입력값 : sig_dict - 악성코드 패턴이 로딩될 자료 구조
    #         sig_prefix - 악성코드 패턴 이름 중 확장자 prefix
    #         sig_key - 악성코드 패턴 이름 중 파일 이름
    #         idx - 악성코드 패턴 이름 중 확장자 번호
    # 리턴값 : 악성코드 패턴 로딩 성공 여부
    # ------------------------------------------------------------------
    def __load_sig_ex(self, sig_dict, sig_prefix, sig_key, idx):
        if not (sig_key in sig_dict):
            sig_dict[sig_key] = {}

        if not (idx in sig_dict[sig_key]):
            # 패턴 로딩
            try:
                name_fname = os.path.join(self.plugins, '%s.%s%s' % (sig_key, sig_prefix, idx))
                sp = self.__load_sig(name_fname)
                if sp is None:
                    return False
            except IOError:
                return False

            sig_dict[sig_key][idx] = sp

        # 현재 시간을 sig_time에 기록한다.
        if not (sig_key in self.sig_times):
            self.sig_times[sig_key] = {}

        if not (sig_prefix in self.sig_times[sig_key]):
            self.sig_times[sig_key][sig_prefix] = {}

        self.sig_times[sig_key][sig_prefix][idx] = time.time()

        return True

    # ------------------------------------------------------------------
    # __save_mem(self)
    # 오랫동안 사용하지 않은 악성코드 패턴을 메모리에서 삭제한다.
    # ------------------------------------------------------------------
    def __save_mem(self):
        # 정리해야 할 패턴 (3분 이상 사용되지 않은 패턴)
        n = time.time()
        for sig_key in self.sig_times.keys():
            for sig_prefix in self.sig_times[sig_key].keys():
                for idx in self.sig_times[sig_key][sig_prefix].keys():
                    if n - self.sig_times[sig_key][sig_prefix][idx] > 3 * 60:
                        if sig_prefix == 'i':  # 1차 패턴
                            self.sig_p1s[sig_key].pop(idx)
                        elif sig_prefix == 'c':  # 2차 패턴
                            self.sig_p2s[sig_key].pop(idx)
                        elif sig_prefix == 'n':  # 악성코드 이름 패턴
                            self.sig_names[sig_key].pop(idx)

                        self.sig_times[sig_key][sig_prefix].pop(idx)  # 시간

    # ------------------------------------------------------------------
    # get_sig_num(self, sig_key)
    # 주어진 sig_key에 해당하는 악성코드 패턴의 누적된 수를 알려준다.
    # 입력값 : sig_key - 악성코드 패턴 이름 (ex:script)
    # 리턴값 : 악성코드 패턴 수
    # ------------------------------------------------------------------
    def get_sig_num(self, sig_key):
        sig_num = 0
        fl = glob.glob1(self.plugins, '%s.c??' % sig_key)

        for fname in fl:
            fname = os.path.join(self.plugins, fname)
            try:
                buf = open(fname, 'rb').read(12)
                if buf[0:4] == 'KAVS':
                    sig_num += get_uint32(buf, 4)
            except IOError:
                return None
        return sig_num

    # ---------------------------------------------------------------------
    # get_sig_vlist(self, sig_key)
    # 주어진 sig_key에 해당하는 악성코드 패턴의 악성코드 이름를 알려준다.
    # 입력값 : sig_key - 악성코드 패턴 이름 (ex:script)
    # 리턴값 : 악성코드 이름
    # ---------------------------------------------------------------------
    def get_sig_vlist(self, sig_key):
        sig_vname = []
        fl = glob.glob1(self.plugins, '%s.n??' % sig_key)

        for fname in fl:
            fname = os.path.join(self.plugins, fname)
            try:
                sig_vname += self.__load_sig(fname)
            except IOError:
                return None

        return sig_vname

# -------------------------------------------------------------------------
# AhoCorasick 클래스
# 원본 : https://gist.github.com/atdt/875e0dba6a15e3fa6018
# -------------------------------------------------------------------------
FAIL = -1


class AhoCorasick:
    def __init__(self):
        self.transitions = {}
        self.outputs = {}
        self.fails = {}

    def make_tree(self, keywords):
        new_state = 0

        for keyword in keywords:
            state = 0

            for j, char in enumerate(keyword):
                res = self.transitions.get((state, char), FAIL)
                if res == FAIL:
                    break
                state = res

            for char in keyword[j:]:
                new_state += 1
                self.transitions[(state, char)] = new_state
                state = new_state

            self.outputs[state] = [keyword]

        queue = []
        for (from_state, char), to_state in self.transitions.items():
            if from_state == 0 and to_state != 0:
                queue.append(to_state)
                self.fails[to_state] = 0

        while queue:
            r = queue.pop(0)
            for (from_state, char), to_state in self.transitions.items():
                if from_state == r:
                    queue.append(to_state)
                    state = self.fails[from_state]

                    while True:
                        res = self.transitions.get((state, char), state and FAIL)
                        if res != FAIL:
                            break
                        state = self.fails[state]

                    failure = self.transitions.get((state, char), state and FAIL)
                    self.fails[to_state] = failure
                    self.outputs.setdefault(to_state, []).extend(
                        self.outputs.get(failure, []))

    def search(self, string):
        state = 0
        results = []
        for i, char in enumerate(string):
            while True:
                res = self.transitions.get((state, char), state and FAIL)
                if res != FAIL:
                    state = res
                    break
                state = self.fails[state]

            for match in self.outputs.get(state, ()):
                pos = i - len(match) + 1
                results.append((pos, match))

        return results

# -------------------------------------------------------------------------
# 함수명 : HexDump
# 설  명 : 주어진 파일에서 지정된 영역에 대해 Hex 덤프를 보여준다.
# 인자값 : fname : 파일명
#         start : 덤프할 영역의 시작 위치
#         size  : 덤프할 크기
#         width : 한줄에 보여줄 문자의 개수
# -------------------------------------------------------------------------
class HexDump:
    def File(self, fname, start, size=0x200, width=16):
        fp = open(fname, "rb")
        fp.seek(start)
        row = start % width  # 열
        col = (start / width) * width  # 행
        r_size = 0
        line_start = row
        while True:
            if (r_size + (width - line_start) < size):
                r_char = (width - line_start)  # 읽어야할 문자 수
                r_size += (width - line_start)
            else:
                r_char = size - r_size
                r_size = size

            # print line_start, r_char
            line = fp.read(r_char)
            if len(line) == 0:
                break
            # 주소 값
            output = "%08X : " % col
            # Hex 값
            output += line_start * "   " \
                      + "".join("%02x " % ord(c) for c in line)
            output += "  " \
                      + (width - (line_start + r_char)) * "   "
            # 문자 값
            output += line_start * " "
            output += "".join(['.', c][self.IsPrint(c)] for c in line)
            print output
            col += width
            line_start = 0
            if r_size == size:
                break
        fp.close()

    # -------------------------------------------------------------------------
    # 함수명 : Buffer
    # 설  명 : 주어진 버퍼에 대해 Hex 덤프를 보여준다.
    # 인자값 : fbuf   : 버퍼
    #         start : 덤프할 영역의 시작 위치
    #         size  : 덤프할 크기
    #         width : 한줄에 보여줄 문자의 개수
    # -------------------------------------------------------------------------
    def Buffer(self, buf, start, size=0x200, width=16):
        # 주어진 크기보다 크면 버퍼가 작다면 인자값을 조정
        if len(buf) < size:
            size = len(buf)
        row = start % width  # 열
        col = (start / width)  # 행
        # [row ... width*col]
        # [width*col ... width * (col+1)]
        r_size = 0
        line_start = row + (col * width)
        # print hex(line_start), hex(width*(col+1))
        # print hex(row), hex(col)
        while True:
            line = buf[line_start:width * (col + 1)]

            if len(line) == 0:
                break
            if ((r_size + len(line)) < size):
                pass
            else:
                # print hex(line_start), hex(line_start + (size - r_size))
                line = line[0:(size - r_size)]
                r_size = size - len(line)
            # 주소 값
            output = "%08X : " % ((line_start / width) * width)
            # Hex 값
            output += row * "   " \
                      + "".join("%02x " % ord(c) for c in line)
            output += "  " \
                      + (width - (row + len(line))) * "   "
            # 문자 값
            output += row * " "
            output += "".join(['.', c][self.IsPrint(c)] for c in line)
            print output
            line_start = width * (col + 1)
            col += 1
            row = 0
            r_size += len(line)
            if r_size == size:
                break

    # -------------------------------------------------------------------------
    # 함수명 : IsPrint
    # 설  명 : 주어진 문자가 출력 가능한 문자인지를 확인한다.
    # 인자값 : char  : 문자
    # 반환값 : True  : 출력 가능한 문자
    #          False : 출력 할 수 없는 문자
    # -------------------------------------------------------------------------
    def IsPrint(self, char):
        c = ord(char)
        if c >= 0x20 and c < 0x80:
            return True
        else:
            return False




# --------------------------------------------------------------------
# get_uint16(buf, off):
# 주어진 버퍼의 오프셋을 기준으로 uint16로 값을 읽어들인다.
# 입력값 : buf - 버퍼
#         off - 오프셋
# 리턴값 : uint16 변환 값
# --------------------------------------------------------------------
def get_uint16(buf, off):
    return struct.unpack('<H', buf[off:off+2])[0]

# --------------------------------------------------------------------
# get_uint32(buf, off):
# 주어진 버퍼의 오프셋을 기준으로 uint32로 값을 읽어들인다.
# 입력값 : buf - 버퍼
#         off - 오프셋
# 리턴값 : uint32 변환값
# --------------------------------------------------------------------
def get_uint32(buf, off):
    return struct.unpack('<L', buf[off:off+4])[0]

# --------------------------------------------------------------------
# get_uint64(buf, off):
# 주어진 버퍼의 오프셋을 기준으로 uint64로 값을 읽어들인다.
# 입력값 : buf - 버퍼
#         off - 오프셋
# 리턴값 : uint64 변환값
# --------------------------------------------------------------------
def get_uint64(buf, off):
    return struct.unpack('<Q', buf[off:off+8])[0]
    # Length of File Size의 값이 0x80일 때 압축된 파일의 크기와
    # 압축되지 않은 파일의 크기가 8Byte가 된다. 이를 처리하기 위한 함수

# -------------------------------------------------------------------------
# normal_vname(vname):
# 주어진 악성코드 이름의 특수 문자를 처리한다.
# 입력값 : vname - 악성코드 이름
#         platform - Win32, MSIL 등
# 리턴값 : 새로운 악성코드 이름
# -------------------------------------------------------------------------
def normal_vname(vname, platform=None):
    # vname = vname.replace('<n>', 'not-a-virus:')
    vname = vname.replace('<n>', '')

    if platform:
        vname = vname.replace('<p>', platform)

    return vname

# --------------------------------------------------------------------
# is_textfile(buf)
# 주어진 버퍼가 Text인지 아닌지를 판단한다.
# 입력값 : buf - 버퍼
# 리턴값 : Text 유무 (True, False)
# --------------------------------------------------------------------
def is_textfile(buf) :
    n_buf = len(buf)

    n_text = len(p_text.findall(buf)) # buf에서 패턴을 모두 찾기

    if n_text / float(n_buf) > 0.8: # 해당 글자가 차지하는 비율이 80% 이상인가?
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
        # 악성코드 패턴 초기화
        global handle_pattern_md5

        handle_pattern_md5 = PatternMD5(plugins_path)

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
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Hyeon Jun'  # 제작자
        info['version'] = '1.0'  # 버전
        info['title'] = 'InfonetVaccine Utility Library'  # 엔진 설명
        info['kmd_name'] = 'kavutil'  # 엔진 파일 이름

        return info


