# -*- coding:utf-8 -*-

import os
import sys
import IVkmdfile
import IVrsa


if __name__ == '__main__' :
    # ------------------------------
    # 인자값을 체크한다.
    # ------------------------------
    if len(sys.argv) != 2 :
        print('Usage : kmake.py [python source]')
        exit()

    IVkmdfile.make(sys.argv[1], True)

