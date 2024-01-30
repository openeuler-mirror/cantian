#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
import sys
from cantian_install import CanTian

if __name__ == "__main__":
    Func = CanTian()
    Func.cantian_pre_install()
    sys.exit(0)
