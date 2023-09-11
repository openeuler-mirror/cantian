#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CANTIAN databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
from cantian_install import CanTian
from exception import NormalException

if __name__ == "__main__":
    Func = CanTian()
    try:
        Func.cantian_start()
    except ValueError as err:
        exit(str(err))
    except Exception as err:
        exit(str(err))
    exit(0)