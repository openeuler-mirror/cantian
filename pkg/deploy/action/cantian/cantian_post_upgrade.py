# !/usr/bin/env python
# -*- coding: utf-8 -*-
from cantian_install import CanTian

if __name__ == "__main__":
    Func = CanTian()
    try:
        Func.post_check()
    except ValueError as err:
        exit(str(err))
    except Exception as err:
        exit(str(err))
    exit(0)