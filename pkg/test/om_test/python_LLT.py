import os
import sys
import unittest
import coverage
import warnings

cur_path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(cur_path))
src_path = os.path.join(cur_path, '..', '..', 'deploy', 'action')
sys.path.append(src_path)
cov = coverage.coverage(branch=True,
                        source=[src_path],
                        omit=["__init__.py", "test_*", "*config.py", "*log.py", "*constant.py"])

warnings.filterwarnings("ignore", category=SyntaxWarning)


def main():
    # 开始收集覆盖率数据
    cov.start()
    suite = unittest.TestLoader().discover(cur_path, pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    # 停止收集覆盖率数据
    cov.stop()
    # 保存覆盖率数据
    cov.save()
    cov.report()
    cov.xml_report(outfile=os.path.join(cur_path, 'coverage.xml'))
    return result.wasSuccessful()


if __name__ == '__main__':
    ret = main()
    sys.exit(0 if ret else 1)
