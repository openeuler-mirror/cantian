#!/usr/bin/env python  
#-*- coding: UTF-8 -*-

import os
import sys
import xml.dom

G_OUTPUT_DIR = "gtest_output"
G_OUTPUT_FILE = "gtest_report.xml"

G_TEST = 0
G_FAILURES = 0
G_DISABLED = 0
G_ERRORS = 0
G_TIME = 0
G_NAME = "AllTests"

if len(sys.argv) > 1 :
    G_OUTPUT_DIR = sys.argv[1]
    
if len(sys.argv) > 2 : 
    G_OUTPUT_FILE = sys.argv[2]

if not os.path.isdir(G_OUTPUT_DIR) :
    print("ERROR:%s not exist." % (G_OUTPUT_DIR)) 
    exit(1)

#逐个读取gtest_output目录的xml文件，最终汇总成一个文件
#需要考虑testsuites字段属性数字累加，其他字段直接拼接合并

impl = xml.dom.getDOMImplementation()
output_dom = impl.createDocument(None, None, None) 
output_root = output_dom.createElement("testsuites")

for FILE_IDX in os.listdir(G_OUTPUT_DIR) :
    print("analyse %s ......" % FILE_IDX)
    dom = xml.dom.minidom.parse("%s/%s" % (G_OUTPUT_DIR, FILE_IDX))
    root = dom.documentElement
    #L_TESTSUITES = root.getElementsByTagName("testsuites")[0]
    
    L_TEST = root.getAttribute('tests')
    G_TEST += int(L_TEST)
    
    L_FAILURES = root.getAttribute('failures')
    G_FAILURES += int(L_FAILURES)
    
    L_DISABLED = root.getAttribute('disabled')
    G_DISABLED += int(L_DISABLED)
    
    L_ERRORS = root.getAttribute('errors')
    G_ERRORS += int(L_ERRORS)
    
    L_TIME = root.getAttribute('time')
    G_TIME += float(L_TIME)
    
    L_TESTSUITE = root.getElementsByTagName("testsuite")
    for TESTSUITE_IDX in L_TESTSUITE :
        output_root.appendChild(TESTSUITE_IDX)
    
    print("    tests=%s, failures=%s, disabled=%s, errors=%s, time=%s" % (L_TEST, L_FAILURES, L_DISABLED, L_ERRORS, L_TIME))
    print("all tests=%d, failures=%d, disabled=%d, errors=%d, time=%0.3f" % (G_TEST, G_FAILURES, G_DISABLED, G_ERRORS, G_TIME))
    print()

#写入xml文件    
output_dom.appendChild(output_root)

output_root.setAttribute('tests', str(G_TEST))
output_root.setAttribute('failures', str(G_FAILURES))
output_root.setAttribute('disabled', str(G_DISABLED))
output_root.setAttribute('errors', str(G_ERRORS))
output_root.setAttribute('time', str(G_TIME))
output_root.setAttribute('name', str(G_NAME))

output_file = open(G_OUTPUT_FILE, mode = 'w')
output_dom.writexml(output_file, '', '    ', '\n', 'utf-8')
output_file.close()