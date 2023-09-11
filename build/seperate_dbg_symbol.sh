#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

function help()
{
    echo ""
    echo $1
    echo ""
    echo "Usage: $0 bin_file"
    echo ""
    echo "          bin_file    --  gcc compile bin file."
    echo ""
}

function seperate_dbg_symbol()
{
   local tmp_bin_file=${1}
   local tmp_bin_dbgfile=${tmp_bin_file}.symbol
   
   if [ "" == "${tmp_bin_file}" ] || [ ! -e "${tmp_bin_file}" ] ;
   then
        echo -e '\E[32m'"\033[1mBinary file(${tmp_bin_file}) not exist\033[0m"
        return 1
   fi

   objcopy --only-keep-debug ${tmp_bin_file} ${tmp_bin_dbgfile}
   objcopy --strip-all ${tmp_bin_file}
   objcopy --add-gnu-debuglink=${tmp_bin_dbgfile} ${tmp_bin_file}
 
   printf '\E[33m'"\033[1mSeperate debug symbol from ${tmp_bin_file} to ${tmp_bin_dbgfile} ..... \033[0m"
 
   if [ -e "${tmp_bin_dbgfile}" ]; 
   then
       echo -e '\E[32m'"\033[1mOK\033[0m" 
   else
       echo -e '\E[31m'"\033[1mFAIL\033[0m"
       return 1
   fi 
   return 0 
}

if [ $# != 1 ]; then
    help "Error : Argu must be 1!"
    exit 1
fi

if [ ! -f "$1" ]; then
    help "File $1 not Found!"
    exit 1
elif [ -L "$1" ];then
	help "$1 is a link, do not separate symbol!"
	exit 1
elif [[ "$1" = *".py" ]];then
	help "$1 is a script, do not separate symbol!"
	exit 1
elif [[ "$1" = *".dat" ]];then
	help "$1 is a license file, do not separate symbol!"
	exit 1	
elif [[ "$1" = *".sh" ]];then
	help "$1 is a shell file, do not separate symbol"
	exit 1
else
	seperate_dbg_symbol $1
	echo ""
fi	