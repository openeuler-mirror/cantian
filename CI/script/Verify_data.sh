usage()
{
    echo "Usage:"
    echo "      need three parameter, file type ,file path(absolute path) and output path(absolute path)"
    echo "      file type -c (ctrl)"
    echo "      file type -f (data file)"
    echo "      file type -l (redo log)"
    echo "      For example: $0 -c /path/page_pool_root_dir/-ctrl1 /home/result"
}

# check user permissions
user=`whoami`
if [ $user != "gaussdba" ]
then
    echo "only gaussdba could use this tool"
    exit 1
fi

# check parameter
if [ $# -ne 3 ]
then
    usage
    exit 1
fi

file_type=$1
if [ $file_type != "-c" ] && [ $file_type != "-f" ] && [ $file_type != "-l" ]
then
    echo "invalid file type"
    usage
    exit 1
fi

file_path=$2
if [ ! -d $file_path ]
then
    echo "$file_path is invalid or not exit"
    exit 1
else
    var=`cd $file_path 2>&1`
    if [ "$?" -ne "0" ]
    then
        echo "$file_path is invalid or Permission denied"
        usage
        exit 1
    fi
fi

result_path=$3
if [ ! -d $result_path ]
then
    echo "$result_path is invalid or not exit"
    exit 1
else
    var=`cd $result_path 2>&1`
    if [ "$?" -ne "0" ]
    then
        echo "$result_path is invalid or Permission denied"
        exit 1
    fi

    cd $result_path
    var=`touch VERIFT_RESULT_PERMISSION.log 2>&1`
    if [ "$?" -ne "0" ]
    then
        echo "Permission denied, cannot create file in $result_path"
        exit 1
    fi
fi

# check if verification is in progress
before_verify_count=`ps -ef | grep "ctbox -T cminer $1.*-F -C -D" | grep -vE '(grep|defunct)' | wc -l`
if [ $before_verify_count -ne "0" ]
then
    echo "Verification is in progress. need wait until the verification is complete."
    exit 1
fi

# start verification
rm -rf $result_path/VERIFT_RESULT_*

cd $2
part_num=`ls -lR| grep "^d" | wc -l`

if [ $file_type == "-l" ]
then
    for i in *
    do
        if [ $i != "ulog_meta" ] && [ -s $i ]
        then
            echo "$2/$i START VERIFT" > $result_path/VERIFT_RESULT_$i.log 2>&1
            nohup ctbox -T cminer $file_type $i -F -C -D >> $result_path/VERIFT_RESULT_$i.log 2>&1 &
        fi
    done
else
    for i in *
    do
        var=`cd $2/$i 2>&1`
        if [ "$?" -ne "0" ]
        then
            echo "cannot cd $2/$i Permission denied"
            exit 1
        fi
        cd $2/$i
        if [ -s "./dataObj" ]
        then
            echo "$2/$i/dataObj START VERIFT" > $result_path/VERIFT_RESULT_$i.log 2>&1
            nohup ctbox -T cminer $1 dataObj -F -C -D -P $part_num -S $i >> $result_path/VERIFT_RESULT_$i.log 2>&1 &
        else
            echo -e "\n\t$2/$i/dataObj IS EMPTY"
        fi
    done
fi

# wait verification finish
while :
do
    verify_count=`ps -ef | grep "ctbox -T cminer $1.*-F -C -D" | grep -vE '(grep|defunct)' | wc -l`
    if [ $verify_count -eq "0" ]
    then
        break
    fi
    sleep 1
done

# output verification result
for i in $result_path/VERIFT_RESULT_*
do
    error_data_count="0"
    name=${i##*_}
    file_name=${name%%.*}
    grep -q "current file finished" $i
    if [ $? -ne "0" ]
    then
        if [ $file_type == "-l" ]
        then
            echo -e "\n\t$2/$file_name VERIFY FAILED, NEED RETRY"
        else
            echo -e "\n\t$2/$file_name/dataObj VERIFY FAILED, NEED RETRY"
        fi
        continue
    fi
    grep -q "ERROR REASON" $i
    if [ $? -eq "0" ]
    then
        error_data_count="1"
    fi
    if [ $error_data_count -eq "0" ]
    then
        if [ $file_type == "-l" ]
        then
            echo -e "\n\t$2/$file_name VERIFY SUCCESS, NO BAD BLOCKS"
        else
            echo -e "\n\t$2/$file_name/dataObj VERIFY SUCCESS, NO BAD BLOCKS"
        fi
    else
        if [ $file_type == "-l" ]
        then
            echo -e "\n\t$2/$file_name HAD BAD BLOCKS :"
        else
            echo -e "\n\t$2/$file_name/dataObj HAD BAD BLOCKS :"
        fi
    fi
    grep "ERROR REASON" $i
done

echo -e "\n\tsee more information in verification result path: $result_path"
exit 0