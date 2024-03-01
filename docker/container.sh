#!/bin/bash

commitID=""

function help()
{
    echo ""
    echo "$0"
    echo ""
    echo "Usage:    container.sh       {dev | rundev | enterdev | killdev | startnode {0, 1} | enternode {0, 1} | stopnode | help} [--cpus --memory --user --host]"
    echo "          dev                start container for single node and enter container"
    echo "          rundev             start container for single node"
    echo "          enterdev           enter container for single node"
    echo "          startnode node_id  start container for cluster"
    echo "          enternode node_id  enter container for cluster"
    echo "          stopnode           stop all containers for cluster"
    echo "          -c, --cpus=        number of CPUs for container"
    echo "          -m, --memory=      memory limit for container"
    echo "          -u, --user=        specify install username, default as cantiandba"
    echo "          -h, --host         use host network for container"
    echo "          -d, --coredir=     specify coredump dir"
}

function err()
{
    echo "error: $@"
    exit 1
}

function run_docker()
{
    init
    extra="$*"
    set -x
    docker run -dit --rm --privileged --shm-size 10240M    \
               --ulimit core=-1 --ulimit memlock=-1        \
               --volume /var/lib/docker:/var/lib/docker    \
               -v /root:/root --cap-add=ALL                \
               -v /etc/localtime:/etc/localtime            \
               --security-opt seccomp=unconfined           \
               ${docker_conf} --name ${container}          \
               ${mounts} --network=${network_name}         \
               ${extra} ${docker_name} /usr/sbin/init
    set +x
}

function create_network()
{
    if [[ ${network_name} == "host" ]]; then
        return
    fi
    
    set -x
    docker network rm ${network_name}
    docker network create -d bridge --subnet 192.168.86.111/16 ${network_name}
    set +x
}

function init_container()
{
    set -x
    docker exec -it ${container} /bin/bash ${regress_dir}/CantianKernel/docker/init_container.sh ${user} ${core_dir} ${commitID}
    set +x
}

function startnode()
{
    node_id=$1
    if [[ ${node_id} != 0 ]] && [[ ${node_id} != 1 ]] && [[ ${node_id} != 2 ]] && [[ ${node_id} != 3 ]]; then
        echo "Wrong node id ${node_id}"
        exit 1
    fi
    
    container="cantian_${mode}-node${node_id}"
    echo docker_name=$docker_name
    echo container=$container

    create_network
    if [[ $network_name == "host" ]]; then
        run_docker
    else
        ip="192.168.86.$((node_id+1))"
        echo ip=$ip
        run_docker --ip ${ip}
    fi
    echo "${container} is running"
    init_container
}

function enternode()
{
    node_id=$1
    if [[ ${node_id} != 0 ]] && [[ ${node_id} != 1 ]] && [[ ${node_id} != 2 ]] && [[ ${node_id} != 3 ]]; then
        echo "Wrong node id ${node_id}"
        exit 1
    fi
    container="cantian_${mode}-node${node_id}"
    
    set -x
    docker exec -it ${container} /bin/bash
    set +x
}

function stopnode()
{
    local i=0
    while ((i<=1))
    do
        container="${docker_name}-node${i}"
        if [[ $(docker ps | grep ${container}) ]]; then
            set -x
            docker kill ${container}
            set +x
        fi
        ((i++))
    done
    
    set -x
    docker network rm ${network_name}
    set +x
}

function rundev()
{
    network_name="host"
    container="${docker_name}-dev"
    script_dir=$(dirname "$(readlink -f "$0")")
    project_dir=$(dirname $script_dir)
    cd $(dirname $project_dir)/cantian-connector-mysql/
    commitID=($(git submodule status))
    cd -
    pwd
    run_docker
    echo "${container} is running"
    init_container
}

function enterdev()
{
    container="${docker_name}-dev"

    set -x
    docker exec -it ${container} /bin/bash
    set +x
}

function killdev()
{
    container="${docker_name}-dev"

    set -x
    docker kill ${container}
    set +x
}

function sync_mysql_code()
{
    mysql_dir=$1
    echo "sync_mysql_code mysql_dir:${mysql_dir}"
    cp -arf ${mysql_dir}/mysql-test ${mysql_dir}/mysql-source
    cp -arf ${mysql_dir}/storage ${mysql_dir}/mysql-source
    cp -arf ${mysql_dir}/mysql-test/*.patch ${mysql_dir}/mysql-source
}

function init()
{
    script_dir=$(dirname "$(readlink -f "$0")")
    local cantian_dir=$(dirname $script_dir)
    local project_dir=$(dirname $script_dir)/..
    data_dir="$(dirname $cantian_dir)/cantian_data/"
    if [[ ! -d ${data_dir} ]]; then
        echo "cantian_data folder not exists, try to create"
        mkdir ${data_dir}
    fi
    mysql_dir="$(dirname $cantian_dir)/cantian-connector-mysql/"
    mysql_source="${mysql_dir}/mysql-source/"
    regress_dir="/home/regress"
    sync_mysql_code ${mysql_dir}
    mounts="-v ${cantian_dir}:${regress_dir}/CantianKernel -v ${data_dir}:${regress_dir}/cantian_data -v ${mysql_dir}:${regress_dir}/cantian-connector-mysql \
	-v ${core_dir}:${core_dir}"

    echo "cantian_dir: ${cantian_dir}"
    echo "data_dir: ${data_dir}"
    echo "mysql_dir: ${mysql_dir}"
    echo "mysql_source: ${mysql_source}"
    echo "mounts: ${mounts}"
}

function parse_params()
{
    ARGS=$(getopt -o c:m:hu:d: --long cpus:,memory:,host,user:,coredir: -n "$0" -- "$@")
    
    if [ $? != 0 ]; then
        log "Terminating..."
        exit 1
    fi
    eval set -- "${ARGS}"

    cpus=""
    memory=""
    user="cantiandba"
    while true
    do
        case "$1" in
            -c | --cpus)
                cpus=$2
                shift 2
                ;;
            -m | --memory)
                memory=$2
                shift 2
                ;;
            -h | --host)
                network_name="host"
                shift
                ;;
            -u | --user)
                user=$2
                shift 2
                ;;
            -d | --coredir)
                core_dir=$2
                shift 2
                ;;
            --)
                shift
                break
                ;;
            *)
                echo "Interval error!"
                exit 1
                ;;
        esac
    done

    docker_conf=""
    if [[ ${cpus} != "" ]]; then
        docker_conf="${docker_conf} --cpus=${cpus}"
    fi
    if [[ ${memory} != "" ]]; then
        docker_conf="${docker_conf} --memory=${memory}"
    fi

    run_mode=$1
    node_id=$2
    if [[ "$3" != "" ]]; then
        echo "Too much start parameters!"
        exit 1
    fi
}

function main()
{
    mode=dev
    docker_name="cantian_${mode}"
    network_name="mynetwork"
    core_dir="/home/core"
    
    parse_params "$@"
    case $run_mode in
        dev)
            rundev
            enterdev
            exit 0
            ;;
        rundev)
            rundev
            exit 0
            ;;
        enterdev)
            enterdev
            exit 0
            ;;
        killdev)
            killdev
            exit 0
            ;;
        startnode)
            startnode $node_id
            exit 0
            ;;
        enternode)
            enternode $node_id
            exit 0
            ;;
        stopnode)
            stopnode
            exit 0
            ;;
        *)
            help
            exit 0
            ;;
    esac
}

main "$@"
