create database clustered dbstor
    character set utf8
    controlfile('-ctrl1', '-ctrl2', '-ctrl3')
    system     tablespace      datafile '-sys.dat' size 5G autoextend on next 32M
    nologging tablespace TEMPFILE '-temp2_01' size 4G autoextend on next 32M
    nologging undo tablespace TEMPFILE '-temp2_undo' size 4G
    sysaux tablespace DATAFILE '-sysaux' size 1G autoextend on next 32M
    default    tablespace      datafile '-user1.dat' size 1G autoextend on next 32M
    instance
    node 0
    undo tablespace datafile '-undo01.dat' size 20G
    temporary tablespace TEMPFILE '-temp1_01' size 4G autoextend on next 32M
    nologging  undo tablespace TEMPFILE '-temp2_undo_01'       size 128M autoextend on next 32M
    logfile ('*redo01.dat' size 30G)
    node 1
    undo tablespace datafile '-undo11.dat' size 20G
    temporary tablespace TEMPFILE '-temp1_11' size 4G autoextend on next 32M
    nologging  undo tablespace TEMPFILE '-temp2_undo_11'       size 128M autoextend on next 32M
    logfile ('*redo11.dat' size 30G);
