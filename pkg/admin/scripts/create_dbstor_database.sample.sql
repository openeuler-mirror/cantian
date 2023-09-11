create database clustered dbstor
    character set utf8
    controlfile('-ctrl1', '-ctrl2', '-ctrl3')
    system     tablespace      datafile '-sys.dat'          size 128M autoextend on next 32M
    nologging  tablespace      TEMPFILE '-temp2_01'         size 160M autoextend on next 32M
    nologging  undo tablespace TEMPFILE '-temp2_undo'       size 1G
    default    tablespace      datafile '-user1.dat'        size 1G autoextend on next 32M
    sysaux tablespace DATAFILE '-sysaux' size 256M autoextend on next 32M
    instance
    node 0
    undo tablespace datafile '-undo01.dat' size 1G autoextend on next 32M
    temporary tablespace TEMPFILE '-temp1_01' size 160M autoextend on next 32M
    nologging  undo tablespace TEMPFILE '-temp2_undo_01'       size 128M autoextend on next 32M
    logfile ('*redo01.dat' size 256M);
