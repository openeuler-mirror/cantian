create database clustered db_name
    character set utf8
    controlfile('ctrl1', 'ctrl2', 'ctrl3')
    system     tablespace      datafile 'sys.dat' size 256M autoextend on next 32M
    nologging tablespace TEMPFILE 'temp2_01' size 256M autoextend on next 32M, 'temp2_02' size 256M autoextend on next 32M
    nologging undo tablespace TEMPFILE 'temp2_undo' size 256M
    default    tablespace      datafile 'user1.dat' size 256M autoextend on next 32M, 'user2.dat' size 256M autoextend on next 32M
    sysaux tablespace DATAFILE 'sysaux' size 256M autoextend on next 32M
    instance
    node 0
    undo tablespace datafile 'undo01.dat' size 256M autoextend on next 32M, 'undo02.dat' size 256M autoextend on next 32M
    temporary tablespace TEMPFILE 'temp1_01' size 256M autoextend on next 32M, 'temp1_02' size 256M autoextend on next 32M
    nologging  undo tablespace TEMPFILE 'temp2_undo_01'       size 128M autoextend on next 32M
    logfile ('redo01.dat' size 256M, 'redo02.dat' size 256M, 'redo03.dat' size 256M)
    node 1
    undo tablespace datafile 'undo11.dat' size 256M autoextend on next 32M, 'undo12.dat' size 256M autoextend on next 32M
    temporary tablespace TEMPFILE 'temp1_11' size 256M autoextend on next 32M, 'temp1_12' size 256M autoextend on next 32M
    nologging  undo tablespace TEMPFILE 'temp2_undo_11'       size 128M autoextend on next 32M
    logfile ('redo11.dat' size 256M, 'redo12.dat' size 256M, 'redo13.dat' size 256M);
