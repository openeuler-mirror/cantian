create database clustered cantian
    character set utf8
    controlfile('dbfiles1/ctrl1', 'dbfiles1/ctrl2', 'dbfiles1/ctrl3')
    system     tablespace      datafile 'dbfiles1/system' size 128M autoextend on next 32M
    nologging tablespace TEMPFILE 'dbfiles1/temp2_01' size 160M autoextend on next 32M, 'dbfiles1/temp2_02' size 160M autoextend on next 32M
    nologging undo tablespace TEMPFILE 'dbfiles1/temp2_undo' size 1G
    default    tablespace      datafile 'dbfiles1/user' size 1G autoextend on next 32M, 'dbfiles1/user1' size 1G autoextend on next 32M
    sysaux tablespace DATAFILE 'dbfiles1/sysaux' size 160M autoextend on next 32M
    instance
    node 0
    undo tablespace datafile 'dbfiles1/undo' size 1G autoextend on next 32M, 'dbfiles1/undo1' size 1G autoextend on next 32M
    temporary tablespace TEMPFILE 'dbfiles1/temp' size 160M autoextend on next 32M, 'dbfiles1/temp1' size 160M autoextend on next 32M
    nologging  undo tablespace TEMPFILE 'dbfiles1/temp2_undo_01'       size 128M autoextend on next 32M
    logfile ('dbfiles1/redo01.dat' size 256M, 'dbfiles1/redo02.dat' size 256M, 'dbfiles1/redo03.dat' size 256M);
