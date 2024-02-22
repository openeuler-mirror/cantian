create database clustered cantian
    character set utf8
    controlfile('dbfiles1/ctrl1', 'dbfiles1/ctrl2', 'dbfiles1/ctrl3')
    system     tablespace      datafile 'dbfiles1/sys.dat' size 128M autoextend on next 32M
    nologging tablespace TEMPFILE 'dbfiles1/temp2_01' size 160M autoextend on next 32M, 'dbfiles1/temp2_02' size 160M autoextend on next 32M
    nologging undo tablespace TEMPFILE 'dbfiles1/temp2_undo' size 1G
    default    tablespace      datafile 'dbfiles1/user1.dat' size 1G autoextend on next 32M, 'dbfiles1/user2.dat' size 1G autoextend on next 32M
    sysaux tablespace DATAFILE 'dbfiles1/sysaux' size 200M autoextend on next 32M
    instance
    node 0
    undo tablespace datafile 'dbfiles1/undo01.dat' size 1G autoextend on next 32M, 'dbfiles1/undo02.dat' size 1G autoextend on next 32M
    temporary tablespace TEMPFILE 'dbfiles1/temp1_01' size 160M autoextend on next 32M, 'dbfiles1/temp1_02' size 160M autoextend on next 32M
    nologging  undo tablespace TEMPFILE 'dbfiles1/temp2_undo_01'       size 128M autoextend on next 32M
    logfile ('dbfiles2/redo01.dat' size 4G, 'dbfiles2/redo02.dat' size 4G, 'dbfiles2/redo03.dat' size 4G,
             'dbfiles2/redo04.dat' size 4G, 'dbfiles2/redo05.dat' size 4G, 'dbfiles2/redo06.dat' size 4G)
    node 1
    undo tablespace datafile 'dbfiles1/undo11.dat' size 1G autoextend on next 32M, 'dbfiles1/undo12.dat' size 1G autoextend on next 32M
    temporary tablespace TEMPFILE 'dbfiles1/temp1_11' size 160M autoextend on next 32M, 'dbfiles1/temp1_12' size 160M autoextend on next 32M
    nologging  undo tablespace TEMPFILE 'dbfiles1/temp2_undo_11'       size 128M autoextend on next 32M
    logfile ('dbfiles3/redo07.dat' size 4G, 'dbfiles3/redo08.dat' size 4G, 'dbfiles3/redo09.dat' size 4G,
             'dbfiles3/redo0a.dat' size 4G, 'dbfiles3/redo11.dat' size 4G, 'dbfiles3/redo12.dat' size 4G);
