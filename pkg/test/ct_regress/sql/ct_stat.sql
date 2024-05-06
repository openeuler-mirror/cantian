-- check system-auto tablespace, include 'SYSTEM','TEMP','UNDO','USERS','TEMP2','TEMP2_UNDO','SYSAUX'
-- if system-auto tablespaces changed, you must modify this UseCase and export-tool's function "exp_get_all_tbspace".
select count(*),'Can not be changed!!!!!!!!!!!!!!!' from dv_tablespaces;

-- start to stat
alter system set sql_stat = true;

drop table if exists t_stat_1;
create table t_stat_1(f1 int);
insert into t_stat_1 values(1);
select * from t_stat_1;
update t_stat_1 set f1=2;
commit;
select * from t_stat_1;
delete from t_stat_1;
insert into t_stat_1 values(2);
select * from t_stat_1;
rollback;
drop table t_stat_1;

-- end of stat
alter system set sql_stat = false;

select * from v$sysstat where NAME = 'CPU time' and VALUE < 0; -- 0 row

select count(*) from v$sgastat where value like '0x%';
select count(*) from v$sgastat where value like '0x0x%';

drop table if exists CUSTOMER_TEST0417;
CREATE TABLE CUSTOMER_TEST0417
(CUSTOMER_ID integer,
CUST_FIRST_NAME  VARCHAR(20) NOT NULL,
CUST_LAST_NAME   VARCHAR(20) NOT NULL,
CREDIT_LIMIT INTEGER);

insert into CUSTOMER_TEST0417 values (1, 'li', 'adjani', 100);
insert into CUSTOMER_TEST0417 values (2, 'li', 'alexander', 2000);
insert into CUSTOMER_TEST0417 values (3, 'li', 'altman', 5000);
commit;
call dbe_stats.collect_schema_stats('sys');
SELECT A.NUM_DISTINCT,A.LOW_VALUE,A.HIGH_VALUE,A.HISTOGRAM FROM SYS_COLUMNS A,SYS_TABLES b,SYS_USERS where A.TABLE#=b.ID AND b.NAME='CUSTOMER_TEST0417' and SYS_USERS.id=b.USER# and SYS_USERS.name='SYS' order by a.id;
select a.BUCKET_NUM,a.ROW_NUM,a.NULL_NUM,a.MINVALUE,a.MAXVALUE,a.DIST_NUM,a.DENSITY FROM SYS_HISTGRAM_ABSTR a,SYS_TABLES b,SYS_USERS where A.TAB#=b.ID AND b.NAME='CUSTOMER_TEST0417' and SYS_USERS.id=b.USER# and SYS_USERS.name='SYS' order by a.col#;
drop table if exists CUSTOMER_TEST0417;

drop table if exists test_vmstat;
create table test_vmstat (fd int, fd2 varchar(100));
CREATE or replace procedure vmstat_proc(startnum int, endall int) is
i INT :=1;
j varchar(20);
str varchar(100);
BEGIN
  FOR i IN startnum..endall LOOP
    select 'test' || i into j from dual;
    insert into test_vmstat values(i%10,j);
  END LOOP;
END;
/

call vmstat_proc(1,10000);
commit;
select LENGTH(GROUP_CONCAT(fd2)) from test_vmstat group by fd;
drop table test_vmstat purge;
drop procedure vmstat_proc;


drop table if exists CUSTOMER_TEST0417;
CREATE TABLE CUSTOMER_TEST0417
(CUSTOMER_ID integer,
CUST_FIRST_NAME  VARCHAR(20) NOT NULL,
CUST_LAST_NAME   VARCHAR(20) NOT NULL,
CREDIT_LIMIT INTEGER);

insert into CUSTOMER_TEST0417 values (1, 'li', 'adjani', 100);
insert into CUSTOMER_TEST0417 values (2, 'li', 'alexander', 2000);
insert into CUSTOMER_TEST0417 values (3, 'li', 'altman', 5000);
commit;


call dbe_stats.collect_schema_stats('sys'); 

SELECT A.NUM_DISTINCT,A.LOW_VALUE,A.HIGH_VALUE,A.HISTOGRAM 
FROM SYS_COLUMNS A,SYS_TABLES b,SYS_USERS 
where A.TABLE#=b.ID AND b.NAME='CUSTOMER_TEST0417' and SYS_USERS.id=b.USER# and SYS_USERS.name='SYS' 
order by a.id;

SELECT A.NUM_DISTINCT,A.LOW_VALUE,A.HIGH_VALUE,A.HISTOGRAM 
FROM SYS_COLUMNS A,SYS_TABLES b,SYS_USERS 
where A.TABLE#=b.ID AND b.NAME='CUSTOMER_TEST0417' and SYS_USERS.id=b.USER# and SYS_USERS.name='SYS' 
order by a.id;

drop table if exists CUSTOMER_TEST0417;
--DTS2019092413327
select if(VALUE>0,1,0) "judge" from v$sysstat where NAME='user logons current';
select if(VALUE<1000000,1,0) "judge" from v$sysstat where NAME='user logons current';
select 1 "judge"  from dual where((select VALUE from v$sysstat where NAME='user logons cumulation')>=(select VALUE from v$sysstat where NAME='user logons current'));
