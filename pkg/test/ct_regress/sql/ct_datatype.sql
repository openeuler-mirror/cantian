--DTS2019042509188,this sql syntax is not supported by mysql or oracle,so the case is here..
select 1 from (select convert(extract(year from systimestamp),int)); 
select 1 from (select convert(extract(year from systimestamp),uint));

--DTS2019041811982
select CHR(65::uint) from dual;
select CHAR(65::uint) from dual;
select CAST(45::uint as int) from dual;
select CONVERT(65::uint,int) from dual;

--DTS2019041009255
drop table if exists t_timestamp_table;
create table t_timestamp_table(
c_id int,
c_bool bool, c_boolean boolean, c_bigint bigint,
c_real real, 
c_date number default timestampdiff(SQL_TSI_FRAC_SECOND,'7898-03-10 12:01:23.000001','7898-03-10 12:01:23.000000'),
c_datetime datetime ,
c_timestamp number
) ;
insert into t_timestamp_table(c_id) values(1);
select * from t_timestamp_table;
drop table if exists t_timestamp_table;
create table t_timestamp_table(
c_id int,
c_bool bool, c_boolean boolean, c_bigint bigint,
c_real real, 
c_date date default timestampadd(month, 1,'7898-03-10 12:01:23.000000'),
c_datetime datetime ,
c_timestamp number
) ;
insert into t_timestamp_table(c_id) values(1);
select * from t_timestamp_table;
drop table if exists t_timestamp_table;

--TEST datatype
select 100 + 483645 from dual;
select 100 + 2147483645 from dual;
select 100 + 9223372036854775103 from dual;
select 100 + 9223372036854775803 from dual;
select '9223371000000000000.000'::number::bigint from dual;
select '9223371000000000000.500'::number::bigint from dual;
select '9223371000000000000.005'::number::bigint from dual;

--date
drop table if exists test_temp_t1;
create table test_temp_t1(f1 date, f2 datetime, f3 timestamp);
insert into test_temp_t1(f1,f2,f3) values(sysdate, sysdate, sysdate);
insert into test_temp_t1(f1,f2,f3) values(sysdate, curdate, systimestamp);
insert into test_temp_t1(f1,f2,f3) values(sysdate, current_date, current_timestamp);
commit;
select to_char(to_date('20171216165511','yyyymmddhh24miss'),'yyyy-mm-dd hh24:mi:ss') from dual;
SELECT TO_TIMESTAMP('08-JAN-2018 11:17:18','DD-MON-YYYY HH:MI:SS') FROM DUAL;
SELECT TO_TIMESTAMP('08-JAN-2018 11:17:18','DD-MON-YYYY HH12:MI:SS') FROM DUAL;
SELECT TO_TIMESTAMP('08-JAN-2018 12:17:18','DD-MON-YYYY HH12:MI:SS') FROM DUAL;
SELECT TO_TIMESTAMP('08-JAN-2018 00:17:18','DD-MON-YYYY HH12:MI:SS') FROM DUAL;
SELECT TO_TIMESTAMP('08-JAN-2018 01:17:18','DD-MON-YYYY HH12:MI:SS') FROM DUAL;
SELECT TO_TIMESTAMP('08-JAN-2018 23:17:18','DD-MON-YYYY HH12:MI:SS') FROM DUAL;
UPDATE test_temp_t1 SET f2 = 2.2;
-- compare with string
select count(*) from test_temp_t1 where f1='2012-12-12 12:12:12' and f3='2012-12-12 12:12:12';
drop table test_temp_t1;

--integer
drop table if exists test_temp_t1;
create table test_temp_t1(f1 bool, f2 int, f3 integer, f4 bigint, f5 serial primary key, f6 varchar(5), f7 date);
select * from test_temp_t1;
insert into test_temp_t1 values(null, null, NULL, NULL, null,null, null);
select * from test_temp_t1;
insert into test_temp_t1 values(1, 2, 3, 4, 5, null, null);
select f1+f2+f3+f4+f5 from test_temp_t1;
insert into test_temp_t1 values(1, 2147483647, -2147483648, null, null, null,null);
select * from test_temp_t1 where f2 > 'A';
insert into test_temp_t1 values(0, 2, NULL, 9223372036854775807, -9223372036854775808, null, null);
insert into test_temp_t1 values(0, 2, NULL, 9223372036854775808, -9223372036854775809, null, null);
insert into test_temp_t1 values(0, 2147483648, NULL, NULL, NULL, null, null);
insert into test_temp_t1 values(0, -2147483649, NULL, NULL, NULL, null, null);
insert into test_temp_t1 values(0, null, NULL, 9223372036854775808, NULL, null, null);
insert into test_temp_t1 values(0, null, NULL, -9223372036854775809, NULL, null, null);
insert INTO test_temp_t1(f4) VALUES(-7777777 * -19223372036854775809);
select * from test_temp_t1;

insert INTO test_temp_t1(f7) values(sysdate);
UPDATE test_temp_t1 SET f7 = 0 WHERE f2 < 4.444;
UPDATE test_temp_t1 SET f3 = 666666 WHERE f7 = -2.2;
UPDATE test_temp_t1 SET f1 = 1 WHERE f2 > 'exzpbt';

drop table test_temp_t1;


drop table if exists test_temp_t1;
create table test_temp_t1(f1 double, f2 float, f3 real);
insert into test_temp_t1 values(null, null, NULL);
insert into test_temp_t1 values(1, 0.001, 123.456);      
select * from test_temp_t1;
drop table test_temp_t1;

--test in ct_decimal.sql  number/number same as decimal
drop table if exists test_temp_t1;
create table test_temp_t1(f1 decimal(20,5));
insert into test_temp_t1(f1) values(12345678.0123456789);
insert into test_temp_t1(f1) values(1.111);
insert into test_temp_t1(f1) values(1.12345);
insert into test_temp_t1(f1) values(1.123456);
insert into test_temp_t1(f1) values(12345.12345);
insert into test_temp_t1(f1) values(123456.12345);
insert into test_temp_t1(f1) values(1234567.12345);
insert into test_temp_t1(f1) values(12345678.123);
insert into test_temp_t1(f1) values(12345678.1234);
insert into test_temp_t1(f1) values(12345678.12345);
insert into test_temp_t1(f1) values(12345678.123456);
insert into test_temp_t1(f1) values(12345678.1234567);
insert into test_temp_t1(f1) values(12345678.12345678);
insert into test_temp_t1(f1) values(12345678.1234567891);
insert into test_temp_t1(f1) values(12345678.12345678912);
insert into test_temp_t1(f1) values(12345678.0123456789);
select to_char(f1) from test_temp_t1;
drop table test_temp_t1;

--test in ct_decimal.sql  number/number same as decimal
drop table if exists test_temp_t1;
create table test_temp_t1(f1 decimal(38,20), f2 numeric, f3 decimal);
insert into test_temp_t1(f1, f2, f3) values(12345678.0123456789, 12345678.0123456789, 12345678.0123456789);
insert into test_temp_t1(f1, f2, f3) values(0.0123456789, 12345678.0123456789, 12345678.0123456789);
select to_char(f1), to_char(f2), to_char(f3) from test_temp_t1;
drop table test_temp_t1;

--test char 
--varchar same as varchar2
drop table if exists test_temp_t1;
create table test_temp_t1(f1 char(8000));
drop table test_temp_t1;
create table test_temp_t1(f1 varchar(8000));
drop table test_temp_t1;
create table test_temp_t1(f1 char, f2 char(5), f3 varchar(10), f4 varchar(8000));
insert into test_temp_t1(f1, f2, f3, f4) values(null, null, null, null);
insert into test_temp_t1(f1, f2, f3, f4) values('a', '12345', '0123456789', '0123456789');
insert into test_temp_t1(f1, f2, f3, f4) values('ab', null, null, null);
insert into test_temp_t1(f1, f2, f3, f4) values(1, null, null, null);
insert into test_temp_t1(f1, f2, f3, f4) values('1', '123456', null, null);
insert into test_temp_t1(f1, f2, f3, f4) values('1', 12345, null, null);
select * from test_temp_t1;
drop table test_temp_t1;

DROP TABLE IF EXISTS T_CHAR_1;
CREATE TABLE T_CHAR_1 (F_CHAR CHAR(8), F_VARCHAR VARCHAR(8));

INSERT INTO T_CHAR_1 VALUES('AB'    , 'AB'    );
INSERT INTO T_CHAR_1 VALUES('AB '   , 'AB '   );
INSERT INTO T_CHAR_1 VALUES(' A B'   , 'A B'   );
INSERT INTO T_CHAR_1 VALUES(' A B '  , 'A B '  );
INSERT INTO T_CHAR_1 VALUES('ABCDEFGH'  , 'ABCDEFGH'  );
UPDATE T_CHAR_1 SET F_CHAR = 'AB',F_VARCHAR = 'AB' WHERE F_CHAR = 'AB' AND F_VARCHAR = 'AB';
COMMIT;

--EXPECT ERROR
SELECT F_CHAR||'W' FROM T_CHAR_1 GROUP BY F_CHAR||'W ';

SELECT F_CHAR||'W' FROM T_CHAR_1 GROUP BY F_CHAR||'W' ORDER BY 1;
SELECT LENGTH(F_CHAR),LENGTH(F_VARCHAR) FROM T_CHAR_1 ORDER BY 1,2;
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'AB';
SELECT * FROM T_CHAR_1 WHERE F_CHAR > 'AB';
SELECT * FROM T_CHAR_1 WHERE F_CHAR like 'A_';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = SUBSTR('ABC',0,2);
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' AB';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'AB ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'AB  ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' A B';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' A B ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' A B  ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'ABCDEFGH';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR > 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR < 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' ABCDEFGH';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'AB';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR like 'A_';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = SUBSTR('ABC',0,2);
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' AB';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'AB ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'AB  ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' A B';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' A B ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' A B  ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'ABCDEFGH';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'ABCDEFGH ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' ABCDEFGH';

SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'AB';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR > 'AB';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR like 'A_';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = SUBSTR('ABC',0,2);
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' AB';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'AB ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'AB  ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' A B';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' A B ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' A B  ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'ABCDEFGH';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR > 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR < 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' ABCDEFGH';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR <<> 'ABCDEFGH; ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'AB';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR like 'A_';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = SUBSTR('ABC',0,2);
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' AB';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'AB ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'AB  ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' A B';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' A B ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' A B  ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'ABCDEFGH';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'ABCDEFGH ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' ABCDEFGH';

SELECT * FROM T_CHAR_1 T1,T_CHAR_1 T2 WHERE T1.F_CHAR = T2.F_CHAR ORDER BY T1.F_CHAR,T1.F_VARCHAR;
SELECT * FROM T_CHAR_1 T1,T_CHAR_1 T2 WHERE T1.F_VARCHAR = T2.F_VARCHAR ORDER BY T1.F_CHAR,T1.F_VARCHAR;
SELECT * FROM T_CHAR_1 T1,T_CHAR_1 T2 WHERE T1.F_CHAR = T2.F_VARCHAR ORDER BY T1.F_CHAR,T1.F_VARCHAR;
SELECT * FROM T_CHAR_1 T1,T_CHAR_1 T2 WHERE T1.F_VARCHAR = T2.F_CHAR ORDER BY T1.F_CHAR,T1.F_VARCHAR;


--TEST INDEX SELECT
CREATE INDEX INDEX_1_T_CHAR_1 ON T_CHAR_1(F_CHAR);
CREATE INDEX INDEX_2_T_CHAR_1 ON T_CHAR_1(F_VARCHAR);

UPDATE T_CHAR_1 SET F_CHAR = 'AB',F_VARCHAR = 'AB' WHERE F_CHAR = 'AB' AND F_VARCHAR = 'AB';
COMMIT;

SELECT LENGTH(F_CHAR),LENGTH(F_VARCHAR) FROM T_CHAR_1 ORDER BY 1,2;
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'AB';
SELECT * FROM T_CHAR_1 WHERE F_CHAR > 'AB';
SELECT * FROM T_CHAR_1 WHERE F_CHAR like 'A_';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = SUBSTR('ABC',0,2);
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' AB';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'AB ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'AB  ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' A B';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' A B ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' A B  ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'ABCDEFGH';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR > 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR < 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_CHAR = ' ABCDEFGH';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'AB';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR like 'A_';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = SUBSTR('ABC',0,2);
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' AB';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'AB ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'AB  ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' A B';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' A B ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' A B  ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'ABCDEFGH';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = 'ABCDEFGH ';
SELECT F_CHAR FROM T_CHAR_1 GROUP BY F_CHAR HAVING F_CHAR = ' ABCDEFGH';

SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'AB';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR > 'AB';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR like 'A_';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = SUBSTR('ABC',0,2);
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' AB';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'AB ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'AB  ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' A B';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' A B ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' A B  ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'ABCDEFGH';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR > 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR < 'ABCDEFGH ';
SELECT * FROM T_CHAR_1 WHERE F_VARCHAR = ' ABCDEFGH';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'AB';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR like 'A_';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = SUBSTR('ABC',0,2);
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' AB';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'AB ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'AB  ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' A B';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' A B ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' A B  ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'ABCDEFGH';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = 'ABCDEFGH ';
SELECT F_VARCHAR FROM T_CHAR_1 GROUP BY F_VARCHAR HAVING F_VARCHAR = ' ABCDEFGH';

SELECT * FROM T_CHAR_1 T1,T_CHAR_1 T2 WHERE T1.F_CHAR = T2.F_CHAR ORDER BY T1.F_CHAR,T1.F_VARCHAR;
SELECT * FROM T_CHAR_1 T1,T_CHAR_1 T2 WHERE T1.F_VARCHAR = T2.F_VARCHAR ORDER BY T1.F_CHAR,T1.F_VARCHAR;
SELECT * FROM T_CHAR_1 T1,T_CHAR_1 T2 WHERE T1.F_CHAR = T2.F_VARCHAR ORDER BY T1.F_CHAR,T1.F_VARCHAR;
SELECT * FROM T_CHAR_1 T1,T_CHAR_1 T2 WHERE T1.F_VARCHAR = T2.F_CHAR ORDER BY T1.F_CHAR,T1.F_VARCHAR;


--lob
drop table if exists test_temp_t1;
create table test_temp_t1(f1 clob, f2 blob, f3 binary(1), f4 raw(1), f5 varbinary(1));
select * from test_temp_t1;
insert into test_temp_t1 values(null, null, null, null, null);
select * from test_temp_t1;
drop table test_temp_t1;

drop table if exists test_temp_t1;
create table test_temp_t1(f1 bool, f2 bool, f3 bool);
select * from test_temp_t1;
insert into test_temp_t1 values(true, TRUE, NULL);
insert into test_temp_t1 values(FALSE, false, null);
select * from test_temp_t1;
select * from test_temp_t1 where f1=true;
select * from test_temp_t1 where f1=FALSE;
UPDATE test_temp_t1 SET f2=true where f1=FALSE;
select * from test_temp_t1;
drop table test_temp_t1;


-- DTS2018020802930
drop table if exists fmytest;
create table fmytest (a blob);
insert into  fmytest values('1');
insert into fmytest values('01');
insert into fmytest values('0x');
insert into fmytest values('0x0');
insert into fmytest values('123');
insert into fmytest values('12345');
insert into fmytest values('09898781');
insert into fmytest values('0x02');
insert into fmytest values('0x023');
insert into fmytest values('1234354587643123455213445656723123424554566776763221132454566768767433242323445453565654542323');
insert into fmytest values('0x02B');
insert into fmytest values('0x02K');
insert into fmytest values('0xK2');
insert into fmytest values('\x2');
insert into fmytest values('\X2D');
select * from fmytest;

drop table if exists fmytest2;
create table fmytest2 (a raw(30));
insert into fmytest2 values('1');
insert into fmytest2 values('01');
insert into fmytest2 values('0x');
insert into fmytest2 values('0x0');
insert into fmytest2 values('123');
insert into fmytest2 values('12345');
insert into fmytest2 values('09898781');
insert into fmytest2 values('0x02');
insert into fmytest2 values('0x023');
insert into fmytest2 values('1234354587643123455213445656723123424554566776763221132454566768767433242323445453565654542323');
insert into fmytest2 values('0x02B');
insert into fmytest2 values('0x02K');
insert into fmytest2 values('0xK2');
insert into fmytest2 values('0xR');
insert into fmytest2 values('0xX1234');
select * from fmytest2 order by a;

-- BOOLEAN DATATYPE
-- DTS2018020602819; DTS2018020505342
DROP TABLE IF EXISTS RQG_ALL_TYPE_TABLE_GSQL;
--CREATE TABLE RQG_ALL_TYPE_TABLE_GSQL( ID BIGINT, C_INTEGER INTEGER NULL , C_BIGINT BIGINT DEFAULT '10', C_NUMBER NUMBER NULL , C_DOUBLE DOUBLE PRECISION NULL , C_CHAR20 CHAR(20) NOT NULL , C_CHAR4000 CHAR(100) DEFAULT '10', C_VARCHAR20 VARCHAR(20) NULL DEFAULT '10', C_VARCHAR4000 VARCHAR(100) DEFAULT NULL, C_TEXT TEXT NULL DEFAULT NULL, C_BOOL BOOL NOT NULL DEFAULT 10, C_TIMESTAMP3 TIMESTAMP(3) NOT NULL DEFAULT '2000-01-01 12:59:59.999', C_TIMESTAMP6 TIMESTAMP(6) NULL ) DISTRIBUTE BY HASH ( C_BIGINT ) PARTITION BY RANGE ( C_VARCHAR20 ) ( PARTITION PT01 VALUES LESS THAN ( 'A' ),PARTITION PT02 VALUES LESS THAN ( 'P' ),PARTITION PT03 VALUES LESS THAN ( MAXVALUE ) );
CREATE TABLE RQG_ALL_TYPE_TABLE_GSQL( ID BIGINT, C_INTEGER INTEGER NULL , C_BIGINT BIGINT DEFAULT '10', C_NUMBER NUMBER NULL , C_DOUBLE DOUBLE PRECISION NULL , C_CHAR20 CHAR(20) NOT NULL , C_CHAR4000 CHAR(100) DEFAULT '10', C_VARCHAR20 VARCHAR(20) NULL DEFAULT '10', C_VARCHAR4000 VARCHAR(100) DEFAULT NULL, C_TEXT TEXT NULL DEFAULT NULL, C_BOOL BOOL NOT NULL DEFAULT 10, C_TIMESTAMP3 TIMESTAMP(3) NOT NULL DEFAULT '2000-01-01 12:59:59.999', C_TIMESTAMP6 TIMESTAMP(6) NULL ) PARTITION BY RANGE ( C_VARCHAR20 ) ( PARTITION PT01 VALUES LESS THAN ( 'A' ),PARTITION PT02 VALUES LESS THAN ( 'P' ),PARTITION PT03 VALUES LESS THAN ( MAXVALUE ) );
CREATE UNIQUE INDEX IDX ON RQG_ALL_TYPE_TABLE_GSQL ( C_VARCHAR20,C_BIGINT,c_timestamp3,c_char20,c_integer )   ;
INSERT INTO RQG_ALL_TYPE_TABLE_GSQL VALUES(0,1,1,1.234,1.12345,'cantiandbachar20','welcome tochinabchar4000','cantiandbavchar20','welcometochinabvchar4000','cantiandbtext',100,'2000-01-01 12:59:59.999','2000-01-01 12:59:59.999999');
INSERT INTO RQG_ALL_TYPE_TABLE_GSQL VALUES(1,2,2,2.234,2.12345,'cantiandbachar202','welcometochinabchar40002','cantiandbvchar202','welcometochinavchar40002','cantiandbtext2',FALSE,'2002-01-01 12:59:59.999','2002-01-01 12:59:59.999999');
INSERT INTO RQG_ALL_TYPE_TABLE_GSQL VALUES(2,-1500,-1500,-1500.234,-1500.12345,'aaussdbachar20','aelcometochinabchar4000','aaussdb vachar20','aelcometochinavarchar4000','aaussdbtext',TRUE,'2200-01-01 12:59:59.999','2200-01-01 12:59:59.999999');
INSERT INTO RQG_ALL_TYPE_TABLE_GSQL VALUES(3,1500,1500,1500.234,1500.12345,'baussdbachar20','belcometochinabchar4000','baussdbvachar20','belcometochinavarchar4000','baussdbtext',-10,'2300-01-01 12:59:59.999','2300-01-01 12:59:59.999999');
INSERT INTO RQG_ALL_TYPE_TABLE_GSQL VALUES(4,NULL,NULL,NULL,NULL,'char20',NULL,NULL,NULL,NULL,10,'2300-01-01 12:59:59.999',NULL) ;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL  order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL > TRUE order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = TRUE  order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 'TRUE'  order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 'falsE' order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 'false' order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 'TRUE  ' order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 'TRUE  1' order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL < 'TRUE' order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 'TRUE  1' order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE 'TRUE' < c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE 'false' < c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE 'false 01' < c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE '01' < c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE '1' < c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE '0' > c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE -1 > c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE -1 < c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE -1::bool > c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE -1::bool < c_bool order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE c_bool IN (TRUE, FALSE) order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE c_bool between FALSE and TRUE order by ID;

SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = '1' order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 1 order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 0 order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = '0' order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 100 order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = -100 order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = -1.001 order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 100.3232323232::decimal::double::int order by ID;
SELECT C_BOOL FROM RQG_ALL_TYPE_TABLE_GSQL WHERE C_BOOL = 0::bigint order by ID;

DROP TABLE IF EXISTS RQG_BOOL_TYPE_GSQL;
CREATE TABLE RQG_BOOL_TYPE_GSQL( ID BIGINT, C_INTEGER INTEGER NULL , C_BOOL boolean default 'False');
insert into RQG_BOOL_TYPE_GSQL values(0, 1, default);
insert into RQG_BOOL_TYPE_GSQL values(1, 1, null);
insert into RQG_BOOL_TYPE_GSQL values(2, null, true);
select * from RQG_BOOL_TYPE_GSQL order by id;

-- boolean and integer 
insert into RQG_BOOL_TYPE_GSQL values(3, 2, 1.00);
insert into RQG_BOOL_TYPE_GSQL values(3, 2, 100);
insert into RQG_BOOL_TYPE_GSQL values(4, 2, -100);
insert into RQG_BOOL_TYPE_GSQL values(5, 2, 0);
insert into RQG_BOOL_TYPE_GSQL values(6, 2, -0);
insert into RQG_BOOL_TYPE_GSQL values(7, 2, 0.0);
insert into RQG_BOOL_TYPE_GSQL values(8, 2, 0.1);
insert into RQG_BOOL_TYPE_GSQL values(9, 2, 0.0E100);
insert into RQG_BOOL_TYPE_GSQL values(10, 2, 1.0012311E2::double);
insert into RQG_BOOL_TYPE_GSQL values(10, 2, 1.0012311E2::decimal);
insert into RQG_BOOL_TYPE_GSQL values(11, 2, 1.0012311E2::double::int);
select * from RQG_BOOL_TYPE_GSQL where C_INTEGER = 2 order by id;
select id, cast(c_bool as integer), 1 - cast(c_bool as bigint) from RQG_BOOL_TYPE_GSQL where C_INTEGER = 2 order by id;
select id, cast(c_bool as double) from RQG_BOOL_TYPE_GSQL where C_INTEGER = 2 order by id;
select id, c_bool::int::double/2 from RQG_BOOL_TYPE_GSQL where C_INTEGER = 2 order by id;

-- reserved words
insert into RQG_BOOL_TYPE_GSQL values(12, 3, TRUE);
insert into RQG_BOOL_TYPE_GSQL values(13, 3, TrUE);
insert into RQG_BOOL_TYPE_GSQL values(14, 3, FALSE);
insert into RQG_BOOL_TYPE_GSQL values(15, 3, FALsE);
select * from RQG_BOOL_TYPE_GSQL where C_INTEGER = 3 order by id;

--- boolean and string
insert into RQG_BOOL_TYPE_GSQL values(20, 4, '0');
insert into RQG_BOOL_TYPE_GSQL values(21, 4, '1');
insert into RQG_BOOL_TYPE_GSQL values(22, 4, 'true');
insert into RQG_BOOL_TYPE_GSQL values(23, 4, 'tRUE');
insert into RQG_BOOL_TYPE_GSQL values(24, 4, 'false');
insert into RQG_BOOL_TYPE_GSQL values(25, 4, 'T');
insert into RQG_BOOL_TYPE_GSQL values(26, 4, 'F');
-- invalid input
insert into RQG_BOOL_TYPE_GSQL values(27, 4, '100');
insert into RQG_BOOL_TYPE_GSQL values(28, 4, '-10');
insert into RQG_BOOL_TYPE_GSQL values(29, 4, '00');
insert into RQG_BOOL_TYPE_GSQL values(30, 4, 'xasfd');
insert into RQG_BOOL_TYPE_GSQL values(31, 4, 'Tr');
insert into RQG_BOOL_TYPE_GSQL values(32, 4, 'Fa');
insert into RQG_BOOL_TYPE_GSQL values(33, 4, 'f'::binary(10));
select * from RQG_BOOL_TYPE_GSQL where C_INTEGER = 4 order by id;
select id, cast(c_bool as char(3)) from RQG_BOOL_TYPE_GSQL where C_INTEGER = 4 order by id;
select id, cast(c_bool as char(5)) from RQG_BOOL_TYPE_GSQL where C_INTEGER = 4 order by id;
select id, c_bool::integer||c_bool::varchar(10) from RQG_BOOL_TYPE_GSQL where C_INTEGER = 4 order by id;
select id, c_bool::binary(20) from RQG_BOOL_TYPE_GSQL where C_INTEGER = 4 order by id;

select * from RQG_BOOL_TYPE_GSQL order by id;
-- boolean column as a condition
select * from RQG_BOOL_TYPE_GSQL where C_BOOL order by id;

-- in and between
select * from RQG_BOOL_TYPE_GSQL where c_bool between 'F' and true and C_INTEGER = 4 order by id;
select * from RQG_BOOL_TYPE_GSQL where c_bool between 'F' and 'FALSE' and C_INTEGER = 4 order by id;
select * from RQG_BOOL_TYPE_GSQL where c_bool between 200 and -100 and C_INTEGER = 4 order by id;
select * from RQG_BOOL_TYPE_GSQL where c_bool not in(TRUE, 100) and C_INTEGER = 4 order by id;
select * from RQG_BOOL_TYPE_GSQL where c_bool not in(TRUE, '1') and C_INTEGER = 4 order by id;
select * from RQG_BOOL_TYPE_GSQL where c_bool in(TRUE, 1, 'F') and C_INTEGER = 4 order by id;
select * from RQG_BOOL_TYPE_GSQL where c_bool between 'F' and 'FALSE' and C_INTEGER = 4 order by id;
select * from RQG_BOOL_TYPE_GSQL where c_bool not in(TRUE, '1', 'xxxx');

--- boolean and aggr.sum
select sum(c_bool::int) from RQG_BOOL_TYPE_GSQL;
select sum(c_bool) from RQG_BOOL_TYPE_GSQL;

DROP TABLE IF EXISTS test;
Create table test(c_int int);
Insert into test values(699990016 / (6 + 1));
Select * from test;

DROP TABLE IF EXISTS RQG_ALL_TYPE_TABLE_GSQL;
CREATE TABLE RQG_ALL_TYPE_TABLE_GSQL(C_ID INTEGER, C_INTEGER INTEGER, C_BIGINT BIGINT,  C_BOOL BOOL,C_CHAR1 CHAR(1), C_CHAR20 CHAR(20), C_CHAR4000 CHAR(4000),C_VARCHAR1 VARCHAR(1), C_VARCHAR20 VARCHAR(20), C_VARCHAR4000 VARCHAR(4000)) ;
INSERT INTO RQG_ALL_TYPE_TABLE_GSQL(C_ID,C_VARCHAR20) VALUES(3,'1');
INSERT INTO RQG_ALL_TYPE_TABLE_GSQL(C_BOOL) VALUES(-9223372036854775808);
INSERT INTO RQG_ALL_TYPE_TABLE_GSQL(C_ID,C_VARCHAR20,C_BOOL) VALUES(3,'1',-9223372036854775808);
select C_ID, C_BOOL from RQG_ALL_TYPE_TABLE_GSQL;

select (10+NULL)::bool;
select -2147483648;

select cast(123123123 as smallint) from dual;
select cast(123123123 as tinyint) from dual;
select cast(123123123 as nvarchar(10)) from dual;
select cast(123123123 as nvarchar2(10)) from dual;

DROP TABLE IF EXISTS tbl_mysql_type_test;
create table tbl_mysql_type_test(f1 longtext, f2 longblob, f3 mediumblob, f4 image, f5 int);
desc tbl_mysql_type_test;
insert into tbl_mysql_type_test values('qwe', 1234, '123qweh', 4567, 1);
insert into tbl_mysql_type_test values('qwe1', 12234, 12678, 'aawweer', 2);
select * from tbl_mysql_type_test order by f5;

DROP TABLE IF EXISTS tbl_mysql_type_test;
create table tbl_mysql_type_test(x nchar, y utinyint);
desc tbl_mysql_type_test;

DROP TABLE IF EXISTS tbl_mysql_type_test;
create table tbl_mysql_type_test(x long);
desc tbl_mysql_type_test;

DROP TABLE IF EXISTS tbl_mysql_type_test;
create table tbl_mysql_type_test(x double(30, 12), y double precision(13, 6));
desc tbl_mysql_type_test;

-- error case
DROP TABLE IF EXISTS tbl_mysql_type_test;
create table tbl_mysql_type_test(x double(30.123, 12));
create table tbl_mysql_type_test(x double(30, 12.11));

-- Support "CAST(expr AS [SIGNED] INTEGER)"
select cast(1 as signed int);
select cast(1 as signed integer);
select cast(1 as signed smallint);

select cast(1 as int);
select cast(1 as integer);

select cast(1 as signed);
select cast(1 as signed bigint);
select cast(1 as signed number);

drop table if exists test_raw;
create table test_raw (a raw(30));
create index idx_test_raw on test_raw(a);
insert into test_raw values('0x023');
insert into test_raw values('1234'::binary(10));
insert into test_raw values(hextoraw('0adef1234'));
select * from test_raw;
--select * from test_raw where a='0x023';
select * from test_raw where a='1234'::binary(10);
select * from test_raw where a=hextoraw('0adef1234');

drop table if exists test_binary;
create table test_binary (a varbinary(30));
create index idx_test_binary on test_binary(a);
insert into test_binary values('0x023');
insert into test_binary values('1234'::binary(10));
insert into test_binary values(hextoraw('0adef1234'));
insert into test_binary values(rawtohex('abcd09812'));
select * from test_binary;
select * from test_binary where a='0x023';
select * from test_binary where a='1234'::binary(10);
select * from test_binary where a=hextoraw('0adef1234');
select * from test_binary where a=rawtohex('abcd09812');

select 9223372036854775807 - (-9223372036854775808) from dual;
select 1 - (-9223372036854775808) from dual;
select 9223372036854775808 - (-1) from dual;


----test uint32
Drop table if exists type_test;
Drop table if exists type_test1;
create table type_test(f1 bool, f2 int, f3 uint, f4 bigint, f5 serial primary key, f6 varchar(10));
insert into type_test values(1, 2147483647, 4294967295, 9223372036854775807, 1,'haha1');
insert into type_test values(1, -2147483648, 0, -9223372036854775808, 2,'haha2');
insert into type_test values(1, 234, 432, 3456, 3,'haha3');
Alter table type_test add column f8 uint default 0;
select * from type_test order by f5;
Alter table type_test drop column f8;
Create table type_test1 as select * from type_test;
Create index IDX_type_test1 on type_test1(f3,f5);
Create index IDX_type_test2 on type_test1(f3);
Select  distinct f3,f5 from type_test1 order by f5 desc ;
Select  distinct *,f5 from type_test1 where f3 !=1 order by f3 desc ;
Select f1,f2,f3,f4,f5,f6 from type_test1 start with f3=0 connect by prior f5 = 0 order by f3 desc;
Select f1,f2,f3,f4,f5,f6 from type_test1 start with f5=0 connect by prior f3 = 0  and  prior f5 = 0 order by f5 desc;
Select sum(f3),f3 from type_test1 group by f3 having avg(f2) >= 0 order by f3 desc;
Alter table type_test add column f8 uint;
Alter table type_test add column f9 binary_uint32;
Alter table type_test add column f10 integer unsigned;
Desc type_test;
Alter table type_test drop column f10;
Alter table type_test modify f9 bigint;
Desc type_test;
Drop table if exists type_test;
Drop table if exists type_test1;

Drop table if exists test_add_sub_mul_div;
Drop table if exists test_uint32;
create table test_add_sub_mul_div(a integer unsigned ,b integer);
insert into test_add_sub_mul_div values(-1 ,1);
insert into test_add_sub_mul_div values(4294967295::uint +10   ,1);
insert into test_add_sub_mul_div values(4294967295   ,1);
insert into test_add_sub_mul_div values(4294967295   ,-1);
insert into test_add_sub_mul_div values(4294967295   ,21342142);
insert into test_add_sub_mul_div values(100,101);
Select a+b from test_add_sub_mul_div order by b desc;
Select b+a from test_add_sub_mul_div order by b desc;
Select a*b from test_add_sub_mul_div order by b desc;
Select b*a from test_add_sub_mul_div order by b desc;
Select round(a/b,2) from test_add_sub_mul_div  order by b desc;
Select round(b/a,2) from test_add_sub_mul_div  order by b desc;
Select a-b from test_add_sub_mul_div order by b desc;
Select b-a from test_add_sub_mul_div order by b desc;
Select -a from  test_add_sub_mul_div where b=-1;
Create table test_uint32(a integer unsigned , b integer unsigned);
Insert into  test_uint32 values(0,4294967295);
Insert into test_uint32 values(10,11);
Insert into test_uint32 values(10,10);
Select a-b from test_uint32;
select mod(a,b) from test_uint32;
Select concat(a,b) from test_uint32;
Select concat_ws('-',a,b) from test_uint32;
select a&b from test_uint32 order by b;
select a|b from test_uint32 order by b;
select a^b from test_uint32 order by b;
select b<<1 from test_uint32 order by b;
select b>>1 from test_uint32 order by b;
Drop table if exists test_add_sub_mul_div;
Drop table if exists test_uint32;

select 4294967295::uint from dual;
select -1::uint from dual;
select 0::uint from dual;
select -10::uint from dual;
select -1::integer unsigned from dual;
select 10::integer unsigned from dual;
desc -q select 10::integer unsigned from dual;
desc -q select ifnull(null,-1::uint);
select 1 from dual where 2::integer unsigned > 1::integer unsigned;
select 1 from dual where 2::integer unsigned < 1::integer unsigned;
select 1 from dual where 2::integer unsigned >= 1::integer unsigned;
select 1 from dual where 2::integer unsigned <= 1::integer unsigned;
select 1 from dual where 2::integer unsigned != 1::integer unsigned;
drop table if exists test_uint32;
create table test_uint32(a integer unsigned);
insert into test_uint32 values(4294967295);
insert into test_uint32 values(100000);
insert into test_uint32 values(0);
select a from test_uint32 where a > -1 order by a;
select a from test_uint32 where a > 4294967296 order by a;
select a from test_uint32 where a >= -1 order by a;
select a from test_uint32 where a >= 4294967296 order by a;
select a from test_uint32 where a < -1 order by a;
select a from test_uint32 where a < 4294967296 order by a;
select a from test_uint32 where a <= -1 order by a;
select a from test_uint32 where a <= 4294967296 order by a;
select a from test_uint32 where a != -1 order by a;
select a from test_uint32 where a != 4294967296 order by a;
select a from test_uint32 where a in (0,100000,4294967295) order by a;
select 1 from dual where not exists (select a from test_uint32 where a in (0,100000,4294967295) order by a);
select 1 from dual where exists (select a from test_uint32 where a not in (-1) order by a);
select a from test_uint32 where a between -100 and 100000000000000000000 order by a;
select a from test_uint32 where a not between 0 and 100000 order by a;
select a from test_uint32 where a is null order by a;
select a from test_uint32 where a is not null order by a;
select * from test_uint32 where to_char(a) LIKE '%294%' order by a;
select * from test_uint32 where to_char(a) not LIKE '%294%' order by a;
select * from test_uint32 where to_char(a) regexp '[1-9]*' order by a;
select * from test_uint32 where regexp_like (a ,'[1-9]*') order by a;
select * from test_uint32 where a = ANY(0,3,5) order by a;
select * from test_uint32 where a = ANY('zhangsan') order by a;
select cast(a as int) from test_uint32 order by a;
select cast(a as bigint) from test_uint32 order by a;
select cast(a as varchar(20)) from test_uint32 order by a;
select cast(a as number(5,0)) from test_uint32 order by a;
select cast(a as number(10,0)) from test_uint32 order by a;
select convert (a, varchar(20)) from test_uint32 order by a;
select convert (a, bigint) from test_uint32 order by a;
select convert (a, int) from test_uint32 order by a;
select convert (a, number(5,0)) from test_uint32 order by a;
select convert (a, number(10,0)) from test_uint32 order by a;
select DECODE(a, 0, 'AAA', 100000, 'BBB', 'OK') from test_uint32 order by a;
select if(a<=0, ifnull(to_char(a),a), ifnull(null,a)) from test_uint32 order by a;
select if(a>0, ifnull(456,null), ifnull(null,123)) from test_uint32 order by a;
select nvl(a,0) from test_uint32 order by a;
select NVL2(a,a,a) from test_uint32 order by a;
select to_clob(a+1) from test_uint32 order by a;
select to_date(a,'YYYY-MM-DD HH24:MI:SS:FF') from test_uint32 order by a;
select to_number(a,'0000000000') from test_uint32 where a = 4294967295;
select sum(a),max(a),min(a),count(a),round(avg(a),2) from test_uint32;
select STDDEV(a) from test_uint32;
select STDDEV_SAMP(a) from test_uint32; 
select GROUP_CONCAT(a) from test_uint32; 
select lag(a,2,null)over(partition by a order by a) from test_uint32;
select COALESCE(null,null,a+10) from test_uint32 order by a;
SELECT DBA_IND_POS(to_char(a),'100000') from test_uint32 where a = 100000;
select GREATEST(a-42949672951) from test_uint32 order by a;
select LEAST(a+10) from test_uint32 order by a;
SELECT VSIZE(a) FROM test_uint32 order by a;
desc -q select nullif(4294967295, -1) from dual;
select nullif(a, -1) from  test_uint32 order by a;
select coalesce(a,-1) from test_uint32 order by a;
drop table if exists test_uint32;

drop procedure if exists proc_test_unint32;
create or replace procedure proc_test_unint32(
para1 integer unsigned
) as
v_name varchar2(20);
v_para integer unsigned;
begin
 v_para := para1 + 1;
 v_name :='zhangsf';
dbe_output.print_line(v_name || para1);
end;
/
begin
proc_test_unint32(4294967295);
end;
/
select * from table(dba_proc_line('SYS', 'PROC_TEST_UNINT32'));
drop procedure if exists proc_test_unint32;

declare 
  i integer unsigned;
  str varchar(100);
begin
  i := 1;  
  execute immediate 'drop table if exists test_uint32';
  execute immediate 'create table test_uint32(a integer unsigned)';
  for i in 1..3 
  loop
	str := 'insert into test_uint32 values('||i||')';
	execute immediate str;
  end loop;
  execute immediate 'drop table if exists test_uint32';
end;
/

drop table if exists a_int;
drop table if exists a_bigint;
drop table if exists a_uint32;
drop table if exists a_int_ua_bigint_ua_uint32_table ;
drop table if exists a_uint32_ua_bigint_ua_int_table ;
drop table if exists a_int_ua_uint32_ua_bigint_table ;
drop table if exists  a_bigint_ua_uint32_ua_int_table;
drop table if exists a_bigint_ua_int_ua_uint32_table;
drop table if exists a_uint32_ua_int_ua_bigint_table;
create table a_int(a int);
create table a_bigint(a bigint);
create table a_uint32(a integer unsigned);
insert into a_int values(-1);
insert into a_bigint values(9223372036854775807);
insert into a_uint32 values(4294967295);
create table a_int_ua_bigint_ua_uint32_table as (select b.a from (select a from a_int union all select a from a_bigint union all select a from a_uint32) b);
create table a_uint32_ua_bigint_ua_int_table as (select b.a from (select a from a_uint32 union all select a from a_bigint union all select a from a_int) b);
create table a_int_ua_uint32_ua_bigint_table as (select b.a from (select a from a_int union all select a from a_uint32 union all select a from a_bigint) b);
create table a_bigint_ua_uint32_ua_int_table as (select b.a from (select a from a_bigint union all select a from a_uint32 union all select a from a_int) b);
create table a_bigint_ua_int_ua_uint32_table as (select b.a from (select a from a_bigint union all select a from a_int union all select a from a_uint32) b);
create table a_uint32_ua_int_ua_bigint_table as (select b.a from (select a from a_uint32 union all select a from a_int union all select a from a_bigint) b);
desc a_int_ua_bigint_ua_uint32_table ;
desc a_uint32_ua_bigint_ua_int_table ;
desc a_int_ua_uint32_ua_bigint_table ;
desc a_bigint_ua_uint32_ua_int_table;
desc a_bigint_ua_int_ua_uint32_table;
desc a_uint32_ua_int_ua_bigint_table;
select * from a_int_ua_bigint_ua_uint32_table order by a;
select * from a_uint32_ua_bigint_ua_int_table order by a;
select * from a_int_ua_uint32_ua_bigint_table order by a;
select * from a_bigint_ua_uint32_ua_int_table order by a;
select * from a_bigint_ua_int_ua_uint32_table order by a;
select * from a_uint32_ua_int_ua_bigint_table order by a;
drop table if exists a_int;
drop table if exists a_bigint;
drop table if exists a_uint32;
drop table if exists a_int_ua_bigint_ua_uint32_table ;
drop table if exists a_uint32_ua_bigint_ua_int_table ;
drop table if exists a_int_ua_uint32_ua_bigint_table ;
drop table if exists  a_bigint_ua_uint32_ua_int_table;
drop table if exists a_bigint_ua_int_ua_uint32_table;
drop table if exists a_uint32_ua_int_ua_bigint_table;

drop table if exists a_int    ;
drop table if exists a_uint32       ;
drop table if exists a_int_ua_uint32;
drop table if exists a_uint32_ua_int;
create table a_int(a int);
create table a_uint32(a integer unsigned);
insert into a_int values(-1);
insert into a_uint32 values(4294967295);
create table a_int_ua_uint32 as (select b.a from (select a from a_int union all select a from a_uint32) b);
create table a_uint32_ua_int as (select b.a from (select a from a_uint32 union all select a from a_int) b);
desc a_int_ua_uint32;
desc a_uint32_ua_int;
select * from a_int_ua_uint32 order by a;
select * from a_uint32_ua_int order by a;
drop table if exists a_int    ;
drop table if exists a_uint32       ;
drop table if exists a_int_ua_uint32;
drop table if exists a_uint32_ua_int;

drop table if exists test_uint32;
create table test_uint32(a int, b int unsigned);
insert into test_uint32 values(-1, 4294967295);
insert into test_uint32 values(-2, 4294967291);
insert into test_uint32 values(3, 3294967291);
insert into test_uint32 values(0, 4294967295/2);
insert into test_uint32 values(-4294967295/2, 0);
select * from test_uint32 order by a;
select mod(a,b) from test_uint32 order by a;
select mod(b,a) from test_uint32 order by a;
select a%b from test_uint32 order by a;
select b%a from test_uint32 order by a;
drop table if exists test_uint32;

--timestamp with time zone
drop table if exists t_date;
CREATE TABLE t_date(c1 int,c2 int,c3 date,c4 timestamp with time zone unique);
CREATE TABLE t_date(c1 int,c2 int,c3 date,c4 timestamp with time zone primary key);

drop table if exists t_date;
CREATE TABLE t_date(a TIMESTAMP WITH TIME ZONE , b int);
alter table t_date add constraint con unique(a);
alter table t_date add constraint con unique(a, b);
alter table t_date add constraint con unique(b, a);
alter table t_date add constraint conx primary key(a);
alter table t_date add constraint conx primary key(a ,b);
alter table t_date add constraint conx primary key(b ,a);
drop table if exists t_date;

--ltz in order clause of sql
ALTER SESSION SET TIME_ZONE='+08:00';
drop table if exists tstz_type_test_tbl;
create table tstz_type_test_tbl(a int, b timestamp with local time zone default localtimestamp);
insert into tstz_type_test_tbl values(1,'2019-04-24 14:36:25.046731');
insert into tstz_type_test_tbl values(2,'2019-04-24 14:36:25.048023');
insert into tstz_type_test_tbl values(3,'2019-04-24 14:36:25.048802');

select b from tstz_type_test_tbl;
select b from (select b from tstz_type_test_tbl);
select b from(select b from (select b from tstz_type_test_tbl));
select b from (select b from(select b from (select b from tstz_type_test_tbl)));

select b from tstz_type_test_tbl;
select b from (select b from tstz_type_test_tbl order by a);
select b from (select b from (select b from tstz_type_test_tbl order by a));
select b from (select b from (select b from (select b from tstz_type_test_tbl order by a)));

select b from tstz_type_test_tbl order by a;
select b from (select b from tstz_type_test_tbl order by a) order by b;
select b from (select b from (select b from tstz_type_test_tbl order by a)) order by b;
select b from (select b from (select b from (select b from tstz_type_test_tbl order by a))) order by b;

select b from tstz_type_test_tbl;
select cast(b as date) from tstz_type_test_tbl;
select cast(b as timestamp) from tstz_type_test_tbl;
select cast(b as timestamp with time zone) from tstz_type_test_tbl;
select cast(b as timestamp with local time zone) from tstz_type_test_tbl;

--diff session tz
ALTER SESSION SET TIME_ZONE='+02:00';
SELECT SESSIONTIMEZONE FROM DUAL;
select b from tstz_type_test_tbl;

ALTER SESSION SET TIME_ZONE='+05:00';
SELECT SESSIONTIMEZONE FROM DUAL;
select b from tstz_type_test_tbl;

ALTER SESSION SET TIME_ZONE='-1:00';
SELECT SESSIONTIMEZONE FROM DUAL;
select b from tstz_type_test_tbl;

ALTER SESSION SET TIME_ZONE='+08:00';
drop table if exists tstz_type_test_tbl;

drop table if exists t_const2num_1;
drop table if exists t_const2num_2;
create table t_const2num_1(
c_int int, c_binary_uint binary_uint32, c_int_unsigned integer unsigned, c_bigint bigint,
c_double double, c_float float, c_real real,
c_number number, c_dec decimal(20,5),
c_varchar varchar(50)
) ;
create table t_const2num_2(
c_int int, c_binary_uint binary_uint32, c_int_unsigned integer unsigned, c_bigint bigint,
c_double double, c_float float, c_real real,
c_number number, c_dec decimal(20,5),
c_varchar varchar(50)
) ;
insert into t_const2num_1 values(
1, 5, 4294967295, 9223372036854775807,
1.12345, 0.001, 123.456,
1.234, 123456.12345,
'hello'
);
insert into t_const2num_2 values(
1, 100, 4294967295, 9223372036854775807,
1.12345, 10.00001, 1234.567,
1.234, 123456.12345,
'nihao'
);
commit;

select c_int, c_varchar from t_const2num_1 where c_int = '1';
select c_int, c_varchar from t_const2num_1 where c_bigint = '9223372036854775807';
select c_int, c_varchar from t_const2num_1 where c_float = '0.001000';
select c_int, c_varchar from t_const2num_1 where '-1.001' < c_real;
select c_int, c_varchar from t_const2num_1 where abs(c_number) = '+1.234';
select c_int, c_varchar from t_const2num_1 where c_dec + 1 = '123457.12345';
select t1.c_int, t2.c_varchar from t_const2num_1 t1 join t_const2num_2 t2 on t1.c_int = t2.c_int and t1.c_real = '123.456' ;
select c_int, count(c_int) from t_const2num_1 group by c_int having count(c_int) = '1.0';
select c_int, c_varchar from t_const2num_1 where '1' = (select count(*) from t_const2num_2);
select case when c_int ='1' then c_float else c_number end c from t_const2num_1 where c_double > '1.123400';
select t1.c_int, t2.c_varchar from t_const2num_1 t1 join t_const2num_2 t2 on t1.c_int = t2.c_int 
    where exists (select 1 from t_const2num_1 where rownum < '9.9') or t1.c_int_unsigned <> '-1';
select level,PRIOR c_int, c_varchar from t_const2num_1 where c_dec >= '123456.12345' and level = '1' 
    start with c_int = '1' connect by nocycle PRIOR c_binary_uint < '100';

drop table t_const2num_1;
drop table t_const2num_2;

drop table if exists t_test_bigint_sub;
create table t_test_bigint_sub(t1 uint, t2 bigint, t3 real);
insert into t_test_bigint_sub values(123, -9223372036854775808, 234);
select t1-t2 from t_test_bigint_sub;
select t3-t2 from t_test_bigint_sub;

drop table if exists FVT_FUCTION_GREATEST_TABLE_001;
create table FVT_FUCTION_GREATEST_TABLE_001( 
COL_1 bigint, 
COL_2 TIMESTAMP WITHOUT TIME ZONE, 
constraint FUCTION_GREATEST_TABLE_001 primary key(COL_1)
);

drop table if exists FVT_FUCTION_GREATEST_TABLE_002;
create table FVT_FUCTION_GREATEST_TABLE_002( 
COL_1 bigint, 
COL_2 TIMESTAMP WITHOUT TIME ZONE, 
constraint FUCTION_GREATEST_TABLE_002 primary key(COL_1)
);

set serveroutput on;
declare
v_count_01 int;
BEGIN
EXECUTE IMMEDIATE 'INSERT INTO FVT_FUCTION_GREATEST_TABLE_002 (COL_1,COL_2) SELECT COL_1,COL_2 FROM FVT_FUCTION_GREATEST_TABLE_001  WHERE COL_1>=GREATEST(:v1,:v2)' USING null,null;
select 
	count(1)   into v_count_01 
from 
(
	select COL_1,COL_2 from FVT_FUCTION_GREATEST_TABLE_001 where COL_1>=GREATEST(null,null) 
	except 
	select COL_1,COL_2 from FVT_FUCTION_GREATEST_TABLE_002
);
dbe_output.print_line(v_count_01);
EXCEPTION
--异常处理语句段
WHEN NO_DATA_FOUND THEN dbe_output.print_line('NO_DATA_FOUND');
END;
/

drop table if exists FVT_FUCTION_GREATEST_TABLE_001;
drop table if exists FVT_FUCTION_GREATEST_TABLE_002;
--DTS2020032613322
drop table if exists t_datatype_20200326;
drop table if exists temp1_DTS2020032613322;
drop table if exists temp2_DTS2020032613322;
drop table if exists temp3_DTS2020032613322;
drop table if exists temp4_DTS2020032613322;
create table t_datatype_20200326(f1 varchar(2 char), f2 char(3 byte), f3 char(20 byte), f7 INTERVAL DAY(7) TO SECOND,f8 INTERVAL YEAR(2) TO MONTH,f9 INTERVAL DAY(2) TO SECOND,f10 INTERVAL YEAR(4) TO MONTH);
insert into t_datatype_20200326 values('环境','gfs','sdfdfdajmsmdsofdms',null,null,null,null);
desc -q select f1 from t_datatype_20200326 union all select f2 from t_datatype_20200326;
create table temp1_DTS2020032613322 as select f1 from t_datatype_20200326 union all select f2 from t_datatype_20200326;
desc -q select f2 from t_datatype_20200326 union all select f1 from t_datatype_20200326;
create table temp2_DTS2020032613322 as select f2 from t_datatype_20200326 union all select f1 from t_datatype_20200326;
desc -q select f1 from t_datatype_20200326 union all select f3 from t_datatype_20200326;
create table temp3_DTS2020032613322 as select f1 from t_datatype_20200326 union all select f3 from t_datatype_20200326;
desc -q select f3 from t_datatype_20200326 union all select f1 from t_datatype_20200326;
create table temp4_DTS2020032613322 as select f3 from t_datatype_20200326 union all select f1 from t_datatype_20200326;
desc -q select f7 from t_datatype_20200326 union all select f9 from t_datatype_20200326;
desc -q select f9 from t_datatype_20200326 union all select f7 from t_datatype_20200326;
desc -q select f8 from t_datatype_20200326 union all select f10 from t_datatype_20200326;
desc -q select f10 from t_datatype_20200326 union all select f8 from t_datatype_20200326;
drop table t_datatype_20200326;
drop table temp1_DTS2020032613322;
drop table temp2_DTS2020032613322;
drop table temp3_DTS2020032613322;
drop table temp4_DTS2020032613322;

-- DTS202010100I8GVTP1E00
drop table if exists test_DTS202010100I8GVTP1E00;
create table test_DTS202010100I8GVTP1E00(f1 real, f2 number, f3 decimal);
insert into test_DTS202010100I8GVTP1E00 values(2.0e+128, 123.456, 456.78);
commit;
select case when f1 < 0 then f2 else f1 end from test_DTS202010100I8GVTP1E00;
desc -q select case when f1 < 0 then f2 else f1 end from test_DTS202010100I8GVTP1E00;
select case when f1 < 0 then f3 else f1 end from test_DTS202010100I8GVTP1E00;
desc -q select case when f1 < 0 then f3 else f1 end from test_DTS202010100I8GVTP1E00;
drop table if exists test_DTS202010100I8GVTP1E00;

drop table if exists test_array;
create table test_array(f1 int[], f2 bigint[], f3 real[], f4 number[], f5 decimal[]);
insert into test_array values(array[1, 2], array[111111111111111111, 22222222222222222], array[2.0e+128, 3.0e+128], array[111.111, 222.222], array[11.11, 22.22]);
commit;
select case when f2[1] < 0 then f1 else f2 end from test_array;
desc -q select case when f2[1] < 0 then f1 else f2 end from test_array;
select case when f3[1] < 0 then f4 else f3 end from test_array;
desc -q select case when f3[1] < 0 then f4 else f3 end from test_array;
select case when f3[1] < 0 then f5 else f3 end from test_array;
desc -q select case when f3[1] < 0 then f5 else f3 end from test_array;
drop table if exists test_array;

-- datatype compare
drop table if exists datatype_cmp_t;
create table datatype_cmp_t
(
    f1 integer, f2 binary_uint32, f3 bigint, f4 binary_double, f5 double, f6 float, f7 real, f8 number(12,3), f9 decimal(20,5), f10 char(30), f11 nchar(30), f12 varchar(30), 
    f13 varchar2(30), f14 nvarchar(30), f15 date, f16 datetime, f17 timestamp, f18 timestamp(3) with time zone, f19 timestamp(3) with local time zone, f20 boolean, 
    f21 interval year(4) to month, f22 interval day(7) to second(6), f23 int[], f24 binary(20), f25 varbinary(20), f26 raw(100), f27 clob, f28 blob, f29 image
);

select f1 from datatype_cmp_t where f1 = f27;
select f1 from datatype_cmp_t where f1 = f29;
select f1 from datatype_cmp_t where f2 = f27;
select f1 from datatype_cmp_t where f2 = f29;
select f1 from datatype_cmp_t where f3 = f27;
select f1 from datatype_cmp_t where f3 = f29;
select f1 from datatype_cmp_t where f4 = f27;
select f1 from datatype_cmp_t where f4 = f29;
select f1 from datatype_cmp_t where f8 = f27;
select f1 from datatype_cmp_t where f8 = f29;
select f1 from datatype_cmp_t where f10 = f27;
select f1 from datatype_cmp_t where f10 = f28;
select f1 from datatype_cmp_t where f10 = f29;
select f1 from datatype_cmp_t where f12 = f27;
select f1 from datatype_cmp_t where f12 = f28;
select f1 from datatype_cmp_t where f12 = f29;
select f1 from datatype_cmp_t where f15 = f27;
select f1 from datatype_cmp_t where f15 = f29;
select f1 from datatype_cmp_t where f17 = f27;
select f1 from datatype_cmp_t where f17 = f29;
select f1 from datatype_cmp_t where f18 = f27;
select f1 from datatype_cmp_t where f18 = f29;
select f1 from datatype_cmp_t where f19 = f27;
select f1 from datatype_cmp_t where f19 = f29;
select f1 from datatype_cmp_t where f20 = f27;
select f1 from datatype_cmp_t where f20 = f29;
select f1 from datatype_cmp_t where f21 = f27;
select f1 from datatype_cmp_t where f21 = f29;
select f1 from datatype_cmp_t where f22 = f27;
select f1 from datatype_cmp_t where f22 = f29;
select f1 from datatype_cmp_t where f24 = f7;
select f1 from datatype_cmp_t where f24 = f8;
select f1 from datatype_cmp_t where f24 = f27;
select f1 from datatype_cmp_t where f24 = f28;
select f1 from datatype_cmp_t where f24 = f29;
select f1 from datatype_cmp_t where f25 = f1;
select f1 from datatype_cmp_t where f25 = f2;
select f1 from datatype_cmp_t where f25 = f3;
select f1 from datatype_cmp_t where f25 = f4;
select f1 from datatype_cmp_t where f25 = f8;
select f1 from datatype_cmp_t where f25 = f27;
select f1 from datatype_cmp_t where f25 = f28;
select f1 from datatype_cmp_t where f25 = f29;
select f1 from datatype_cmp_t where f26 = f27;
select f1 from datatype_cmp_t where f26 = f28;
select f1 from datatype_cmp_t where f26 = f29;

drop table datatype_cmp_t;

-- DTS202101040IA7VDP1300
drop table if exists t_base_vchar3;
CREATE TABLE t_base_vchar3
(id int,
 c_vchar1 binary(20),
 c_vchar2 binary(20),
 c_int3   int,
 c_vchar4 varbinary(20),
 c_vchar5 varbinary(20)
);
INSERT INTO t_base_vchar3 values (1,'115',115,'115','115','115');
INSERT INTO t_base_vchar3 values (2,'26',26,'26','26','26');
INSERT INTO t_base_vchar3 values (3,'120',120,'120','120','120');
INSERT INTO t_base_vchar3 values (4,'10.0',15,'15.0','15.0','15.0');
INSERT INTO t_base_vchar3 values (5,'120.1',120,'120.1','120.1','120.1');
INSERT INTO t_base_vchar3 values (6,'-120.3',121,'120.3','120.3','120.3');
INSERT INTO t_base_vchar3 values (7,'120.4',123,'120.4','120.4','120.4');
INSERT INTO t_base_vchar3 values (8,'120.5',120,'120.5','120.5','120.5');
INSERT INTO t_base_vchar3 values (9,'1115',1115,'1115','1115','1115');
COMMIT;

create index idx_c_vchar2_1 on t_base_vchar3 (c_vchar2);
create index idx_c_vchar2_2 on t_base_vchar3 (c_int3);

-- binary cache
drop table if exists binary_cache_t;
create table binary_cache_t(c1 int, c2 bigint, c3 binary(20));
insert into binary_cache_t values(1,2,'1');
insert into binary_cache_t values(2,3,'2');
select c1,c2 from binary_cache_t t1 where c2 >=any(select c3 from binary_cache_t where c1 < 10) order by 1,2;
drop table binary_cache_t;
--20210730
drop table if exists temp_0730;
create table temp_0730(f1 tinyint unsigned);
insert into temp_0730 values(-1);
drop table temp_0730;
create table temp_0730(f1 smallint unsigned);
insert into temp_0730 values(-1);
drop table temp_0730;
alter database set time_zone='+08:00';
alter database set time_zone='+00:00';
