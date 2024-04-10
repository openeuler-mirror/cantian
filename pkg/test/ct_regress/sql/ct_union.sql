DROP TABLE IF EXISTS T_UNION_1;
DROP TABLE IF EXISTS T_UNION_2;
CREATE TABLE T_UNION_1 (F_INT1 INT, F_INT2 DECIMAL(20,0), F_CHAR CHAR(16), F_DATE DATE);
CREATE TABLE T_UNION_2 (F_INT1 INT, F_INT2 DECIMAL(20,0), F_CHAR CHAR(16), F_DATE DATE);

--EXPECT ERROR
SELECT * FROM T_UNION_1 UNION SELECT * FROM T_UNION_2 ORDER BY F_INT1 ORDER BY F_INT1;
SELECT * FROM T_UNION_1 ORDER BY F_INT1 ORDER BY F_INT1 UNION SELECT * FROM T_UNION_2;
SELECT F_INT1 FROM T_UNION_1 UNION SELECT * FROM T_UNION_2;
SELECT * FROM T_UNION_1 UNION SELECT F_INT1 FROM T_UNION_2;
SELECT F_INT1 FROM T_UNION_1 UNION SELECT F_INT1,F_INT2 FROM T_UNION_2;
SELECT F_INT1,F_INT2 FROM T_UNION_1 UNION SELECT F_INT1 FROM T_UNION_2;

--EMPTY RECORD
(SELECT F_INT1 FROM T_UNION_1 GROUP BY F_INT1) UNION (SELECT F_INT1 FROM T_UNION_2 GROUP BY F_INT1) ORDER BY F_INT1 DESC;
SELECT * FROM T_UNION_1 UNION SELECT * FROM T_UNION_2 ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_1) UNION (SELECT * FROM T_UNION_2) ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_1) UNION (SELECT * FROM T_UNION_2) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_1) UNION (SELECT * FROM T_UNION_2) UNION ALL (SELECT * FROM T_UNION_1) ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_1) UNION (SELECT * FROM T_UNION_2) UNION ALL (SELECT * FROM T_UNION_1) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_1 WHERE F_INT1 = 1) UNION ALL (SELECT * FROM T_UNION_2 WHERE F_INT2 = 3) UNION ALL (SELECT * FROM T_UNION_1) ORDER BY F_INT1,F_INT2 DESC;

INSERT INTO T_UNION_1 VALUES(1,2,'A','2017-12-11 14:08:00');
INSERT INTO T_UNION_1 VALUES(3,4,'C','2017-12-12 16:08:00');
INSERT INTO T_UNION_1 VALUES(1,3,'A','2017-12-11 14:18:00');
INSERT INTO T_UNION_1 VALUES(2,3,'B','2017-12-11 16:08:00');
INSERT INTO T_UNION_2 VALUES(4,2,'A','2017-12-11 14:08:00');
INSERT INTO T_UNION_2 VALUES(3,4,'C','2017-12-12 16:08:00');
INSERT INTO T_UNION_2 VALUES(6,4,'C','2017-12-12 16:08:00');
INSERT INTO T_UNION_2 VALUES(4,3,'A','2017-12-11 14:18:00');
INSERT INTO T_UNION_2 VALUES(5,3,'B','2017-12-11 16:08:00');
INSERT INTO T_UNION_2 VALUES(2,3,'B','2017-12-11 16:08:00');
INSERT INTO T_UNION_2 VALUES(1,3,'A','2017-12-11 14:18:00');
COMMIT;

--TEST if there is a virtual memory leak in nl join + hash union
SELECT 1 FROM (SELECT * FROM T_UNION_1 A),(SELECT * FROM T_UNION_1 UNION SELECT * FROM T_UNION_1);
SELECT 1 FROM T_UNION_1 A LEFT JOIN T_UNION_1 B ON A.F_INT1 = B.F_INT1 JOIN (SELECT * FROM T_UNION_1 UNION SELECT * FROM T_UNION_1);

(SELECT F_INT1 FROM T_UNION_1 GROUP BY F_INT1) UNION (SELECT F_INT1 FROM T_UNION_2 GROUP BY F_INT1) ORDER BY F_INT1 DESC;
SELECT * FROM T_UNION_1 UNION SELECT * FROM T_UNION_2 ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_1) UNION (SELECT * FROM T_UNION_2) ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_1) UNION (SELECT * FROM T_UNION_2) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_1) UNION (SELECT * FROM T_UNION_2) UNION (SELECT * FROM T_UNION_1) ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_1) UNION ALL (SELECT * FROM T_UNION_2) UNION (SELECT * FROM T_UNION_1) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_1) UNION ALL ((SELECT * FROM T_UNION_2) UNION (SELECT * FROM T_UNION_1)) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_1 WHERE F_INT1 = 1) UNION (SELECT * FROM T_UNION_2 WHERE F_INT2 = 3) UNION ALL (SELECT * FROM T_UNION_1) ORDER BY F_INT1,F_INT2 DESC;

--TEST DATATYPE
SELECT F_INT1 FROM T_UNION_1 UNION SELECT F_DATE FROM T_UNION_1 ORDER BY F_INT1;
SELECT F_CHAR FROM T_UNION_1 UNION SELECT F_DATE FROM T_UNION_1 ORDER BY F_CHAR;
SELECT F_INT1 FROM T_UNION_1 UNION SELECT F_INT2 FROM T_UNION_1 ORDER BY F_INT1;
SELECT F_INT1 FROM T_UNION_1 UNION SELECT F_CHAR FROM T_UNION_1 ORDER BY F_INT1;
SELECT F_INT2 FROM T_UNION_1 UNION SELECT F_CHAR FROM T_UNION_1 ORDER BY F_INT2;
SELECT F_INT1,F_INT2 FROM T_UNION_1 UNION SELECT F_CHAR,F_INT2 FROM T_UNION_1 ORDER BY F_INT1,F_INT2;
SELECT F_INT1,F_INT2 FROM T_UNION_1 UNION SELECT F_INT1,F_CHAR FROM T_UNION_1 ORDER BY F_INT1,F_INT2;
SELECT F_INT1,F_CHAR FROM T_UNION_1 UNION SELECT F_INT1,F_INT2 FROM T_UNION_1 ORDER BY F_INT1,F_CHAR;
SELECT F_INT1,F_INT2 FROM T_UNION_1 UNION SELECT F_CHAR,F_INT1 FROM T_UNION_1 ORDER BY F_INT1,F_INT2;
SELECT * FROM T_UNION_1 UNION SELECT F_INT2,F_CHAR,F_INT1,F_DATE FROM T_UNION_1 ORDER BY F_INT1,F_INT2,F_CHAR;
SELECT F_INT2,F_CHAR,F_INT1,F_DATE FROM T_UNION_1 UNION SELECT * FROM T_UNION_1 ORDER BY F_INT1,F_INT2,F_CHAR;
 
desc -q select current_date,current_timestamp from dual union (select current_timestamp,current_date from dual);

create or replace view UNION_VIEW_TEST1 as select current_timestamp(3) c from dual union select current_timestamp(6) c from dual order by 1;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select current_timestamp(3) c from dual union select current_timestamp(6) c from dual order by 1;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select sysdate c from dual union select current_timestamp(5) c from dual order by 1;
desc UNION_VIEW_TEST1

desc -q select to_date('2012-12-12') from dual minus select cast(systimestamp as timestamp(5) with time zone) from dual; 

create or replace view UNION_VIEW_TEST1 as select cast(systimestamp as timestamp with local time zone) c from dual union select cast(systimestamp as timestamp with time zone) from dual order by 1;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select cast(systimestamp as timestamp(1) with local time zone) c from dual union select cast(systimestamp as timestamp(2) with time zone) from dual order by 1;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select systimestamp(0) c from dual union select cast(systimestamp as timestamp(2) with time zone) from dual order by 1;
desc UNION_VIEW_TEST1

-- BOOLEAN union datatype
desc -q select true X from dual union select false from dual;
desc -q select true X from dual union select 1 from dual;
desc -q select true X from dual union select 1.0 from dual;

-- NULL union datatype
desc -q select NULL X from dual union select 1.0 from dual;
desc -q select NULL X from dual union select cast(2.3 as number(30, 2)) from dual;
desc -q select NULL X from dual union select sysdate from dual;
desc -q select NULL X from dual union select 'asdasdasd' from dual;
desc -q select NULL X from dual union select 'asdasdasd' from dual union select NULL from dual;
desc -q select NULL X from dual union select NULL from dual;
desc -q select 'asdasdasd' X from dual union select NULL from dual;
desc -q select 'asdasdasd' X from dual union select NULL from dual union select to_char(sin(1)) from dual;
create or replace view UNION_VIEW_TEST1 as select NULL c from dual union select NULL from dual order by 1;
desc UNION_VIEW_TEST1
desc -q select NULL c from dual union select NULL from dual order by 1;
desc -q select cast(NULL as varchar(2)) c from dual union select NULL from dual;
desc -q select '' X  from dual;
select NULL X from dual union select '' from dual;
desc -q select NULL X from dual union select '' + 1 from dual;
desc -q select '' X from dual union select '' + 1 from dual;
desc -q select '' X from dual minus select '' from dual union select NULL from dual;
desc -q select '' X from dual minus select '1' from dual union select NULL from dual;
desc -q select '2' X from dual minus select '1' from dual union select NULL from dual;
desc -q select '2' X from dual minus select '1' from dual union select '' from dual;
desc -q select null - null X from dual minus select '1' from dual;
desc -q select null - null X from dual minus select 1 from dual;
desc -q select null - null X from dual minus select null from dual;
desc -q select null - null X from dual minus select null || null from dual;
desc -q select null X from dual minus select null || null from dual;
desc -q select 'TRUE' X from dual minus select FALSE from dual;
desc -q select cast('' as char(2)) X from dual minus select 'FA' from  dual;
desc -q select cast('X' as char(2)) X from dual minus select 'FA' from  dual;
desc -q select cast(dummy as char(2)) X from dual minus select 'FA' from  dual;
desc -q select cast(dummy as varchar(2)) X from dual minus select 'FA' from  dual;
desc -q select cast(dummy as number(38)) X from dual minus select 'FA' + NULL from  dual;
desc -q select cast(dummy as number(38)) X from dual minus select NULL from  dual;
desc -q select cast(dummy as number(38)) X from dual minus select NULL from dual union select NULL from dual;
desc -q select (select to_date('') from dual) X from dual minus select NULL from dual union select NULL from dual;
desc -q select (select to_date('') from dual) X from dual minus select NULL from dual union select systimestamp(0) from dual;
desc -q select X from (select to_date('') X from dual) minus select NULL from dual union select systimestamp(2) from dual;


create or replace view UNION_VIEW_TEST1 as select cast(NULL as varchar(12)) c from dual union select NULL from dual order by 1;
desc UNION_VIEW_TEST1

desc -q select cast(NULL as varchar(2)) c from dual union select cast(NULL as date) from dual;

-- union string datatype group
desc -q select '2012-12-12' c from dual union select cast(NULL as date) from dual;
desc -q select cast('1' as char(100)) X from dual union select cast(3 as char(100)) from dual;
desc -q select cast('1' as char(100 char)) X from dual union select cast(3 as char(100)) from dual;
desc -q select cast('1' as varchar(100)) X from dual union select cast('123' as varchar(200)) from dual;
create or replace view UNION_VIEW_TEST1 as select cast('1' as char(100 char)) X from dual union select cast(3 as char(200) )  from dual;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select cast('1' as varchar(100 char)) X from dual union select cast(3 as char(100) )  from dual;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select cast('1' as char(100 char)) X from dual union select cast(3 as char(100 char) )  from dual;
desc UNION_VIEW_TEST1

desc -q select cast(dummy as char(38)) X from dual union select cast(dummy as varchar(38 char)) X from dual;
desc -q select cast(dummy as char(38)) X from dual union select cast(dummy as varchar(5 char)) X from dual;
desc -q select cast(dummy as char(38)) X from dual union select cast(dummy as varchar(40 char)) X from dual;
desc -q select cast(dummy as varchar(38 char)) X from dual union select cast(dummy as varchar(40 char)) X from dual;
desc -q select cast(dummy as varchar(38 char)) X from dual union select cast(dummy as varchar(40)) X from dual;
desc -q select cast(dummy as varchar(38 char)) X from dual union select cast(dummy as varchar(400)) X from dual;
desc -q select cast(dummy as varchar(38 char)) X from dual union select null X from dual;
desc -q select cast(dummy as varchar(380)) X from dual union select cast(dummy as varchar(400)) X from dual;
desc -q select cast(dummy as varchar(380 char)) X from dual union select cast(dummy as varchar(400)) X from dual;
desc -q select cast(dummy as varchar(1 char)) X from dual union select cast(dummy as varchar(400)) X from dual;
desc -q select cast(dummy as char(1 char)) X from dual union select cast(dummy as char(400)) X from dual;

-- testing for numeric datatype group
desc -q select cast(1 as binary_integer) from dual union select cast(3.1 as binary_bigint) from dual;
desc -q select cast(1 as binary_integer) from dual union select 3.1 from dual;
desc -q select cast(1 as NUMBER(10)) from dual union select 3.1::NUMBER(10) from dual;
create or replace view UNION_VIEW_TEST1 as select cast('1' as NUMBER(10)) X from dual union select cast(3 as NUMBER(10, 0)) from dual;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select cast('1' as NUMBER(10)) X from dual union select cast(3 as NUMBER(10, 1)) from dual;
desc UNION_VIEW_TEST1

desc -q select cast('1' as NUMBER(10)) X from dual union select cast(3 as NUMBER(11,1)) from dual;

desc -q select cast('1' as BINARY_BIGINT) X from dual union select cast(3 as NUMBER(10, 1)) from dual;
desc -q select cast('1' as BINARY_BIGINT) X from dual union select cast(3 as BINARY_DOUBLE) from dual;
desc -q select '1' X from dual union select cast(3 as BINARY_DOUBLE) from dual;
desc -q select cast('1' as raw(100)) X from dual union select cast('123' as BINARY_DOUBLE) from dual;
desc -q select cast('1' as raw(100)) X from dual union select cast('123' as raw(100)) from dual;
desc -q select cast('1' as raw(100)) X from dual union select cast('123' as raw(200)) from dual;
create or replace view UNION_VIEW_TEST1 as select cast('1' as raw(100)) X from dual union select cast('123' as raw(200)) from dual;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select cast('1' as raw(100)) X from dual union select cast('123' as raw(200)) from dual union select true from dual;

desc -q select cast('1' as raw(100)) X from dual union select '123' from dual;
create or replace view UNION_VIEW_TEST1 as select NULL || cast('1' as char(100)) X from dual union select '123' from dual;
desc UNION_VIEW_TEST1

create or replace view UNION_VIEW_TEST1 as select NULL * cast('1' as char(100)) X from dual union select '123' from dual;

desc -q select NULL * NULL X from dual union select '123' from dual;
desc -q select NULL * 1 X from dual union select '123' from dual;
desc -q select NULL + 1 X from dual union select '123' from dual;
desc -q select NULL || 1 X from dual union select '123' from dual;
desc -q select NULL | 1 X from dual union select '123' from dual;
desc -q select NULL | 1 X from dual union select 123 from dual;
desc -q select cast('123' as binary(30)) X from dual union select cast('123' as binary(30)) from dual;
desc -q select cast('123' as binary(30)) X from dual union select cast('123' as binary(32)) from dual;
desc -q select cast('123' as binary(30)) X from dual union select cast('123' as varbinary(30)) from dual;
desc -q select cast('123' as binary(36)) X from dual union select cast('123' as varbinary(30)) from dual;

desc -q select cast('123' as binary(30)) X from dual union select cast('123' as char(30)) from dual;
desc -q select cast('123' as binary(30)) X from dual union select cast('123' as raw(30)) from dual;

desc -q select interval '12-1' year to month X from dual union select NULL from dual;
desc -q select null from dual union select interval '12-1' year to month X from dual union select NULL from dual;
desc -q select interval '12-1' year(2) to month X from dual union select interval '123-1' year(4) to month from dual;
desc -q select interval '12-1' year to month X from dual union select numtoyminterval(8888, 'month') from dual;
desc -q select interval '12-1' year to month X from dual union select cast('' as interval year(3) to month) from dual;
desc -q select null from dual union select interval '12-1' year to month X from dual union select 'X' from dual;
desc -q select null from dual union select interval '0 0:0:1' day to second X from dual;
desc -q select numtodsinterval(999999, 'second') H from dual union select interval '0 0:0:1' day to second X from dual;
desc -q select interval '0 0:0:1' day(5) to second(2) X from dual union select interval '0 0:0:1' day(3) to second(5) X from dual;
desc -q select interval '0 0:0:1' day(5) to second(2) X from dual union select interval '12-1' year to month X from dual;

drop table if exists UNION_TAB_TEST1;
create table UNION_TAB_TEST1(c_varchar varchar(100), c_char char(36), c_char2 char(36 char), c_bool bool, c_clob clob, c_int binary_integer, c_dec number);

desc -q select c_char from UNION_TAB_TEST1 union select c_varchar from UNION_TAB_TEST1;
desc -q select c_char2 from UNION_TAB_TEST1 union select c_varchar from UNION_TAB_TEST1;
desc -q select c_char2 from UNION_TAB_TEST1 union select c_char from UNION_TAB_TEST1;
desc -q select c_char2 from UNION_TAB_TEST1 union select cast(1 as char(110)) from UNION_TAB_TEST1;
create or replace view UNION_VIEW_TEST1 as select cast('1' as char(100)) X from dual union select c_char from UNION_TAB_TEST1;
desc UNION_VIEW_TEST1
desc -q select X from UNION_VIEW_TEST1 union select c_char2 from UNION_TAB_TEST1;

-- FUNC_AS_TABLE
desc -q select * from table(dba_analyze_table('sys','UNION_TAB_TEST1'));
desc -q select VALUE from table(dba_analyze_table('sys','UNION_TAB_TEST1')) union select  to_number(123) from dual;
desc -q select STAT_ITEM from table(dba_analyze_table('sys','UNION_TAB_TEST1')) union select '' from dual;

desc -q select -null X from dual minus select +'a' from dual;
desc -q select sin(null) X from dual minus select -'a' from dual;
desc -q select -null X from dual minus select null from dual;
desc -q select -null X from dual minus select +null from dual;

desc -q select null from dual union select null from dual union select 2.3 from dual;
desc -q select null from dual union select null from dual union select 2.3 from dual minus select null from dual;
desc -q select null from dual union select null from dual union select 'abcd' from dual minus select null from dual union select 'hijklmn' from dual;

-- testing for BOOLEAN union
select min(true) from dual;
select min(x), max(x), count(x) from (select true X from dual connect by rownum < 10 union select false from dual);
select min(x), max(x), count(x) from (select true X from dual connect by rownum < 10 union all select false from dual);
select max(false) from dual union select count(sysdate) from dual;
select max(false) from dual union select count(1) from dual;

