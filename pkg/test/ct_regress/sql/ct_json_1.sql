SELECT JSON_QUERY('{A:"B"}', '$') FROM DUAL;
SELECT JSON_QUERY('{"A":"B"}', '$') FROM DUAL;
SELECT JSON_QUERY('1,1', '$') JSON FROM DUAL;
SELECT JSON_QUERY(' ', '$') JSON FROM DUAL;

SELECT JSON_QUERY('{A:"B"}', '$' ERROR ON ERROR) FROM DUAL;
SELECT JSON_QUERY('{"A":"B"}', '$' ERROR ON ERROR) FROM DUAL;
SELECT JSON_QUERY('1,1', '$' ERROR ON ERROR) JSON FROM DUAL;
SELECT JSON_QUERY(' ', '$' ERROR ON ERROR) JSON FROM DUAL;

select json_query('{"name":"\/"}', '$') from dual;
select length(json_query('{"name":"\/"}', '$')) from dual;


select 1 from dual where '{"name":TRUE}' is json;
select 1 from dual where '{"name":FALSE}' is json;
select json_value('{"name":TRUE}', '$.name') from dual;
select json_value('{"name":FALSE}', '$.name') from dual;

select 1 from dual where json_value('{"name":TRUE}', '$.name') = 'TRUE';
select 1 from dual where json_value('{"name":FALSE}', '$.name') = 'FALSE';
select 1 from dual where json_value('{"name":TRUE}', '$.name') = true;
select 1 from dual where json_value('{"name":FALSE}', '$.name') = false;
select 1 from dual where json_value('{"name":TRUE}', '$.name' error on error) = 'TRUE';
select 1 from dual where json_value('{"name":FALSE}', '$.name' error on error) = 'FALSE';

select RAWTOHEX(json_value('{"name":"\r\ra\rs\rdf\rdf\r\r\ras\rd\rf\rxxxx\r\r\r"}', '$.name')) from dual;
select RAWTOHEX(json_value('{"name":"\r\ra\rs\rdf\rdf\r\r\ras\rd\rf\rxxxx"}', '$.name')) from dual;
select RAWTOHEX(json_value('{"name":"\r\ra\rs\rdf\rdf\r\r\ras\rd\rf\rxxxx\r"}', '$.name')) from dual;
select RAWTOHEX(json_value('{"name":"\r\ra\rs\rdf\rdf\r\r\ras\rd\rf\rxxxx\r\r"}', '$.name')) from dual;
select RAWTOHEX(json_value('{"name":"\r\ra\rs\rdf\rdf\r\r\ras\rd\rf\rxxxx\r\r\r"}', '$.name')) from dual;
select RAWTOHEX(json_value('{"name":"\b\ba\b\bsdfdf\b\basdf\b\bdf"}', '$.name')) from dual;
select RAWTOHEX(json_value('{"name":"\b\ba\b\bsdfdf\b\basdf\b\bdf\b"}', '$.name')) from dual;
select RAWTOHEX(json_value('{"name":"\b\ba\b\bsdfdf\b\basdf\b\bdf\b\b"}', '$.name')) from dual;
select RAWTOHEX(json_value('{"name":"\b\ba\b\bsdfdf\b\basdf\b\bdf\b\b\b"}', '$.name')) from dual;


drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"123456789"}','$.name') c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"123456789"}','$.name' returning varchar2(20) error on error) c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"123456789"}','$.name' returning varchar2(3900) error on error) c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"123456789"}','$.name' returning varchar2(4000) error on error) c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"123456789"}','$.name' returning varchar2(7000) error on error) c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"' || lpad('asdds', 9, 'as') || '"}','$.name') c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"' || lpad('asdds', 9, 'as') || '"}','$.name' returning varchar2(20) error on error) c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"' || lpad('asdds', 9, 'as') || '"}','$.name' returning varchar2(3900) error on error) c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"' || lpad('asdds', 9, 'as') || '"}','$.name' returning varchar2(4000) error on error) c1 from dual;
desc t_tj_1

drop table if exists t_tj_1;
create table t_tj_1 as select json_value('{"name":"' || lpad('asdds', 9, 'as') || '"}','$.name' returning varchar2(7000) error on error) c1 from dual;
desc t_tj_1


drop table if exists t_jn_1;
create table t_jn_1(id int, c1 clob);

begin
    insert into t_jn_1 values (1, NULL);
    for i in 1..255 loop
            update t_jn_1 set c1 = c1 || '"' || lpad('c1', 4093, 'c1') || '",';
            commit;
    end loop;

    update t_jn_1 set c1 = c1 || '"' || lpad('c1', 4092, 'c1') || '"';

    commit;
end;
/

update t_jn_1 set c1 = '[' || c1 || ']' where id = 1;
commit;

select id, length(c1), 1024*1024 - length(c1) from t_jn_1;

select 1 from t_jn_1 where c1 is json;
select 1 from t_jn_1 where c1 is not json;

-- OK
alter table t_jn_1 add  CONSTRAINT con1 check(c1 is json);
alter table t_jn_1 drop CONSTRAINT con1;

-- FAILED
alter table t_jn_1 add CONSTRAINT con2 check(c1 is not json);

-- OK
select length(json_value(c1, '$[0]' returning varchar2(8192) error on error)) from t_jn_1;

----------------
-- 1M+1
update t_jn_1 set c1 = c1 || ' ';
commit;
select id, length(c1), 1024*1024 - length(c1) from t_jn_1;

-- success
alter table t_jn_1 add  CONSTRAINT con1 check(c1 is json);

-- failed
alter table t_jn_1 add  CONSTRAINT con2 check(c1 is not json);
alter table t_jn_1 drop CONSTRAINT con1;

-- FAILED
select length(json_value(c1, '$[0]' returning varchar2(8192) error on error)) from t_jn_1;
----------------
drop table t_jn_1;


select json_query('[123, -123, 4.5572E+18, -4.5572E+18, 4.5572111112312321E+8, -4.5572111112312321E+8]','$') from dual;

DROP TABLE if exists T_JSON_TEST_1;
CREATE TABLE T_JSON_TEST_1 (C1 VARCHAR2(8000) check (c1 is json));
CREATE INDEX IDX_T_JSON_TEST_1_C1 ON T_JSON_TEST_1 (json_value(c1, '$.Aa' returning VARCHAR2(3900) null on error null on empty));
SELECT DEFAULT_TEXT FROM ALL_IND_COLUMNS WHERE TABLE_NAME = 'T_JSON_TEST_1' AND INDEX_NAME = 'IDX_T_JSON_TEST_1_C1' ORDER BY COLUMN_POSITION;
insert into T_JSON_TEST_1 values ('{"Aa":123}');
commit;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' returning VARCHAR2(3900) null on error null on empty) = '123';

DROP TABLE T_JSON_TEST_1;

------------------------------- JSON FUNC INDEX -------------------------------
DROP TABLE IF EXISTS T_JSON_TEST_1;
CREATE TABLE T_JSON_TEST_1 (C1 VARCHAR2(8000) check (c1 is json));
CREATE INDEX IDX_T_JSON_TEST_1_C1 ON T_JSON_TEST_1 (json_value(c1, '$.Aa'));
insert into T_JSON_TEST_1 values ('{"Aa":123}');
commit;

-- function
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa') = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' RETURNING VARCHAR2(3900)) = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' RETURNING VARCHAR2(3900) NULL ON ERROR) = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' NULL ON ERROR) = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' RETURNING VARCHAR2(3901)) = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' RETURNING VARCHAR2(3900) ERROR ON ERROR) = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' RETURNING VARCHAR2(3900) ERROR ON ERROR ERROR ON EMPTY) = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' RETURNING VARCHAR2(3900) ERROR ON EMPTY) = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' RETURNING VARCHAR2(3900) NULL ON EMPTY) = 123;
select * from T_JSON_TEST_1 where json_value(c1, '$.Aa' RETURNING VARCHAR2(3900) NULL ON ERROR NULL ON EMPTY) = 123;

DROP TABLE T_JSON_TEST_1;


------------------------------- JSON FUNC SERIALIZATION -------------------------------
-- constraint serialization
DROP TABLE IF EXISTS T_JSON_TEST_1;
CREATE TABLE T_JSON_TEST_1 ("c1" varchar2(8000), constraint con_T_JSON_TEST_1_1 check(length(json_value("c1", '$.Aa' returning varchar2(1024) error on error)) > 0));
SELECT COND_TEXT FROM SYS.CONSDEF$ WHERE CONS_NAME = 'CON_T_JSON_TEST_1_1';
DROP TABLE T_JSON_TEST_1;

DROP TABLE IF EXISTS T_JSON_TEST_1;
CREATE TABLE T_JSON_TEST_1 ("c1" varchar2(8000), "c2" int default length(json_value("c1", '$.Aa' returning varchar2(1024) error on error)));
SELECT COND_TEXT FROM SYS.CONSDEF$ WHERE CONS_NAME = 'CON_T_JSON_TEST_1_1';
DROP TABLE T_JSON_TEST_1;

-- constraint serialization
DROP TABLE IF EXISTS T_JSON_TEST_1;
CREATE TABLE T_JSON_TEST_1 (C1 INT, COL_T_JSON_TEST_1_C1 varchar2(8000) default length(json_value('{"Aa":123}', '$.Aa' returning varchar2(1024) error on error)));
select DEFAULT_TEXT from sys.column$ where name = 'COL_T_JSON_TEST_1_C1';
DROP TABLE T_JSON_TEST_1;

-- view serialization
create view V_JSON_TEST_1 as select json_value('{"Aa":123}', '$.Aa' returning varchar2(1024) error on error) C1 from dual;
desc V_JSON_TEST_1
select * from V_JSON_TEST_1;
SELECT 'CREATE OR REPLACE VIEW ' || U.NAME || '.' || V.NAME || ' ( '|| VC.COLUMNS || ' ) AS ', V.TEXT || ';' AS VIEWDEF FROM SYS.VIEW$ V, (SELECT USER#, VIEW#, GROUP_CONCAT(NAME ORDER BY ID) COLUMNS FROM SYS.VIEWCOL$ GROUP BY USER#, VIEW#) VC, SYS.USER$ U WHERE V.USER# = VC.USER# AND V.ID = VC.VIEW# AND V.USER# = U.ID AND V.NAME = 'V_JSON_TEST_1'; 
drop view V_JSON_TEST_1;
--DTS2020021009659
select json_array('true' format json, '1234' format json, 'null' format json) from dual;

-- AR.SR.IREQ02575689.001.001
drop table if exists json_t_mem_opt;
create table json_t_mem_opt (c clob);
insert into json_t_mem_opt values('[1,');
begin 
for i in 1..2000
    loop    
        update json_t_mem_opt set c = c || '1,1,1,8,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,';
    end loop;
    update json_t_mem_opt set c = c || '1]';
end;
/

commit;
select lengthb(c) from json_t_mem_opt;

begin 
for i in 1..5
    loop    
        insert into json_t_mem_opt select * from json_t_mem_opt;
    end loop;
end;
/

commit;

select json_value(c,'$[4]') from json_t_mem_opt;

select json_value('{"Aaa":{"A":12, "B":13, "c":[[[1,2],[3,4]],[[5,6],[7.8]]]}}', '$.Aaa[*].c[0][1][0]') as val from SYS_DUMMY;
