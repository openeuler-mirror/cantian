--- The optimization for constant expression 
select * from dual where 1=1 and 1 = -1-2-3-4+5+6;

--- The optimization for ROWNUM
select * from dual where rownum is null;
select * from dual where rownum is not null;
select * from dual where rownum = 1;
select * from dual where rownum = 2;
select * from dual where rownum >= 0;
select * from dual where rownum >= 1;
select * from dual where rownum >= 2;
select * from dual where rownum > 0;
select * from dual where rownum > 0.5;
select * from dual where rownum > 1;
select * from dual where rownum > 1.5;
select * from dual where rownum < 0;
select * from dual where rownum < 1;
select * from dual where rownum < 2;
select * from dual where rownum <= 1;
select * from dual where rownum <= 0;
select * from dual where rownum <= 2;
select * from dual where rownum <> 0;
select * from dual where rownum <> 1;
select * from dual where rownum <> 3;
select * from dual where rownum <> 3.1;
select * from dual where rownum<1+1-1+2-2;

select * from dual where 1   =  rownum;
select * from dual where 2   =  rownum;
select * from dual where 0   >= rownum;
select * from dual where 1   >= rownum;
select * from dual where 2   >= rownum;
select * from dual where 0   >  rownum;
select * from dual where 0.5 >  rownum;
select * from dual where 1   >  rownum;
select * from dual where 1.5 >  rownum;
select * from dual where 0   <  rownum;
select * from dual where 1   <  rownum;
select * from dual where 2   <  rownum;
select * from dual where 1   <= rownum;
select * from dual where 0   <= rownum;
select * from dual where 2   <= rownum;
select * from dual where 0   <> rownum;
select * from dual where 1   <> rownum;
select * from dual where 3   <> rownum;
select * from dual where 3.1 <> rownum;
select * from dual where 1+1-1+2-2 < rownum;


--- Select data from table
DROP TABLE IF EXISTS rownum_test;
create table rownum_test(id int, tt char(30));
insert into rownum_test values(1, 'Hello 1');
insert into rownum_test values(2, 'Hello 2');
insert into rownum_test values(2, 'Hello 3');
insert into rownum_test values(4, 'Hello 4');
insert into rownum_test values(3, 'Hello 5');
DROP TABLE IF EXISTS ROWNUM_TEST_1;
CREATE TABLE ROWNUM_TEST_1(F_INT INT, F_CHAR CHAR(30));
INSERT INTO  ROWNUM_TEST_1 VALUES(1, 'TEST 1');
INSERT INTO  ROWNUM_TEST_1 VALUES(1, 'TEST 2');
INSERT INTO  ROWNUM_TEST_1 VALUES(2, 'TEST 1');
INSERT INTO  ROWNUM_TEST_1 VALUES(2, 'TEST 2');
INSERT INTO  ROWNUM_TEST_1 VALUES(3, 'TEST 1');
INSERT INTO  ROWNUM_TEST_1 VALUES(3, 'TEST 2');
INSERT INTO  ROWNUM_TEST_1 VALUES(4, 'TEST 1');
INSERT INTO  ROWNUM_TEST_1 VALUES(4, 'TEST 2');
commit;

-- basic test
select rownum, id, tt from rownum_test;
select rownum, id, tt from rownum_test rt where rownum is null;
select rownum, id, tt from rownum_test rt where rownum is not null;
select rownum, id, tt from rownum_test rt where rownum < -1;
select rownum, id, tt from rownum_test rt where rownum < 1;
select rownum, id, tt from rownum_test rt where rownum < 1.1;
select rownum, id, tt from rownum_test rt where rownum < 1.0000001;
select rownum, id, tt from rownum_test rt where rownum < 1.0000000000000000000000000000000000001;
select rownum, id, tt from rownum_test rt where rownum < 2;
select rownum, id, tt from rownum_test rt where rownum <= 2;
select rownum, id, tt from rownum_test rt where rownum <= 2.1;
select rownum, id, tt from rownum_test rt where rownum > 0;
select rownum, id, tt from rownum_test rt where rownum > -1;
select rownum, id, tt from rownum_test rt where rownum > 1;
select rownum, id, tt from rownum_test rt where rownum > 0.9;
select rownum, id, tt from rownum_test rt where rownum >= 0;
select rownum, id, tt from rownum_test rt where rownum >= 1;
select rownum, id, tt from rownum_test rt where rownum >= 2;
select rownum, id, tt from rownum_test rt where rownum = 1;
select rownum, id, tt from rownum_test rt where rownum = 1.2;
select rownum, id, tt from rownum_test rt where rownum = 3;
select rownum, id, tt from rownum_test rt where rownum <> -2;
select rownum, id, tt from rownum_test rt where rownum <> 1;
select rownum, id, tt from rownum_test rt where rownum <> 1.000001;
select rownum, id, tt from rownum_test rt where rownum <> 1.0000000000000000000000000000000000001;
select rownum, id, tt from rownum_test rt where rownum <> 3;
select rownum, id, tt from rownum_test rt where rownum <> 3.2;

-- rownum in constant expression
select rownum, id, tt from rownum_test rt where rownum < 3 + 2 -3;
select rownum, id, tt from rownum_test rt where rownum >= 3 + 2 -3;

-- rownum in complex condition expression
select rownum, id, tt from rownum_test rt where rownum > 1 or id = 2;
select rownum, id, tt from rownum_test rt where rownum > 1 and id = 2;
select rownum, id, tt from rownum_test rt where rownum <= 1 and id = 2;
select rownum, id, tt from rownum_test rt where rownum <= 10 and id = 2;
select rownum, id, tt from rownum_test rt where rownum > 1 or rownum < 3;
select rownum, id, tt from rownum_test rt where rownum < 2 and rownum < 3;
select rownum, id, tt from rownum_test rt where rownum < 2 or rownum < 3;
select rownum, id, tt from rownum_test rt where rownum < 2 or (rownum < 3 and id <> 2);
select rownum, id, tt from rownum_test rt where rownum <= 4 or (rownum < 3 and id <> 2);
select rownum, id, tt from rownum_test rt where 1=1 or rownum > 100;
select rownum, rt.id, rt.tt from rownum_test rt;
select rt.rownum, rt.id, rt.tt from rownum_test rt;


--- rownum order by
select rownum, rt.id, rt.tt from rownum_test rt order by id;

--- ROWNUM and in expression
-- The following queries show that ROWNUM = 2 can not be optimized directly,
-- since when rownum = 1 holds, then rownum = 2 may satisfy the conditions.
select rownum, id, tt from rownum_test where rownum in (1,2,4);
select rownum, id, tt from rownum_test where rownum = 1 or rownum = 2 or rownum = 4;
select rownum, id, tt from rownum_test where (rownum, id) in ((1,2), (2,3));
select rownum, id, tt from rownum_test where (rownum = 1 and id = 2) or (rownum = 2 and id = 3);
-- Similarly, we can not optimize rownum>2, since the condition rownum < 3 may be hold
select rownum, id, tt from rownum_test where rownum>2 or rownum < 3;
select rownum, id, tt from rownum_test where (rownum<>1 or id = 1) and rownum < 5;
select rownum, id, tt from rownum_test where (rownum<>1 or id = 1) or rownum=1;

--- for condtion optimization, which can emit some illegal 
--- id is an integer type, thus conditions id = 'afasdf' is illegal, and an error
--- should be notified. The rownum < 0 (false) can eliminate (rownum < 0 and id = 'afasdf');
-- The following SQLs seems to have no effect. :(
select rownum, id, tt from rownum_test where id = 'afasdf';
select rownum, id, tt from rownum_test where rownum < 0 and id = 'afasdf';
select rownum, id, tt from rownum_test where id = 'afasdf' and rownum < 0;
select rownum, id, tt from rownum_test where id = 'afasdf' or rownum < 0;

-- The following SQLs have effects. :)
select * from rownum_test where id + 'sdf' < 5;
select * from rownum_test where rownum<2 or id + 'sdf' < 5;
-- The illegal condition id + 'sdf' < 5 can be eliminated.
select * from rownum_test where rownum<1 and id + 'sdf' < 5;
select * from rownum_test where id + 'sdf' < 5 and rownum<1;
select * from rownum_test where (rownum = 2.3 and id + 'sdf' < 5) or rownum<3;
select * from rownum_test where rownum<3 or (rownum = 2.3 and id + 'sdf' < 5);
--- for UPDATE test
update rownum_test set id = 6 where 2 >= rownum;
select rownum, id, tt from rownum_test;

update rownum_test set rownum = 6 where 2 >= rownum;

update rownum_test set id = 7 where 2 > rownum;
select rownum, id, tt from rownum_test;

--- for DELETE test
delete rownum_test where id >5 and rownum < 4;
select rownum, id, tt from rownum_test;

-- TEST SORT
SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM < 7 ORDER BY F_INT;
SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM > 1 ORDER BY F_INT;
SELECT F_INT, COUNT(*) FROM ROWNUM_TEST_1 WHERE ROWNUM < 7 GROUP BY F_INT ORDER BY F_INT;
SELECT F_INT, COUNT(*) FROM ROWNUM_TEST_1 WHERE ROWNUM > 0 GROUP BY F_INT ORDER BY F_INT;
SELECT F_INT, COUNT(*) FROM ROWNUM_TEST_1 WHERE ROWNUM > 1 GROUP BY F_INT ORDER BY F_INT;
SELECT F_INT, F_CHAR,COUNT(*) FROM ROWNUM_TEST_1 WHERE ROWNUM < 7 GROUP BY F_INT, F_CHAR ORDER BY F_INT,F_CHAR;
SELECT F_INT, F_CHAR,COUNT(*) FROM ROWNUM_TEST_1 WHERE ROWNUM > 1 GROUP BY F_INT, F_CHAR ORDER BY F_INT;
SELECT DISTINCT F_INT, F_CHAR FROM ROWNUM_TEST_1 WHERE ROWNUM < 7;
SELECT DISTINCT F_INT, F_CHAR FROM ROWNUM_TEST_1 WHERE ROWNUM > 1;

-- TEST JOIN
-- SELECT TT2.F_INT, TT2.F_CHAR FROM ROWNUM_TEST TT1 JOIN ROWNUM_TEST_1 TT2 ON TT1.ID = TT2.F_INT WHERE ROWNUM < 5 ORDER BY TT2.F_INT;
-- SELECT TT2.F_INT, TT2.F_CHAR FROM ROWNUM_TEST TT1 JOIN ROWNUM_TEST_1 TT2 ON TT1.ID = TT2.F_INT WHERE ROWNUM > 0 ORDER BY TT2.F_INT;
-- SELECT TT2.F_INT, TT2.F_CHAR FROM ROWNUM_TEST TT1 JOIN ROWNUM_TEST_1 TT2 ON TT1.ID = TT2.F_INT WHERE ROWNUM > 1;
-- TEST SUB_SELECT
SELECT * FROM (SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM < 7);
SELECT * FROM (SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM > 0);
SELECT * FROM (SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM > 1);
SELECT * FROM (SELECT * FROM ROWNUM_TEST_1) WHERE ROWNUM < 7;
SELECT * FROM (SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM < 7) WHERE ROWNUM < 5;
SELECT * FROM ROWNUM_TEST WHERE ID IN (SELECT F_INT FROM ROWNUM_TEST_1 WHERE ROWNUM < 7);
SELECT * FROM ROWNUM_TEST WHERE ID IN (SELECT F_INT FROM ROWNUM_TEST_1 WHERE ROWNUM > 0) ORDER BY ID;
SELECT * FROM ROWNUM_TEST WHERE ID IN (SELECT F_INT FROM ROWNUM_TEST_1 WHERE ROWNUM > 1);
SELECT * FROM ROWNUM_TEST WHERE ID IN (SELECT F_INT FROM ROWNUM_TEST_1) AND ROWNUM < 4 ORDER BY ID;
SELECT * FROM ROWNUM_TEST WHERE ID IN (SELECT F_INT FROM ROWNUM_TEST_1 WHERE ROWNUM < 7) AND ROWNUM < 4;
-- TEST UNION
SELECT * FROM ROWNUM_TEST WHERE ROWNUM < 4 UNION SELECT * FROM ROWNUM_TEST_1 ORDER BY 1,2;
SELECT * FROM ROWNUM_TEST UNION SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM < 7 ORDER BY 1,2;
SELECT * FROM ROWNUM_TEST WHERE ROWNUM < 4 UNION SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM < 7 ORDER BY 1,2;
SELECT * FROM ROWNUM_TEST WHERE ROWNUM < 4 UNION SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM > 0 ORDER BY 1,2;
SELECT * FROM ROWNUM_TEST WHERE ROWNUM < 4 UNION SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM > 1 ORDER BY 1,2;
SELECT * FROM ROWNUM_TEST WHERE ROWNUM < 4 UNION ALL SELECT * FROM ROWNUM_TEST_1;
SELECT * FROM ROWNUM_TEST UNION ALL SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM < 7;
SELECT * FROM ROWNUM_TEST WHERE ROWNUM < 4 UNION ALL SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM < 7;
SELECT * FROM ROWNUM_TEST WHERE ROWNUM < 4 UNION ALL SELECT * FROM ROWNUM_TEST_1 WHERE ROWNUM > 1;
DROP TABLE IF EXISTS rownum_test;
DROP TABLE IF EXISTS ROWNUM_TEST_1;
commit;

drop table if exists t_join_base_101;
drop table if exists t_join_base_102;
create table t_join_base_101(id int,c_int int not null,c_vchar varchar(100) not null,c_clob clob not null,c_blob blob not null,c_date date);
create table t_join_base_102(id int,c_int int not null,c_vchar varchar(100) not null,c_clob clob not null,c_blob blob not null,c_date date);

insert into t_join_base_101 values(1,1000,'abc123',lpad('123abc',50,'abc'),lpad('11100011',50,'1100'),to_timestamp(to_char('1800-01-01 10:51:47'),'yyyy-mm-dd hh24:mi:ss'));
insert into t_join_base_102 values(1,1000,'abc123',lpad('123abc',50,'abc'),lpad('11100011',50,'1100'),to_timestamp(to_char('1800-01-01 10:51:47'),'yyyy-mm-dd hh24:mi:ss'));
CREATE or replace procedure proc_insert(tname varchar,startall int,endall int) as
sqlst varchar(500);
BEGIN
  FOR i IN startall..endall LOOP
                sqlst := 'insert into ' || tname ||' select id+'||i||',c_int+'||i||',c_vchar||'||i||',c_clob||'||i||',c_blob'||',c_date from '||tname|| ' where id=1';
        execute immediate sqlst;
  END LOOP;
END;
/
exec proc_insert('t_join_base_101',1,10);
exec proc_insert('t_join_base_102',1,5);

select t1.c_int,t2.c_int,t3.c_int,1 from  t_join_base_101 t1 full join (t_join_base_101 t2 full join t_join_base_102 t3 on t2.c_vchar=t3.c_vchar) on t1.c_int>t2.c_int  and rownum in(select rownum from t_join_base_101) order by 1,2,3;

drop table if exists t_join_base_101;
drop table if exists t_join_base_102;
drop procedure proc_insert;
