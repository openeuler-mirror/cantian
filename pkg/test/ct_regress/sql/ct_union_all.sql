DROP TABLE IF EXISTS T_UNION_ALL_1;
DROP TABLE IF EXISTS T_UNION_ALL_2;
CREATE TABLE T_UNION_ALL_1 (F_INT1 INT, F_INT2 DECIMAL(20,0), F_CHAR CHAR(16), F_DATE DATE);
CREATE TABLE T_UNION_ALL_2 (F_INT1 INT, F_INT2 DECIMAL(20,0), F_CHAR CHAR(16), F_DATE DATE);

--EXPECT ERROR
SELECT * FROM T_UNION_ALL_1 UNION ALL SELECT * FROM T_UNION_ALL_2 ORDER BY F_INT1 ORDER BY F_INT1;
SELECT * FROM T_UNION_ALL_1 ORDER BY F_INT1 ORDER BY F_INT1 UNION ALL SELECT * FROM T_UNION_ALL_2;
SELECT F_INT1 FROM T_UNION_ALL_1 UNION ALL SELECT * FROM T_UNION_ALL_2;
SELECT * FROM T_UNION_ALL_1 UNION ALL SELECT F_INT1 FROM T_UNION_ALL_2;
SELECT F_INT1 FROM T_UNION_ALL_1 UNION ALL SELECT F_INT1,F_INT2 FROM T_UNION_ALL_2;
SELECT F_INT1,F_INT2 FROM T_UNION_ALL_1 UNION ALL SELECT F_INT1 FROM T_UNION_ALL_2;

--EMPTY RECORD
(SELECT F_INT1 FROM T_UNION_ALL_1 GROUP BY F_INT1) UNION ALL (SELECT F_INT1 FROM T_UNION_ALL_2 GROUP BY F_INT1) ORDER BY F_INT1 DESC;
SELECT * FROM T_UNION_ALL_1 UNION ALL SELECT * FROM T_UNION_ALL_2 ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_ALL_1) UNION ALL (SELECT * FROM T_UNION_ALL_2) ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_ALL_1) UNION ALL (SELECT * FROM T_UNION_ALL_2) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_ALL_1) UNION ALL (SELECT * FROM T_UNION_ALL_2) UNION ALL (SELECT * FROM T_UNION_ALL_1) ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_ALL_1) UNION ALL (SELECT * FROM T_UNION_ALL_2) UNION ALL (SELECT * FROM T_UNION_ALL_1) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_ALL_1 WHERE F_INT1 = 1) UNION ALL (SELECT * FROM T_UNION_ALL_2 WHERE F_INT2 = 3) UNION ALL (SELECT * FROM T_UNION_ALL_1) ORDER BY F_INT1,F_INT2 DESC;

INSERT INTO T_UNION_ALL_1 VALUES(1,2,'A','2017-12-11 14:08:00');
INSERT INTO T_UNION_ALL_1 VALUES(3,4,'C','2017-12-12 16:08:00');
INSERT INTO T_UNION_ALL_1 VALUES(1,3,'A','2017-12-11 14:18:00');
INSERT INTO T_UNION_ALL_1 VALUES(2,3,'B','2017-12-11 16:08:00');
INSERT INTO T_UNION_ALL_2 VALUES(4,2,'A','2017-12-11 14:08:00');
INSERT INTO T_UNION_ALL_2 VALUES(6,4,'C','2017-12-12 16:08:00');
INSERT INTO T_UNION_ALL_2 VALUES(4,3,'A','2017-12-11 14:18:00');
INSERT INTO T_UNION_ALL_2 VALUES(5,3,'B','2017-12-11 16:08:00');
COMMIT;

(SELECT F_INT1 FROM T_UNION_ALL_1 GROUP BY F_INT1) UNION ALL (SELECT F_INT1 FROM T_UNION_ALL_2 GROUP BY F_INT1) ORDER BY F_INT1 DESC;
SELECT * FROM T_UNION_ALL_1 UNION ALL SELECT * FROM T_UNION_ALL_2 ORDER BY F_INT1,F_INT2 DESC;
(SELECT F_INT1,F_INT2 FROM T_UNION_ALL_1) UNION ALL (SELECT F_INT1,F_INT2 FROM T_UNION_ALL_2 GROUP BY F_INT1,F_INT2) ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_ALL_1) UNION ALL (SELECT * FROM T_UNION_ALL_2) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_ALL_1) UNION ALL (SELECT * FROM T_UNION_ALL_2) UNION ALL (SELECT * FROM T_UNION_ALL_1) ORDER BY F_INT1,F_INT2 DESC;
(SELECT * FROM T_UNION_ALL_1) UNION ALL (SELECT * FROM T_UNION_ALL_2) UNION ALL (SELECT * FROM T_UNION_ALL_1) ORDER BY F_DATE DESC,F_INT1 DESC;
(SELECT * FROM T_UNION_ALL_1 WHERE F_INT1 = 1) UNION ALL (SELECT * FROM T_UNION_ALL_2 WHERE F_INT2 = 3) UNION ALL (SELECT * FROM T_UNION_ALL_1) ORDER BY F_INT1,F_INT2 DESC;

--TEST DATATYPE
SELECT F_INT1 FROM T_UNION_ALL_1 UNION ALL SELECT F_DATE FROM T_UNION_ALL_1 ORDER BY F_INT1;
SELECT F_CHAR FROM T_UNION_ALL_1 UNION ALL SELECT F_DATE FROM T_UNION_ALL_1 ORDER BY F_CHAR;
SELECT F_INT1 FROM T_UNION_ALL_1 UNION ALL SELECT F_INT2 FROM T_UNION_ALL_1 ORDER BY F_INT1;
SELECT F_INT1 FROM T_UNION_ALL_1 UNION ALL SELECT F_CHAR FROM T_UNION_ALL_1 ORDER BY F_INT1;
SELECT F_INT2 FROM T_UNION_ALL_1 UNION ALL SELECT F_CHAR FROM T_UNION_ALL_1 ORDER BY F_INT2;
SELECT F_INT1,F_INT2 FROM T_UNION_ALL_1 UNION ALL SELECT F_CHAR,F_INT2 FROM T_UNION_ALL_1 ORDER BY F_INT1,F_INT2;
SELECT F_INT1,F_INT2 FROM T_UNION_ALL_1 UNION ALL SELECT F_INT1,F_CHAR FROM T_UNION_ALL_1 ORDER BY F_INT1,F_INT2;
SELECT F_INT1,F_CHAR FROM T_UNION_ALL_1 UNION ALL SELECT F_INT1,F_INT2 FROM T_UNION_ALL_1 ORDER BY F_INT1,F_CHAR;
SELECT F_INT1,F_INT2 FROM T_UNION_ALL_1 UNION ALL SELECT F_CHAR,F_INT1 FROM T_UNION_ALL_1 ORDER BY F_INT1,F_INT2;
SELECT * FROM T_UNION_ALL_1 UNION ALL SELECT F_INT2,F_CHAR,F_INT1,F_DATE FROM T_UNION_ALL_1 ORDER BY F_INT1,F_INT2,F_CHAR;
SELECT F_INT2,F_CHAR,F_INT1,F_DATE FROM T_UNION_ALL_1 UNION ALL SELECT * FROM T_UNION_ALL_1 ORDER BY F_INT1,F_INT2,F_CHAR;


--DTS2018082211009
DROP TABLE IF EXISTS TEST_UNION_ALL_01;
DROP TABLE IF EXISTS TEST_UNION_ALL_02;
CREATE TABLE TEST_UNION_ALL_01(A INT,B INT);
INSERT INTO TEST_UNION_ALL_01 VALUES(0,1);
INSERT INTO TEST_UNION_ALL_01 VALUES(1,4);
INSERT INTO TEST_UNION_ALL_01 VALUES(2,2);
INSERT INTO TEST_UNION_ALL_01 VALUES(3,1);
INSERT INTO TEST_UNION_ALL_01 VALUES(4,2);
CREATE TABLE TEST_UNION_ALL_02(A INT,B INT);
INSERT INTO TEST_UNION_ALL_02 VALUES(0,1);
INSERT INTO TEST_UNION_ALL_02 VALUES(1,4);
INSERT INTO TEST_UNION_ALL_02 VALUES(4,2);
INSERT INTO TEST_UNION_ALL_02 VALUES(5,1);
INSERT INTO TEST_UNION_ALL_02 VALUES(6,4);

SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 LIMIT 1 UNION ALL SELECT * FROM TEST_UNION_ALL_02;  --syntax error
SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 LIMIT 1 UNION ALL SELECT * FROM TEST_UNION_ALL_02 LIMIT 3; --syntax error
(SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 ORDER BY A, B LIMIT 1) UNION ALL SELECT * FROM TEST_UNION_ALL_02 ORDER BY A, B LIMIT 3;   --OK
(SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 LIMIT 1) UNION ALL SELECT * FROM TEST_UNION_ALL_02 LIMIT 1 LIMIT 3;  --syntax error
(SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 ORDER BY A, B LIMIT 1) UNION ALL (SELECT * FROM TEST_UNION_ALL_02 ORDER BY A, B LIMIT 1) ORDER BY A, B LIMIT 3;  --OK
SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 UNION ALL SELECT * FROM TEST_UNION_ALL_02 ORDER BY A, B LIMIT 3;  --OK

(SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 ORDER BY A, B LIMIT 1) UNION ALL SELECT * FROM TEST_UNION_ALL_02 ORDER BY A, B;  --OK
SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 LIMIT 1 UNION ALL SELECT * FROM TEST_UNION_ALL_02;  --syntax error

SELECT * FROM ((SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 ORDER BY A, B LIMIT 1) UNION ALL SELECT * FROM TEST_UNION_ALL_02 ORDER BY A, B) TEMP ORDER BY A, B;  --OK
SELECT * FROM (SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 LIMIT 1 UNION ALL SELECT * FROM TEST_UNION_ALL_02) TEMP;  --syntax error

SELECT * FROM TEST_UNION_ALL_01 WHERE A IN (SELECT A FROM TEST_UNION_ALL_01 WHERE A > 2 LIMIT 1 UNION ALL SELECT A FROM TEST_UNION_ALL_02 WHERE A >3);  --syntax error

DROP TABLE IF EXISTS TEMPTBL;
CREATE TABLE TEMPTBL(A INT,B INT);
INSERT INTO TEMPTBL SELECT * FROM TEST_UNION_ALL_01 WHERE A > 2 LIMIT 1 UNION ALL SELECT * FROM TEST_UNION_ALL_02;  --syntax error

DROP TABLE TEMPTBL;
DROP TABLE TEST_UNION_ALL_02;
DROP TABLE TEST_UNION_ALL_01;

--TEST INSERT
DROP TABLE IF EXISTS T_UNION_ALL_1;
CREATE TABLE T_UNION_ALL_1 (F_INT1 INT, F_INT2 DECIMAL(20,0), F_CHAR CHAR(16), F_DATE DATE);
INSERT INTO T_UNION_ALL_1 VALUES(1,2,'A','2017-12-11 14:08:00');
INSERT INTO T_UNION_ALL_1 VALUES(3,4,'C','2017-12-12 16:08:00');
INSERT INTO T_UNION_ALL_1 (SELECT t1.F_INT1,t1.F_INT2,t1.F_CHAR,t1.F_DATE FROM T_UNION_ALL_1 t1) UNION ALL SELECT t1.F_INT1,t1.F_INT2,t1.F_CHAR,t1.F_DATE FROM T_UNION_ALL_1 t1;
SELECT * FROM T_UNION_ALL_1 ORDER BY 1;
DROP TABLE T_UNION_ALL_1;
--timestamp/date
drop table if exists t_time_20200226;
create table t_time_20200226(
id int not null,c_int int,c_real real,c_float float,c_decimal decimal,c_number number,
c_char char(10),c_vchar varchar(20) not null,c_vchar2 varchar2(100),c_clob clob,
c_long varchar(200),c_blob blob,c_raw raw(100),c_date date,c_timestamp timestamp);
insert into t_time_20200226 values(1,1000,100.123,100.456,100.789,100.123,'abc123','abcdefg',lpad('123abc',50,'abc'),lpad('123abc',50,'abc'),lpad('11100000',50,'1100'),lpad('11100001',50,'1100'),lpad('11100011',50,'1100'),to_timestamp(to_char('1800-01-01 10:51:47'),'yyyy-mm-dd hh24:mi:ss.ff6'),to_timestamp(to_char('1800-03-05 10:51:47.123456'),'yyyy-mm-dd hh24:mi:ss.ff6'));
commit;
select * from (select c_date from t_time_20200226 union all select c_timestamp from t_time_20200226) order by 1;
select * from (select c_timestamp from t_time_20200226 union all select c_date from t_time_20200226) order by 1;
drop table t_time_20200226;

-- union all left:merge join, union right:pivot
drop table if exists merge_join_union_t1;
drop table if exists merge_join_union_t2;
drop table if exists merge_join_union_t3;

create table merge_join_union_t1(id number(8), c_int number(8), c_str varchar(20));
create table merge_join_union_t2(id number(8), c_int number(8), c_str varchar(20));
create table merge_join_union_t3(id number(8), c_int number(8), c_str varchar(20));
insert into merge_join_union_t1 values(1,2,'test1');
insert into merge_join_union_t1 values(2,4,'test2');
insert into merge_join_union_t1 values(3,6,'test3');
insert into merge_join_union_t1 values(4,7,'test4');
insert into merge_join_union_t2 values(1,2,'test1');
insert into merge_join_union_t2 values(2,4,'test2');
insert into merge_join_union_t2 values(3,6,'test3');
insert into merge_join_union_t2 values(4,7,'test4');
insert into merge_join_union_t3 values(1,2,'test1');
insert into merge_join_union_t3 values(2,4,'test2');
insert into merge_join_union_t3 values(3,6,'test3');
insert into merge_join_union_t3 values(4,7,'test4');
commit;

(
select ref_0.c_int
from 
    merge_join_union_t1 ref_0
    inner join merge_join_union_t2 ref_1
    on ref_0.id > ref_1.id
order by ref_0.c_int
)
union all
(
 (select ref_3.c_int
  from 
    (merge_join_union_t3 pivot(
        min(c_int) as aggr_0
        for (c_str)
        in (('test1') as pexpr_0,
            ('test2') as pexpr_1
           )
        ) ref_2 
    ) left join 
    merge_join_union_t2 ref_3
    on 1=1
 )
 intersect
 (select 
    c_int
  from
    merge_join_union_t2 ref_4
  where id < 1
 )
);

drop table merge_join_union_t1;
drop table merge_join_union_t2;
drop table merge_join_union_t3;

-- vmc core
drop table if exists sort_pending_t1;
drop table if exists sort_pending_t2;
drop table if exists sort_pending_t3;

create table sort_pending_t1(c1 int, c2 int);
create table sort_pending_t2(c1 int, c2 int, c3 int, c4 int, c5 int);
create table sort_pending_t3(c1 int, c2 int);
insert into sort_pending_t1 values(1,2);
insert into sort_pending_t2 values(1,1,1,1,1);
insert into sort_pending_t2 values(2,2,2,1,1);
insert into sort_pending_t2 values(3,3,3,2,2);

(select
    case when 2 > all(select 3 as c1 from sort_pending_t1 ref_1) then null else null end as c2,
    null as c3
from
    sort_pending_t1 ref_0
order by 2
)
union all 
(
select 
    case when ref_2.c1 is not null then null else null end as c7,
    cast(null as varchar(5)) as c8
from
  ((sort_pending_t2 ref_2) cross join 
  ((select 
        ref_3.c1 as c5
    from
        sort_pending_t3 ref_3
    connect by  prior ref_3.c1 = ref_3.c2
   ) subq_1))
  full join ((sort_pending_t3 ref_4))
  on (ref_2.c2 = ref_4.c2)
order by ref_2.c1, ref_2.c2, ref_2.c3, ref_2.c4, subq_1.c5
);

drop table sort_pending_t1;
drop table sort_pending_t2;
drop table sort_pending_t3;