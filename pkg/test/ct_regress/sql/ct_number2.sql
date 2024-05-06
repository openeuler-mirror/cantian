drop user if exists number2_tester cascade;
create user number2_tester identified by 'Changeme_123';
grant dba to number2_tester;
conn number2_tester/Changeme_123@127.0.0.1:1611

--- overflow/underflow test
select exp(295); --exp() return value is number
select exp(294);
select exp(-292);
select exp(-293);
SELECT TANH(50) ;
select TANH(-50);

drop table if exists number2_test_overflow;
create table number2_test_overflow(id number2);
insert into number2_test_overflow values(cast('9.999999999999999999999999999999999999999E+125' as number2));
select * from  number2_test_overflow;
select id - 1E125 from  number2_test_overflow;
drop table if exists number2_test_overflow;

select to_char(cast('9.999999999999999999999999999999999999999E+125' as number2)) from dual;
select cast('9.9999999999999999999999999999999999999999E+125' as number2) from dual;
select cast('9.999999999999999999999999999999999999999E-131' as number2), to_char(cast('9.999999999999999999999999999999999999999E-131' as number2)) from dual;

select to_char(cast('1234567890123456789012345678901234567890123456789012345678901234567890' as number2) * cast('1234567890123456789012345678901234567890123456789012345678' as number2)) from dual;
select to_char(cast('1234567890123456789012345678901234567890123456789012345678901234567890' as number2) * cast('123456789012345678901234567890123456789012345678901234567' as number2)) from dual;
select to_char(cast('9.99999999999999999999999999999999999999999E-125' as number2) * cast('1E-130' as number2)) from dual;
select to_char(cast('9.9999999999999999999999999999999999999E+125' as number2) * cast('1E-127' as number2)) from dual;
select to_char(cast('9.9999999999999999999999999999999999999999E-125' as number2) * cast('1E-6' as number2)) from dual;
select 3.333333333333333333333333333333 * 3.03030303030303030303030303030304;

select to_char(cast('9.999999999999999999999999999E+125' as number2) + cast('1' as number2)) from dual;
select to_char(cast('9.99999999999E+125' as number2) + cast('1e125' as number2)) from dual;

select to_char(cast('1234567890123456789012345678901234567895123456789012345678901234567890' as number2) - cast('1234567890123456789012345678901234567895123456789012345678901234567891' as number2)) from dual;
select to_char(cast('1E-130' as number2) - cast('1.0E-129' as number2)) from dual;
select to_char(cast('1E-130' as number2) - cast('1.0E-131' as number2)) from dual;
select to_char(cast('9.9999999999999999E-130' as number2) - cast('-0.00010E-130' as number2)) from dual;

select 1/(8E-126) from dual;
select to_char(cast('9.999999999999999999999999999999999999999E+125' as number2) / cast('1.0E-130' as number2)) from dual;

--csf
drop table if exists number2_test_csf;
create table number2_test_csf(f1 int, f2 number2(12, 5), f3 DECIMAL(38, 0), f4 int) format csf;
alter table number2_test_csf add constraint f2_check check(f2 < 2);
insert into number2_test_csf values(1, 1.25765, 444, 1);
insert into number2_test_csf values(0, 0,444, 1);
insert into number2_test_csf values(0, NULL, 0, 0);
insert into number2_test_csf values(0, 2.2, 1.25765, 444);
insert into number2_test_csf values(3, 1.25765, NULL, 444);
select * from number2_test_csf;
update number2_test_csf set f2 = 1.2;
select * from number2_test_csf;
drop table if exists number2_test_csf;

--create tabel/orderby/index/update
drop table if exists number2_orderby;
CREATE TABLE  number2_orderby(
     COL_1 real,
     COL_2 double,
     COL_3 float,
     COL_4 number2(12,6),
     COL_5 number2,
     COL_6 number2,
     PRIMARY KEY (COL_6) using index
);
begin
    for i in 1..10 loop
      insert into number2_orderby values(
      i+3.1415926,
      i+445.255,
      3.1415926-i*2,
      98*0.99*i, 
      99*1.01*i,
      -98*0.99*i
      );
      commit;
    end loop;
end;
/
update number2_orderby set COL_5 = 0.08;
create index number2_index on number2_orderby(COL_4);
select COL_4 from number2_orderby order by COL_4;
select COL_4 from number2_orderby order by COL_4 desc limit 2;
drop index number2_index on number2_orderby;
select (select COL_4||dummy from dual) from number2_orderby order by COL_4 desc limit 2;
select (select COL_3||dummy from dual) from number2_orderby order by COL_4;
drop table number2_orderby;

--aggr
drop table if exists t_aggr_number2;
create table t_aggr_number2(f1 number2(20,10), C_VARCHAR VARCHAR(2000));
insert into t_aggr_number2 values(9912334.997, 43244354354354);
insert into t_aggr_number2 values(null, 564654646554);
insert into t_aggr_number2 values(9912334.999, NULL);
insert into t_aggr_number2 values(9912334.998, 345344443);
select count(f1) from t_aggr_number2;
select sum(f1) from t_aggr_number2;
select max(f1) from t_aggr_number2;
select min(f1) from t_aggr_number2;
select avg(f1) from t_aggr_number2;
select distinct sum(c_varchar + f1) from t_aggr_number2;
select distinct max(c_varchar::number2(38, -6)) from t_aggr_number2;
select distinct min(c_varchar::number2(38, -5)) from t_aggr_number2;
drop table t_aggr_number2;
commit;

----array
select array[null, '1234567.89', 1234567.89, null]::number2(12,1)[] from dual;

drop table if exists array_number2_1;
create table array_number2_1(a number2(12,3)[]);
desc array_number2_1;
insert into array_number2_1 values('{null,1234567.89,1234567.89,null}');
insert into array_number2_1 values(array[null, '1234567.89', 1234567.89, null]);
insert into array_number2_1 values('{null,12347.89,12567.9,null}');
insert into array_number2_1 values(array[null, '1234567.89', 13.89, null]);
select * from array_number2_1;
select to_char(a[3]) from array_number2_1;
select to_char(a) from array_number2_1;
drop table if exists array_number2_1;


set serveroutput on
drop table if exists array_number2_2;
create table array_number2_2 (COL1 int,COL2 INTERVAL YEAR TO MONTH[],COL3 number2[]);
insert into array_number2_2 values(1,array[(INTERVAL '12' YEAR(4)) , (INTERVAL '-99' YEAR(3)) , (INTERVAL '0' YEAR(2))],array[-0.9E124 , 1.0E124 -1 , -89.0000001]);
insert into array_number2_2 values(2,array[(INTERVAL '12' YEAR(4)) , (INTERVAL '-99' YEAR(3)) , (INTERVAL '0' YEAR(2))],array[-1.0E124 , 1.0E28 , -1-128]);
commit;

CREATE OR REPLACE PROCEDURE PROC_ARRAY_NUMBER2(P1 out number2 )
AS
V1 number2;
BEGIN
	select COL3[2] into V1 from array_number2_2 where COL1 = 2;
	P1:= V1;
	dbe_output.print_line(P1);
EXCEPTION WHEN NO_DATA_FOUND THEN dbe_output.print_line('NO_DATA_FOUND');
END;
/

declare
  p number2;
begin
    begin PROC_ARRAY_NUMBER2(p); end;
end;
/
drop table if exists array_number2_2;
drop PROCEDURE PROC_ARRAY_NUMBER2;
set serveroutput off

--COLLECTION
set serveroutput on
DROP TYPE IF EXISTS number2_test_table;
DECLARE
    type number2_test_table is table of number2;
    var_test number2_test_table := number2_test_table(123, 234, 345); 
BEGIN
    var_test(2) := 8E30;
    DBE_OUTPUT.PRINT_LINE(var_test(2));
    var_test.delete(2,3);
    DBE_OUTPUT.PRINT_LINE(var_test.count);
END;
/
DROP TYPE IF EXISTS number2_test_table;

DROP TYPE IF EXISTS number2_test_varry;
DECLARE
    type number2_test_varry is varray(20) of number2;
    var_test number2_test_varry := number2_test_varry(123, 234, 345); 
BEGIN
    var_test(2) := 8E-30;
    DBE_OUTPUT.PRINT_LINE(var_test(2));
    DBE_OUTPUT.PRINT_LINE(var_test.count);
END;
/
DROP TYPE IF EXISTS number2_test_varry;

DROP TYPE IF EXISTS number2_type_asso;
DECLARE
    TYPE number2_type_asso IS TABLE OF number2 INDEX BY int; 
    var_asso number2_type_asso;
BEGIN
    var_asso(4) := 1.2E30;
    var_asso(3) := -1.2E30;
    DBE_OUTPUT.PRINT_LINE(var_asso(3));
END;
/
DROP TYPE IF EXISTS number2_type_asso;

--record
DROP TYPE IF EXISTS number2_type_record;
DECLARE
    TYPE number2_type_record IS RECORD(rec1 int, rec2 number2);    
    var_rec number2_type_record;
BEGIN
    var_rec.rec1 := 1;
    var_rec.rec2 := 1E2;
    DBE_OUTPUT.PRINT_LINE(var_rec.rec1 + var_rec.rec2);
END;
/
DROP TYPE IF EXISTS number2_type_record;


--object
DROP TYPE IF EXISTS number2_obj_type;
CREATE OR REPLACE TYPE number2_obj_type FORCE AS OBJECT(f1 number2, f2 int) NOT FINAL;
/
DECLARE
    var_obj number2_obj_type;
BEGIN
    var_obj := number2_obj_type(5E3, 2);
    DBE_OUTPUT.PRINT_LINE(var_obj.f1 + var_obj.f2);
END;
/
DROP TYPE IF EXISTS number2_obj_type;

--%type,%ROWTYPE
DROP table IF EXISTS number2_type_test;
CREATE TABLE number2_type_test(f1 number2, f2 int); 
INSERT INTO number2_type_test VALUES(1E2, 456);
COMMIT; 

DECLARE
cv      SYS_REFCURSOR;
v_f1    number2_type_test.f1%TYPE;
v_f2    number2_type_test.f2%TYPE;
v_test  number2_type_test%ROWTYPE; 
BEGIN
OPEN cv FOR SELECT f1,f2 FROM number2_type_test ORDER BY f1;
LOOP
FETCH cv INTO v_f1, v_f2;
EXIT WHEN cv%NOTFOUND;
DBE_OUTPUT.PRINT_LINE(v_f1 + v_f2);
END LOOP;
CLOSE cv;
END;
/
DROP table IF EXISTS number2_type_test;

drop TYPE if exists number2_c_n_s force;
drop TYPE if exists number2_c_v_n force;
drop TYPE if exists number2_r_s_r_n_v force;
drop TYPE if exists number2_c_v_r force;
drop TYPE if exists number2_c_n_r force;
create type number2_c_n_s is table of number2;
/   
create type number2_c_v_n is varray(3) of number2_c_n_s;
/   
create type number2_r_s_r_n_v FORCE AS OBJECT(a number2, b number2_c_v_n);
/      
create type number2_c_v_r is varray(3) of number2_r_s_r_n_v;
/      
create type number2_c_n_r is table of number2_r_s_r_n_v;
/
DECLARE
    v1 number2_c_n_s := number2_c_n_s(123, 456, 789);
    v2 number2_c_v_n := number2_c_v_n(v1, number2_c_n_s(111, 222, 333));
    v3 number2_r_s_r_n_v := number2_r_s_r_n_v(1, v2);
    v4 number2_c_v_r := number2_c_v_r(v3, v3);
    v5 number2_c_n_r := number2_c_n_r(v3, v3, v3);
BEGIN
    dbe_output.print_line(v5(1).b(1)(1));
	v4 :=null;
	if v4 is NULL then
      dbe_output.print_line('v4' ||' is null');
	end if;
    END;
/
drop TYPE if exists number2_c_n_s force;
drop TYPE if exists number2_c_v_n force;
drop TYPE if exists number2_r_s_r_n_v force;
drop TYPE if exists number2_c_v_r force;
drop TYPE if exists number2_c_n_r force;
set serveroutput off

--alter table
drop table if exists alt_dec_number2;
create table alt_dec_number2(id int, c1 decimal, c2 number, c3 number(5,3), c4 number(5, -2));
insert into alt_dec_number2 values(1, 1.123123123123, 1.123456789, 1.001, 123456.812839);
alter table alt_dec_number2 modify c1 number2;
drop table if exists alt_dec_number2;

drop table if exists alt_dec_number2_2;
create table alt_dec_number2_2(id int, c1 decimal, c2 number2, c3 number2(5,3), c4 number(5, -2));
ALTER TABLE alt_dec_number2_2 ADD (CONSTRAINT alt_dec_number2_2_CONSTRAINT UNIQUE(c2));
insert into alt_dec_number2_2 values(1, 1.123123123123, 1.123456789, 1.001, 123456.812839);
insert into alt_dec_number2_2 values(2, 1.123123123123, 1.123456789, 2.0022, 123456.812839);
insert into alt_dec_number2_2 values(2, 1.123123123123, 0.123456789, 2.0022, 123456.812839);
ALTER TABLE alt_dec_number2_2 drop CONSTRAINT alt_dec_number2_2_CONSTRAINT;

insert into alt_dec_number2_2 values(3, 1.123123123123, 1.123456789, 333.0033, 123456.812839);
create index alt_table_index on alt_dec_number2_2(c3);
alter table alt_dec_number2_2 modify c2 number;
alter table alt_dec_number2_2 modify c3 number2(7,4);
alter table alt_dec_number2_2 modify c3 number2(5,1);
ALTER TABLE alt_dec_number2_2 ADD COLUMN c5 NUMBER2 DEFAULT 110 NOT NULL; 
alter table alt_dec_number2_2 drop c5;
select * from alt_dec_number2_2;
drop table if exists alt_dec_number2_2;

--analyze
drop table if exists analyze_number2;
create table analyze_number2(a number2);
-- 15
insert into analyze_number2 values(12312.121);
insert into analyze_number2 values(12312.122);
insert into analyze_number2 values(12312.122);
insert into analyze_number2 values(12312.123);
insert into analyze_number2 values(12312.123);
insert into analyze_number2 values(12312.123);
insert into analyze_number2 values(12312.124);
insert into analyze_number2 values(12312.124);
insert into analyze_number2 values(12312.124);
insert into analyze_number2 values(12312.124);
insert into analyze_number2 values(12312.125);
insert into analyze_number2 values(12312.125);
insert into analyze_number2 values(12312.125);
insert into analyze_number2 values(12312.125);
insert into analyze_number2 values(12312.125);
analyze table analyze_number2 compute statistics;
select ENDPOINT_NUMBER, ENDPOINT_VALUE, ENDPOINT_ACTUAL_VALUE from MY_HISTOGRAMS where TABLE_NAME ='ANALYZE_NUMBER2' order by ENDPOINT_NUMBER;

delete from analyze_number2 where a = 12312.125;
call dbe_stats.collect_table_stats('NUMBER2_TESTER','ANALYZE_NUMBER2');
select ENDPOINT_NUMBER, ENDPOINT_VALUE, ENDPOINT_ACTUAL_VALUE from MY_HISTOGRAMS where TABLE_NAME ='ANALYZE_NUMBER2' order by ENDPOINT_NUMBER;
drop table analyze_number2;

--partition/index
drop table if exists number2_part_1;
drop index if exists idx_number2_part_1 on number2_part_1;
create table number2_part_1(f1 number2)
PARTITION BY RANGE(f1)
(
 PARTITION p1 values less than(10),
 PARTITION p2 values less than(20),
 PARTITION p3 values less than(30),
 PARTITION p4 values less than(maxvalue)
) crmode row;
create index idx_number2_part_1 on number2_part_1(f1) local
(
partition p1,
partition p2,
partition p3,
partition p4
);
insert into number2_part_1 values (1E-30);
insert into number2_part_1 values (1E50);
select * from number2_part_1 partition (p1);
select * from number2_part_1 partition (p4);

drop table if exists number2_part_1;
drop index if exists idx_number2_part_1 on number2_part_1;

drop table if exists number2_part_2;
drop index if exists idx_number2_part_2 on number2_part_2;
create table number2_part_2(f1 number2, f2 number2)
PARTITION BY RANGE(f1)
(
 PARTITION p1 values less than(10),
 PARTITION p2 values less than(20),
 PARTITION p3 values less than(30),
 PARTITION p4 values less than(maxvalue)
) crmode row;
create index idx_number2_part_2 on number2_part_2(f1, f2);
insert into number2_part_2 values (1E-30, 1E-31);
insert into number2_part_2 values (1E-32, 1E31);
alter table number2_part_2 split partition p1 at(5.25) into (partition p1_f, partition p1_r);
insert into number2_part_2 values (7, 1E-31);
select * from number2_part_2 partition(p1_r);
select * from number2_part_2 order by 1,2;
drop table if exists number2_part_2;
drop index if exists idx_number2_part_2 on number2_part_2;


drop table if exists number2_part_3;
create table number2_part_3(f1 number2, f2 number2)
PARTITION BY hash(f1) SUBPARTITION BY RANGE(f2)
(
PARTITION p1
(
SUBPARTITION PART_11 VALUES LESS THAN(20),
SUBPARTITION PART_12 VALUES LESS THAN(70),
SUBPARTITION PART_13 VALUES LESS THAN(MAXVALUE)
),
PARTITION p2
(
SUBPARTITION PART_21 VALUES LESS THAN(1E-5),
SUBPARTITION PART_22 VALUES LESS THAN(1E50),
SUBPARTITION PART_23 VALUES LESS THAN(MAXVALUE)
),
PARTITION p3
) crmode page;

begin
    for i in 1..20 loop
      insert into number2_part_3 values( 3.1415926-i*2, 98*0.99*i);
      commit;
    end loop;
end;
/
select count(*) from number2_part_3 partition(p1);
select count(*) from number2_part_3 subpartition(PART_22);
drop table if exists number2_part_3;


drop table if exists number2_part_4;
create table number2_part_4(f1 int, f2 bigint, f3 number2(38, 5), f4 DECIMAL(38, 0))
PARTITION BY RANGE(f3)
INTERVAL(10)
(
PARTITION number2_part_4_p1 values less than(10)
)format csf;
create index idx_number2_part_4 on number2_part_4(f3) local;
insert into number2_part_4 values(1,2,3.256,444);
insert into number2_part_4 values(1,2,33,444);
insert into number2_part_4 values(1,2,333,444);
commit;

 select PARTITION_COUNT from MY_PART_TABLES where TABLE_NAME = upper('number2_part_4');
select * from number2_part_4 partition(number2_part_4_p1);
drop table if exists number2_part_4;


drop table if exists number2_part_5;
create table number2_part_5(f1 int, f2 bigint, f3 number2(10, 5), f4 number2(12, 6))
PARTITION BY list(f3) SUBPARTITION BY LIST(f4) 
(
PARTITION number2_part_5_p1 VALUES(1.01, 1.02, 1.03)
(
SUBPARTITION number2_part_5_p11 VALUES(2.01, 2.02, 2.03),
SUBPARTITION number2_part_5_p12 VALUES(2.04, 2.05, 2.06)
),
PARTITION number2_part_5_p2 VALUES(1.04, 1.05, 1.06)
(
SUBPARTITION number2_part_5_p21 VALUES(2.01, 2.02, 2.03),
SUBPARTITION number2_part_5_p22 VALUES(2.04, 2.05, 2.06)
)
);
insert into number2_part_5 values(1,2,1.01,2.02);
insert into number2_part_5 values(1,2,1.05,2.02);
insert into number2_part_5 values(1,2,1.08,3.26);
insert into number2_part_5 values(1,2,1.03,3.26);
commit;
select * from number2_part_5 partition(number2_part_5_p1);
select * from number2_part_5 subpartition(number2_part_5_p21);
drop table if exists number2_part_5;


drop table if exists number2_part_6;
create table number2_part_6(f1 number2(10, 5), f2 number2(12, 6))
PARTITION BY hash(f1) SUBPARTITION BY hash(f2) 
(
PARTITION number2_part_6_p1
(
SUBPARTITION number2_part_6_p11,
SUBPARTITION number2_part_6_p12
),
PARTITION number2_part_6_p2
(
SUBPARTITION number2_part_6_p21,
SUBPARTITION number2_part_6_p22
),
PARTITION number2_part_6_p3
(
SUBPARTITION number2_part_6_p31,
SUBPARTITION number2_part_6_p32
)
);
begin
    for i in 1..20 loop
      insert into number2_part_6 values(i * 1.23, 98*0.99*i);
      commit;
    end loop;
end;
/
commit;
select count(*) from number2_part_6 partition(number2_part_6_p1);
select count(*) from number2_part_6 subpartition(number2_part_6_p21);
select count(*) from number2_part_6 subpartition(number2_part_6_p22);
alter table number2_part_6 modify partition number2_part_6_p2 coalesce subpartition;
select count(*) from number2_part_6 subpartition(number2_part_6_p21);
alter table number2_part_6 modify partition number2_part_6_p2 add subpartition number2_part_6_p23;
select count(*) from number2_part_6 subpartition(number2_part_6_p21);
drop table if exists number2_part_6;

--package
drop package if exists number2_pack1;
create or replace package number2_pack1 is
function f2 return number2;
end;
/
create or replace package body number2_pack1 is
function f2 return number2 
as
a number2;
begin
a:= 1;
return(a);
end f2;
end number2_pack1;
/
select object_name,object_type from my_procedures where object_name='NUMBER2_PACK1';
drop package if exists number2_pack1;

--function
select '9223371000000000000.005'::number2::bigint from dual;
select cast(45::int as number2(10,0));
select convert(45::int, number2(10,0));
select convert('1.01E5', number2(10,0));
select abs(-1.0123564E5::number2(10,0));
select * from dual where abs(-1.0123564E5::number2(10,0)) = '101236';
select cast('1231233413.123123213E100' as number2)||'e213213', to_char(cast('1231233413.123123213E100' as number2))||'e213213' from dual;
select to_date(20091001000000::number2);
select to_blob(122::NUMBER);
select decode(-1.0123564E5::number2(10,0), -1.01236E5, array[11.11, 22.22], array[2.0e+129, 3.0e+129]);
select cast(null as number2) from dual;

--compare
drop table if exists number2_cmp_t;
create table number2_cmp_t
(
    f1 integer, f2 binary_uint32, f3 bigint, f4 binary_double, f5 double, f6 float, f7 real, f8 number(12,3), f9 decimal(20,5), f10 char(30), f11 nchar(30), f12 varchar(30), 
    f13 varchar2(30), f14 nvarchar(30), f15 date, f16 datetime, f17 timestamp, f18 timestamp(3) with time zone, f19 timestamp(3) with local time zone, f20 boolean, 
    f21 interval year(4) to month, f22 interval day(7) to second(6), f23 int[], f24 binary(20), f25 varbinary(20), f26 raw(100), f27 clob, f28 blob, f29 image, f30 number(18,3)
);

select f1 from number2_cmp_t where f1 = f30;
select f1 from number2_cmp_t where f2 = f30;
select f1 from number2_cmp_t where f3 = f30;
select f1 from number2_cmp_t where f4 = f30;
select f1 from number2_cmp_t where f5 = f30;
select f1 from number2_cmp_t where f6 = f30;
select f1 from number2_cmp_t where f7 = f30;
select f1 from number2_cmp_t where f8 = f30;
select f1 from number2_cmp_t where f9 = f30;
select f1 from number2_cmp_t where f10 = f30;
select f1 from number2_cmp_t where f12 = f30;
select f1 from number2_cmp_t where f15 = f30;
select f1 from number2_cmp_t where f17 = f30;
select f1 from number2_cmp_t where f18 = f30;
select f1 from number2_cmp_t where f19 = f30;
select f1 from number2_cmp_t where f20 = f30;
select f1 from number2_cmp_t where f21 = f30;
select f1 from number2_cmp_t where f22 = f30;
select f1 from number2_cmp_t where f23 = f30;
select f1 from number2_cmp_t where f24 = f30;
select f1 from number2_cmp_t where f25 = f30;
select f1 from number2_cmp_t where f26 = f30;
select f1 from number2_cmp_t where f27 = f30;
select f1 from number2_cmp_t where f28 = f30;
select f1 from number2_cmp_t where f29 = f30;
drop table number2_cmp_t;

drop table if exists test_number2_add_timeltz;
CREATE TABLE test_number2_add_timeltz 
(
  "COL_INT_UNSIGNED" NUMBER2(38) NOT NULL,
  "COL_TIMESTAMP4" TIMESTAMP(6) WITH LOCAL TIME ZONE
);
INSERT INTO test_number2_add_timeltz ("COL_INT_UNSIGNED","COL_TIMESTAMP4") values (1,'2008-08-01 00:00:00.000000');
select col_int_unsigned+col_timestamp4,col_timestamp4  from test_number2_add_timeltz;
drop table test_number2_add_timeltz;


--bind para
CREATE OR REPLACE FUNCTION get_number2(acc_no IN NUMBER2)
   RETURN NUMBER2
   IS acc_bal NUMBER2(11,2);
   BEGIN
      acc_bal := acc_no;
      RETURN(acc_bal);
    END get_number2;
/

select get_number2(1) from dual;
select get_number2(2::int) from dual;
select get_number2(6.556::real)::int from dual;
drop function get_number2;

drop table if exists for_number2_array;
create table for_number2_array
(
c1 INT
);
begin
	for i in 1 .. 100 loop
		insert into for_number2_array values(i);
	end loop;
end;
/
create or replace function func_numer2_array(a number2[],n int) return number2
as
b number2;
begin
	b:=a[3]-n;
	return b;
end;
/
select func_numer2_array(array_agg(c1),9) from for_number2_array;
drop function func_numer2_array;
drop table if exists for_number2_array;

--expression:add sub mul div
DROP TABLE if exists number2_data;
CREATE TABLE number2_data (id int, val number2(38,10));
DROP TABLE if exists number2_exp_add;
CREATE TABLE number2_exp_add (id1 int, id2 int, expected number2(38,10));
DROP TABLE if exists number2_exp_sub;
CREATE TABLE number2_exp_sub (id1 int, id2 int, expected number2(38,10));
DROP TABLE if exists number2_exp_div;
CREATE TABLE number2_exp_div (id1 int, id2 int, expected number2(38,10));
DROP TABLE if exists number2_exp_mul;
CREATE TABLE number2_exp_mul (id1 int, id2 int, expected number2(38,10));
DROP TABLE if exists number2_result;
CREATE TABLE number2_result (id1 int, id2 int, result number2(38,10));

INSERT INTO number2_exp_add VALUES (0,0,'0');
INSERT INTO number2_exp_sub VALUES (0,0,'0');
INSERT INTO number2_exp_mul VALUES (0,0,'0');
INSERT INTO number2_exp_div VALUES (0,0,'NaN');
INSERT INTO number2_exp_add VALUES (0,1,'0');
INSERT INTO number2_exp_sub VALUES (0,1,'0');
INSERT INTO number2_exp_mul VALUES (0,1,'0');
INSERT INTO number2_exp_div VALUES (0,1,'NaN');
INSERT INTO number2_exp_add VALUES (0,2,'-34338492.215397047');
INSERT INTO number2_exp_sub VALUES (0,2,'34338492.215397047');
INSERT INTO number2_exp_mul VALUES (0,2,'0');
INSERT INTO number2_exp_div VALUES (0,2,'0');
INSERT INTO number2_exp_add VALUES (0,3,'4.31');
INSERT INTO number2_exp_sub VALUES (0,3,'-4.31');
INSERT INTO number2_exp_mul VALUES (0,3,'0');
INSERT INTO number2_exp_div VALUES (0,3,'0');
INSERT INTO number2_exp_add VALUES (0,4,'7799461.4119');
INSERT INTO number2_exp_sub VALUES (0,4,'-7799461.4119');
INSERT INTO number2_exp_mul VALUES (0,4,'0');
INSERT INTO number2_exp_div VALUES (0,4,'0');
INSERT INTO number2_exp_add VALUES (0,5,'16397.038491');
INSERT INTO number2_exp_sub VALUES (0,5,'-16397.038491');
INSERT INTO number2_exp_mul VALUES (0,5,'0');
INSERT INTO number2_exp_div VALUES (0,5,'0');
INSERT INTO number2_exp_add VALUES (0,6,'93901.57763026');
INSERT INTO number2_exp_sub VALUES (0,6,'-93901.57763026');
INSERT INTO number2_exp_mul VALUES (0,6,'0');
INSERT INTO number2_exp_div VALUES (0,6,'0');
INSERT INTO number2_exp_add VALUES (0,7,'-83028485');
INSERT INTO number2_exp_sub VALUES (0,7,'83028485');
INSERT INTO number2_exp_mul VALUES (0,7,'0');
INSERT INTO number2_exp_div VALUES (0,7,'0');
INSERT INTO number2_exp_add VALUES (0,8,'74881');
INSERT INTO number2_exp_sub VALUES (0,8,'-74881');
INSERT INTO number2_exp_mul VALUES (0,8,'0');
INSERT INTO number2_exp_div VALUES (0,8,'0');
INSERT INTO number2_exp_add VALUES (0,9,'-24926804.045047420');
INSERT INTO number2_exp_sub VALUES (0,9,'24926804.045047420');
INSERT INTO number2_exp_mul VALUES (0,9,'0');
INSERT INTO number2_exp_div VALUES (0,9,'0');
INSERT INTO number2_exp_add VALUES (1,0,'0');
INSERT INTO number2_exp_sub VALUES (1,0,'0');
INSERT INTO number2_exp_mul VALUES (1,0,'0');
INSERT INTO number2_exp_div VALUES (1,0,'NaN');
INSERT INTO number2_exp_add VALUES (1,1,'0');
INSERT INTO number2_exp_sub VALUES (1,1,'0');
INSERT INTO number2_exp_mul VALUES (1,1,'0');
INSERT INTO number2_exp_div VALUES (1,1,'NaN');
INSERT INTO number2_exp_add VALUES (1,2,'-34338492.215397047');
INSERT INTO number2_exp_sub VALUES (1,2,'34338492.215397047');
INSERT INTO number2_exp_mul VALUES (1,2,'0');
INSERT INTO number2_exp_div VALUES (1,2,'0');
INSERT INTO number2_exp_add VALUES (1,3,'4.31');
INSERT INTO number2_exp_sub VALUES (1,3,'-4.31');
INSERT INTO number2_exp_mul VALUES (1,3,'0');
INSERT INTO number2_exp_div VALUES (1,3,'0');
INSERT INTO number2_exp_add VALUES (1,4,'7799461.4119');
INSERT INTO number2_exp_sub VALUES (1,4,'-7799461.4119');
INSERT INTO number2_exp_mul VALUES (1,4,'0');
INSERT INTO number2_exp_div VALUES (1,4,'0');
INSERT INTO number2_exp_add VALUES (1,5,'16397.038491');
INSERT INTO number2_exp_sub VALUES (1,5,'-16397.038491');
INSERT INTO number2_exp_mul VALUES (1,5,'0');
INSERT INTO number2_exp_div VALUES (1,5,'0');
INSERT INTO number2_exp_add VALUES (1,6,'93901.57763026');
INSERT INTO number2_exp_sub VALUES (1,6,'-93901.57763026');
INSERT INTO number2_exp_mul VALUES (1,6,'0');
INSERT INTO number2_exp_div VALUES (1,6,'0');
INSERT INTO number2_exp_add VALUES (1,7,'-83028485');
INSERT INTO number2_exp_sub VALUES (1,7,'83028485');
INSERT INTO number2_exp_mul VALUES (1,7,'0');
INSERT INTO number2_exp_div VALUES (1,7,'0');
INSERT INTO number2_exp_add VALUES (1,8,'74881');
INSERT INTO number2_exp_sub VALUES (1,8,'-74881');
INSERT INTO number2_exp_mul VALUES (1,8,'0');
INSERT INTO number2_exp_div VALUES (1,8,'0');
INSERT INTO number2_exp_add VALUES (1,9,'-24926804.045047420');
INSERT INTO number2_exp_sub VALUES (1,9,'24926804.045047420');
INSERT INTO number2_exp_mul VALUES (1,9,'0');
INSERT INTO number2_exp_div VALUES (1,9,'0');
INSERT INTO number2_exp_add VALUES (2,0,'-34338492.215397047');
INSERT INTO number2_exp_sub VALUES (2,0,'-34338492.215397047');
INSERT INTO number2_exp_mul VALUES (2,0,'0');
INSERT INTO number2_exp_div VALUES (2,0,'NaN');
INSERT INTO number2_exp_add VALUES (2,1,'-34338492.215397047');
INSERT INTO number2_exp_sub VALUES (2,1,'-34338492.215397047');
INSERT INTO number2_exp_mul VALUES (2,1,'0');
INSERT INTO number2_exp_div VALUES (2,1,'NaN');
INSERT INTO number2_exp_add VALUES (2,2,'-68676984.430794094');
INSERT INTO number2_exp_sub VALUES (2,2,'0');
INSERT INTO number2_exp_mul VALUES (2,2,'1179132047626883.596862135856320209');
INSERT INTO number2_exp_div VALUES (2,2,'1.00000000000000000000');
INSERT INTO number2_exp_add VALUES (2,3,'-34338487.905397047');
INSERT INTO number2_exp_sub VALUES (2,3,'-34338496.525397047');
INSERT INTO number2_exp_mul VALUES (2,3,'-147998901.44836127257');
INSERT INTO number2_exp_div VALUES (2,3,'-7967167.56737750510440835266');
INSERT INTO number2_exp_add VALUES (2,4,'-26539030.803497047');
INSERT INTO number2_exp_sub VALUES (2,4,'-42137953.627297047');
INSERT INTO number2_exp_mul VALUES (2,4,'-267821744976817.8111137106593');
INSERT INTO number2_exp_div VALUES (2,4,'-4.40267480046830116685');
INSERT INTO number2_exp_add VALUES (2,5,'-34322095.176906047');
INSERT INTO number2_exp_sub VALUES (2,5,'-34354889.253888047');
INSERT INTO number2_exp_mul VALUES (2,5,'-563049578578.769242506736077');
INSERT INTO number2_exp_div VALUES (2,5,'-2094.18866914563535496429');
INSERT INTO number2_exp_add VALUES (2,6,'-34244590.637766787');
INSERT INTO number2_exp_sub VALUES (2,6,'-34432393.793027307');
INSERT INTO number2_exp_mul VALUES (2,6,'-3224438592470.18449811926184222');
INSERT INTO number2_exp_div VALUES (2,6,'-365.68599891479766440940');
INSERT INTO number2_exp_add VALUES (2,7,'-117366977.215397047');
INSERT INTO number2_exp_sub VALUES (2,7,'48689992.784602953');
INSERT INTO number2_exp_mul VALUES (2,7,'2851072985828710.485883795');
INSERT INTO number2_exp_div VALUES (2,7,'.41357483778485235518');
INSERT INTO number2_exp_add VALUES (2,8,'-34263611.215397047');
INSERT INTO number2_exp_sub VALUES (2,8,'-34413373.215397047');
INSERT INTO number2_exp_mul VALUES (2,8,'-2571300635581.146276407');
INSERT INTO number2_exp_div VALUES (2,8,'-458.57416721727870888476');
INSERT INTO number2_exp_add VALUES (2,9,'-59265296.260444467');
INSERT INTO number2_exp_sub VALUES (2,9,'-9411688.170349627');
INSERT INTO number2_exp_mul VALUES (2,9,'855948866655588.453741509242968740');
INSERT INTO number2_exp_div VALUES (2,9,'1.37757299946438931811');
INSERT INTO number2_exp_add VALUES (3,0,'4.31');
INSERT INTO number2_exp_sub VALUES (3,0,'4.31');
INSERT INTO number2_exp_mul VALUES (3,0,'0');
INSERT INTO number2_exp_div VALUES (3,0,'NaN');
INSERT INTO number2_exp_add VALUES (3,1,'4.31');
INSERT INTO number2_exp_sub VALUES (3,1,'4.31');
INSERT INTO number2_exp_mul VALUES (3,1,'0');
INSERT INTO number2_exp_div VALUES (3,1,'NaN');
INSERT INTO number2_exp_add VALUES (3,2,'-34338487.905397047');
INSERT INTO number2_exp_sub VALUES (3,2,'34338496.525397047');
INSERT INTO number2_exp_mul VALUES (3,2,'-147998901.44836127257');
INSERT INTO number2_exp_div VALUES (3,2,'-.00000012551512084352');
INSERT INTO number2_exp_add VALUES (3,3,'8.62');
INSERT INTO number2_exp_sub VALUES (3,3,'0');
INSERT INTO number2_exp_mul VALUES (3,3,'18.5761');
INSERT INTO number2_exp_div VALUES (3,3,'1.00000000000000000000');
INSERT INTO number2_exp_add VALUES (3,4,'7799465.7219');
INSERT INTO number2_exp_sub VALUES (3,4,'-7799457.1019');
INSERT INTO number2_exp_mul VALUES (3,4,'33615678.685289');
INSERT INTO number2_exp_div VALUES (3,4,'.00000055260225961552');
INSERT INTO number2_exp_add VALUES (3,5,'16401.348491');
INSERT INTO number2_exp_sub VALUES (3,5,'-16392.728491');
INSERT INTO number2_exp_mul VALUES (3,5,'70671.23589621');
INSERT INTO number2_exp_div VALUES (3,5,'.00026285234387695504');
INSERT INTO number2_exp_add VALUES (3,6,'93905.88763026');
INSERT INTO number2_exp_sub VALUES (3,6,'-93897.26763026');
INSERT INTO number2_exp_mul VALUES (3,6,'404715.7995864206');
INSERT INTO number2_exp_div VALUES (3,6,'.00004589912234457595');
INSERT INTO number2_exp_add VALUES (3,7,'-83028480.69');
INSERT INTO number2_exp_sub VALUES (3,7,'83028489.31');
INSERT INTO number2_exp_mul VALUES (3,7,'-357852770.35');
INSERT INTO number2_exp_div VALUES (3,7,'-.00000005190989574240');
INSERT INTO number2_exp_add VALUES (3,8,'74885.31');
INSERT INTO number2_exp_sub VALUES (3,8,'-74876.69');
INSERT INTO number2_exp_mul VALUES (3,8,'322737.11');
INSERT INTO number2_exp_div VALUES (3,8,'.00005755799201399553');
INSERT INTO number2_exp_add VALUES (3,9,'-24926799.735047420');
INSERT INTO number2_exp_sub VALUES (3,9,'24926808.355047420');
INSERT INTO number2_exp_mul VALUES (3,9,'-107434525.43415438020');
INSERT INTO number2_exp_div VALUES (3,9,'-.00000017290624149854');
INSERT INTO number2_exp_add VALUES (4,0,'7799461.4119');
INSERT INTO number2_exp_sub VALUES (4,0,'7799461.4119');
INSERT INTO number2_exp_mul VALUES (4,0,'0');
INSERT INTO number2_exp_div VALUES (4,0,'NaN');
INSERT INTO number2_exp_add VALUES (4,1,'7799461.4119');
INSERT INTO number2_exp_sub VALUES (4,1,'7799461.4119');
INSERT INTO number2_exp_mul VALUES (4,1,'0');
INSERT INTO number2_exp_div VALUES (4,1,'NaN');
INSERT INTO number2_exp_add VALUES (4,2,'-26539030.803497047');
INSERT INTO number2_exp_sub VALUES (4,2,'42137953.627297047');
INSERT INTO number2_exp_mul VALUES (4,2,'-267821744976817.8111137106593');
INSERT INTO number2_exp_div VALUES (4,2,'-.22713465002993920385');
INSERT INTO number2_exp_add VALUES (4,3,'7799465.7219');
INSERT INTO number2_exp_sub VALUES (4,3,'7799457.1019');
INSERT INTO number2_exp_mul VALUES (4,3,'33615678.685289');
INSERT INTO number2_exp_div VALUES (4,3,'1809619.81714617169373549883');
INSERT INTO number2_exp_add VALUES (4,4,'15598922.8238');
INSERT INTO number2_exp_sub VALUES (4,4,'0');
INSERT INTO number2_exp_mul VALUES (4,4,'60831598315717.14146161');
INSERT INTO number2_exp_div VALUES (4,4,'1.00000000000000000000');
INSERT INTO number2_exp_add VALUES (4,5,'7815858.450391');
INSERT INTO number2_exp_sub VALUES (4,5,'7783064.373409');
INSERT INTO number2_exp_mul VALUES (4,5,'127888068979.9935054429');
INSERT INTO number2_exp_div VALUES (4,5,'475.66281046305802686061');
INSERT INTO number2_exp_add VALUES (4,6,'7893362.98953026');
INSERT INTO number2_exp_sub VALUES (4,6,'7705559.83426974');
INSERT INTO number2_exp_mul VALUES (4,6,'732381731243.745115764094');
INSERT INTO number2_exp_div VALUES (4,6,'83.05996138436129499606');
INSERT INTO number2_exp_add VALUES (4,7,'-75229023.5881');
INSERT INTO number2_exp_sub VALUES (4,7,'90827946.4119');
INSERT INTO number2_exp_mul VALUES (4,7,'-647577464846017.9715');
INSERT INTO number2_exp_div VALUES (4,7,'-.09393717604145131637');
INSERT INTO number2_exp_add VALUES (4,8,'7874342.4119');
INSERT INTO number2_exp_sub VALUES (4,8,'7724580.4119');
INSERT INTO number2_exp_mul VALUES (4,8,'584031469984.4839');
INSERT INTO number2_exp_div VALUES (4,8,'104.15808298366741897143');
INSERT INTO number2_exp_add VALUES (4,9,'-17127342.633147420');
INSERT INTO number2_exp_sub VALUES (4,9,'32726265.456947420');
INSERT INTO number2_exp_mul VALUES (4,9,'-194415646271340.1815956522980');
INSERT INTO number2_exp_div VALUES (4,9,'-.31289456112403769409');
INSERT INTO number2_exp_add VALUES (5,0,'16397.038491');
INSERT INTO number2_exp_sub VALUES (5,0,'16397.038491');
INSERT INTO number2_exp_mul VALUES (5,0,'0');
INSERT INTO number2_exp_div VALUES (5,0,'NaN');
INSERT INTO number2_exp_add VALUES (5,1,'16397.038491');
INSERT INTO number2_exp_sub VALUES (5,1,'16397.038491');
INSERT INTO number2_exp_mul VALUES (5,1,'0');
INSERT INTO number2_exp_div VALUES (5,1,'NaN');
INSERT INTO number2_exp_add VALUES (5,2,'-34322095.176906047');
INSERT INTO number2_exp_sub VALUES (5,2,'34354889.253888047');
INSERT INTO number2_exp_mul VALUES (5,2,'-563049578578.769242506736077');
INSERT INTO number2_exp_div VALUES (5,2,'-.00047751189505192446');
INSERT INTO number2_exp_add VALUES (5,3,'16401.348491');
INSERT INTO number2_exp_sub VALUES (5,3,'16392.728491');
INSERT INTO number2_exp_mul VALUES (5,3,'70671.23589621');
INSERT INTO number2_exp_div VALUES (5,3,'3804.41728329466357308584');
INSERT INTO number2_exp_add VALUES (5,4,'7815858.450391');
INSERT INTO number2_exp_sub VALUES (5,4,'-7783064.373409');
INSERT INTO number2_exp_mul VALUES (5,4,'127888068979.9935054429');
INSERT INTO number2_exp_div VALUES (5,4,'.00210232958726897192');
INSERT INTO number2_exp_add VALUES (5,5,'32794.076982');
INSERT INTO number2_exp_sub VALUES (5,5,'0');
INSERT INTO number2_exp_mul VALUES (5,5,'268862871.275335557081');
INSERT INTO number2_exp_div VALUES (5,5,'1.00000000000000000000');
INSERT INTO number2_exp_add VALUES (5,6,'110298.61612126');
INSERT INTO number2_exp_sub VALUES (5,6,'-77504.53913926');
INSERT INTO number2_exp_mul VALUES (5,6,'1539707782.76899778633766');
INSERT INTO number2_exp_div VALUES (5,6,'.17461941433576102689');
INSERT INTO number2_exp_add VALUES (5,7,'-83012087.961509');
INSERT INTO number2_exp_sub VALUES (5,7,'83044882.038491');
INSERT INTO number2_exp_mul VALUES (5,7,'-1361421264394.416135');
INSERT INTO number2_exp_div VALUES (5,7,'-.00019748690453643710');
INSERT INTO number2_exp_add VALUES (5,8,'91278.038491');
INSERT INTO number2_exp_sub VALUES (5,8,'-58483.961509');
INSERT INTO number2_exp_mul VALUES (5,8,'1227826639.244571');
INSERT INTO number2_exp_div VALUES (5,8,'.21897461960978085228');
INSERT INTO number2_exp_add VALUES (5,9,'-24910407.006556420');
INSERT INTO number2_exp_sub VALUES (5,9,'24943201.083538420');
INSERT INTO number2_exp_mul VALUES (5,9,'-408725765384.257043660243220');
INSERT INTO number2_exp_div VALUES (5,9,'-.00065780749354660427');
INSERT INTO number2_exp_add VALUES (6,0,'93901.57763026');
INSERT INTO number2_exp_sub VALUES (6,0,'93901.57763026');
INSERT INTO number2_exp_mul VALUES (6,0,'0');
INSERT INTO number2_exp_div VALUES (6,0,'NaN');
INSERT INTO number2_exp_add VALUES (6,1,'93901.57763026');
INSERT INTO number2_exp_sub VALUES (6,1,'93901.57763026');
INSERT INTO number2_exp_mul VALUES (6,1,'0');
INSERT INTO number2_exp_div VALUES (6,1,'NaN');
INSERT INTO number2_exp_add VALUES (6,2,'-34244590.637766787');
INSERT INTO number2_exp_sub VALUES (6,2,'34432393.793027307');
INSERT INTO number2_exp_mul VALUES (6,2,'-3224438592470.18449811926184222');
INSERT INTO number2_exp_div VALUES (6,2,'-.00273458651128995823');
INSERT INTO number2_exp_add VALUES (6,3,'93905.88763026');
INSERT INTO number2_exp_sub VALUES (6,3,'93897.26763026');
INSERT INTO number2_exp_mul VALUES (6,3,'404715.7995864206');
INSERT INTO number2_exp_div VALUES (6,3,'21786.90896293735498839907');
INSERT INTO number2_exp_add VALUES (6,4,'7893362.98953026');
INSERT INTO number2_exp_sub VALUES (6,4,'-7705559.83426974');
INSERT INTO number2_exp_mul VALUES (6,4,'732381731243.745115764094');
INSERT INTO number2_exp_div VALUES (6,4,'.01203949512295682469');
INSERT INTO number2_exp_add VALUES (6,5,'110298.61612126');
INSERT INTO number2_exp_sub VALUES (6,5,'77504.53913926');
INSERT INTO number2_exp_mul VALUES (6,5,'1539707782.76899778633766');
INSERT INTO number2_exp_div VALUES (6,5,'5.72674008674192359679');
INSERT INTO number2_exp_add VALUES (6,6,'187803.15526052');
INSERT INTO number2_exp_sub VALUES (6,6,'0');
INSERT INTO number2_exp_mul VALUES (6,6,'8817506281.4517452372676676');
INSERT INTO number2_exp_div VALUES (6,6,'1.00000000000000000000');
INSERT INTO number2_exp_add VALUES (6,7,'-82934583.42236974');
INSERT INTO number2_exp_sub VALUES (6,7,'83122386.57763026');
INSERT INTO number2_exp_mul VALUES (6,7,'-7796505729750.37795610');
INSERT INTO number2_exp_div VALUES (6,7,'-.00113095617281538980');
INSERT INTO number2_exp_add VALUES (6,8,'168782.57763026');
INSERT INTO number2_exp_sub VALUES (6,8,'19020.57763026');
INSERT INTO number2_exp_mul VALUES (6,8,'7031444034.53149906');
INSERT INTO number2_exp_div VALUES (6,8,'1.25401073209839612184');
INSERT INTO number2_exp_add VALUES (6,9,'-24832902.467417160');
INSERT INTO number2_exp_sub VALUES (6,9,'25020705.622677680');
INSERT INTO number2_exp_mul VALUES (6,9,'-2340666225110.29929521292692920');
INSERT INTO number2_exp_div VALUES (6,9,'-.00376709254265256789');
INSERT INTO number2_exp_add VALUES (7,0,'-83028485');
INSERT INTO number2_exp_sub VALUES (7,0,'-83028485');
INSERT INTO number2_exp_mul VALUES (7,0,'0');
INSERT INTO number2_exp_div VALUES (7,0,'NaN');
INSERT INTO number2_exp_add VALUES (7,1,'-83028485');
INSERT INTO number2_exp_sub VALUES (7,1,'-83028485');
INSERT INTO number2_exp_mul VALUES (7,1,'0');
INSERT INTO number2_exp_div VALUES (7,1,'NaN');
INSERT INTO number2_exp_add VALUES (7,2,'-117366977.215397047');
INSERT INTO number2_exp_sub VALUES (7,2,'-48689992.784602953');
INSERT INTO number2_exp_mul VALUES (7,2,'2851072985828710.485883795');
INSERT INTO number2_exp_div VALUES (7,2,'2.41794207151503385700');
INSERT INTO number2_exp_add VALUES (7,3,'-83028480.69');
INSERT INTO number2_exp_sub VALUES (7,3,'-83028489.31');
INSERT INTO number2_exp_mul VALUES (7,3,'-357852770.35');
INSERT INTO number2_exp_div VALUES (7,3,'-19264149.65197215777262180974');
INSERT INTO number2_exp_add VALUES (7,4,'-75229023.5881');
INSERT INTO number2_exp_sub VALUES (7,4,'-90827946.4119');
INSERT INTO number2_exp_mul VALUES (7,4,'-647577464846017.9715');
INSERT INTO number2_exp_div VALUES (7,4,'-10.64541262725136247686');
INSERT INTO number2_exp_add VALUES (7,5,'-83012087.961509');
INSERT INTO number2_exp_sub VALUES (7,5,'-83044882.038491');
INSERT INTO number2_exp_mul VALUES (7,5,'-1361421264394.416135');
INSERT INTO number2_exp_div VALUES (7,5,'-5063.62688881730941836574');
INSERT INTO number2_exp_add VALUES (7,6,'-82934583.42236974');
INSERT INTO number2_exp_sub VALUES (7,6,'-83122386.57763026');
INSERT INTO number2_exp_mul VALUES (7,6,'-7796505729750.37795610');
INSERT INTO number2_exp_div VALUES (7,6,'-884.20756174009028770294');
INSERT INTO number2_exp_add VALUES (7,7,'-166056970');
INSERT INTO number2_exp_sub VALUES (7,7,'0');
INSERT INTO number2_exp_mul VALUES (7,7,'6893729321395225');
INSERT INTO number2_exp_div VALUES (7,7,'1.00000000000000000000');
INSERT INTO number2_exp_add VALUES (7,8,'-82953604');
INSERT INTO number2_exp_sub VALUES (7,8,'-83103366');
INSERT INTO number2_exp_mul VALUES (7,8,'-6217255985285');
INSERT INTO number2_exp_div VALUES (7,8,'-1108.80577182462841041118');
INSERT INTO number2_exp_add VALUES (7,9,'-107955289.045047420');
INSERT INTO number2_exp_sub VALUES (7,9,'-58101680.954952580');
INSERT INTO number2_exp_mul VALUES (7,9,'2069634775752159.035758700');
INSERT INTO number2_exp_div VALUES (7,9,'3.33089171198810413382');
INSERT INTO number2_exp_add VALUES (8,0,'74881');
INSERT INTO number2_exp_sub VALUES (8,0,'74881');
INSERT INTO number2_exp_mul VALUES (8,0,'0');
INSERT INTO number2_exp_div VALUES (8,0,'NaN');
INSERT INTO number2_exp_add VALUES (8,1,'74881');
INSERT INTO number2_exp_sub VALUES (8,1,'74881');
INSERT INTO number2_exp_mul VALUES (8,1,'0');
INSERT INTO number2_exp_div VALUES (8,1,'NaN');
INSERT INTO number2_exp_add VALUES (8,2,'-34263611.215397047');
INSERT INTO number2_exp_sub VALUES (8,2,'34413373.215397047');
INSERT INTO number2_exp_mul VALUES (8,2,'-2571300635581.146276407');
INSERT INTO number2_exp_div VALUES (8,2,'-.00218067233500788615');
INSERT INTO number2_exp_add VALUES (8,3,'74885.31');
INSERT INTO number2_exp_sub VALUES (8,3,'74876.69');
INSERT INTO number2_exp_mul VALUES (8,3,'322737.11');
INSERT INTO number2_exp_div VALUES (8,3,'17373.78190255220417633410');
INSERT INTO number2_exp_add VALUES (8,4,'7874342.4119');
INSERT INTO number2_exp_sub VALUES (8,4,'-7724580.4119');
INSERT INTO number2_exp_mul VALUES (8,4,'584031469984.4839');
INSERT INTO number2_exp_div VALUES (8,4,'.00960079113741758956');
INSERT INTO number2_exp_add VALUES (8,5,'91278.038491');
INSERT INTO number2_exp_sub VALUES (8,5,'58483.961509');
INSERT INTO number2_exp_mul VALUES (8,5,'1227826639.244571');
INSERT INTO number2_exp_div VALUES (8,5,'4.56673929509287019456');
INSERT INTO number2_exp_add VALUES (8,6,'168782.57763026');
INSERT INTO number2_exp_sub VALUES (8,6,'-19020.57763026');
INSERT INTO number2_exp_mul VALUES (8,6,'7031444034.53149906');
INSERT INTO number2_exp_div VALUES (8,6,'.79744134113322314424');
INSERT INTO number2_exp_add VALUES (8,7,'-82953604');
INSERT INTO number2_exp_sub VALUES (8,7,'83103366');
INSERT INTO number2_exp_mul VALUES (8,7,'-6217255985285');
INSERT INTO number2_exp_div VALUES (8,7,'-.00090187120721280172');
INSERT INTO number2_exp_add VALUES (8,8,'149762');
INSERT INTO number2_exp_sub VALUES (8,8,'0');
INSERT INTO number2_exp_mul VALUES (8,8,'5607164161');
INSERT INTO number2_exp_div VALUES (8,8,'1.00000000000000000000');
INSERT INTO number2_exp_add VALUES (8,9,'-24851923.045047420');
INSERT INTO number2_exp_sub VALUES (8,9,'25001685.045047420');
INSERT INTO number2_exp_mul VALUES (8,9,'-1866544013697.195857020');
INSERT INTO number2_exp_div VALUES (8,9,'-.00300403532938582735');
INSERT INTO number2_exp_add VALUES (9,0,'-24926804.045047420');
INSERT INTO number2_exp_sub VALUES (9,0,'-24926804.045047420');
INSERT INTO number2_exp_mul VALUES (9,0,'0');
INSERT INTO number2_exp_div VALUES (9,0,'NaN');
INSERT INTO number2_exp_add VALUES (9,1,'-24926804.045047420');
INSERT INTO number2_exp_sub VALUES (9,1,'-24926804.045047420');
INSERT INTO number2_exp_mul VALUES (9,1,'0');
INSERT INTO number2_exp_div VALUES (9,1,'NaN');
INSERT INTO number2_exp_add VALUES (9,2,'-59265296.260444467');
INSERT INTO number2_exp_sub VALUES (9,2,'9411688.170349627');
INSERT INTO number2_exp_mul VALUES (9,2,'855948866655588.453741509242968740');
INSERT INTO number2_exp_div VALUES (9,2,'.72591434384152961526');
INSERT INTO number2_exp_add VALUES (9,3,'-24926799.735047420');
INSERT INTO number2_exp_sub VALUES (9,3,'-24926808.355047420');
INSERT INTO number2_exp_mul VALUES (9,3,'-107434525.43415438020');
INSERT INTO number2_exp_div VALUES (9,3,'-5783481.21694835730858468677');
INSERT INTO number2_exp_add VALUES (9,4,'-17127342.633147420');
INSERT INTO number2_exp_sub VALUES (9,4,'-32726265.456947420');
INSERT INTO number2_exp_mul VALUES (9,4,'-194415646271340.1815956522980');
INSERT INTO number2_exp_div VALUES (9,4,'-3.19596478892958416484');
INSERT INTO number2_exp_add VALUES (9,5,'-24910407.006556420');
INSERT INTO number2_exp_sub VALUES (9,5,'-24943201.083538420');
INSERT INTO number2_exp_mul VALUES (9,5,'-408725765384.257043660243220');
INSERT INTO number2_exp_div VALUES (9,5,'-1520.20159364322004505807');
INSERT INTO number2_exp_add VALUES (9,6,'-24832902.467417160');
INSERT INTO number2_exp_sub VALUES (9,6,'-25020705.622677680');
INSERT INTO number2_exp_mul VALUES (9,6,'-2340666225110.29929521292692920');
INSERT INTO number2_exp_div VALUES (9,6,'-265.45671195426965751280');
INSERT INTO number2_exp_add VALUES (9,7,'-107955289.045047420');
INSERT INTO number2_exp_sub VALUES (9,7,'58101680.954952580');
INSERT INTO number2_exp_mul VALUES (9,7,'2069634775752159.035758700');
INSERT INTO number2_exp_div VALUES (9,7,'.30021990699995814689');
INSERT INTO number2_exp_add VALUES (9,8,'-24851923.045047420');
INSERT INTO number2_exp_sub VALUES (9,8,'-25001685.045047420');
INSERT INTO number2_exp_mul VALUES (9,8,'-1866544013697.195857020');
INSERT INTO number2_exp_div VALUES (9,8,'-332.88556569820675471748');
INSERT INTO number2_exp_add VALUES (9,9,'-49853608.090094840');
INSERT INTO number2_exp_sub VALUES (9,9,'0');
INSERT INTO number2_exp_mul VALUES (9,9,'621345559900192.420120630048656400');
INSERT INTO number2_exp_div VALUES (9,9,'1.00000000000000000000');

INSERT INTO number2_data VALUES (0, '0');
INSERT INTO number2_data VALUES (1, '0');
INSERT INTO number2_data VALUES (2, '-34338492.215397047');
INSERT INTO number2_data VALUES (3, '4.31');
INSERT INTO number2_data VALUES (4, '7799461.4119');
INSERT INTO number2_data VALUES (5, '16397.038491');
INSERT INTO number2_data VALUES (6, '93901.57763026');
INSERT INTO number2_data VALUES (7, '-83028485');
INSERT INTO number2_data VALUES (8, '74881');
INSERT INTO number2_data VALUES (9, '-24926804.045047420');


DROP INDEX if exists number2_exp_add_idx ON number2_exp_add;
CREATE UNIQUE INDEX number2_exp_add_idx ON number2_exp_add (id1, id2);
DROP INDEX if exists number2_exp_sub_idx ON number2_exp_sub;
CREATE UNIQUE INDEX number2_exp_sub_idx ON number2_exp_sub (id1, id2);
DROP INDEX if exists number2_exp_div_idx ON number2_exp_div;
CREATE UNIQUE INDEX number2_exp_div_idx ON number2_exp_div (id1, id2);
DROP INDEX if exists number2_exp_mul_idx ON number2_exp_mul;
CREATE UNIQUE INDEX number2_exp_mul_idx ON number2_exp_mul (id1, id2);

DELETE FROM number2_result;
INSERT INTO number2_result SELECT t1.id, t2.id, t1.val + t2.val
    FROM number2_data t1, number2_data t2;
SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM number2_result t1, number2_exp_add t2 
    WHERE t1.id1 = t2.id1 AND t1.id2 = t2.id2 AND t1.result != t2.expected 
    order by t1.id1, t1.id2;

DELETE FROM number2_result;
DELETE FROM number2_result;
INSERT INTO number2_result SELECT t1.id, t2.id, t1.val - t2.val
    FROM number2_data t1, number2_data t2;
SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM number2_result t1, number2_exp_sub t2
    WHERE t1.id1 = t2.id1 
    AND t1.id2 = t2.id2 
    AND t1.result != t2.expected order by t1.id1, t1.id2;

-- ******************************
-- * Multiply check
-- ******************************
DELETE FROM number2_result;
INSERT INTO number2_result SELECT t1.id, t2.id, t1.val * t2.val
    FROM number2_data t1, number2_data t2;
SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM number2_result t1, number2_exp_mul t2
    WHERE t1.id1 = t2.id1 
    AND t1.id2 = t2.id2 
    AND t1.result != t2.expected order by t1.id1, t1.id2;

DELETE FROM number2_result;
INSERT INTO number2_result SELECT t1.id, t2.id, t1.val / t2.val
    FROM number2_data t1, number2_data t2
    WHERE t2.val != '0.0';
	
SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM number2_result t1, number2_exp_div t2
    WHERE t1.id1 = t2.id1 
    AND t1.id2 = t2.id2 
    AND t1.result != t2.expected order by t1.id1, t1.id2;

DROP TABLE if exists number2_data;
DROP TABLE if exists number2_exp_add;
DROP TABLE if exists number2_exp_sub;
DROP TABLE if exists number2_exp_div;
DROP TABLE if exists number2_exp_mul;
DROP TABLE if exists number2_result;

DROP TABLE if exists t_num;
create table t_num(number2 number2);
insert into t_num values(1234);
commit;
select number2 from t_num;
DROP TABLE t_num;

create or replace function DBA_ARGUMENTS_003_f1(number1 in out number ) return number2
IS
number2 number2(9,3);
number3 number(9,3);
begin
    null;
end;
/
select data_type,data_length,data_precision,data_scale from user_arguments where object_name = 'DBA_ARGUMENTS_003_F1' order by sequence;
drop function DBA_ARGUMENTS_003_f1;

--nameable datatype as right value in pl
set serveroutput on;
drop table if exists t123;
create table t123(number2 number2, id number2);
insert into t123 values(12, 45);
commit;
select sum(number2) from t123 where number2 < 20;
select dense_rank(15) within group (order by number2) from t123;

CREATE OR REPLACE FUNCTION ztest_f1112(a number2, b number2) RETURN number2
AS
number2 number2;
n number2;
id number2 := 3;
BEGIN
number2 := a + b + 2;
dbe_output.print_line(number2);
n := number2;
dbe_output.print_line(n);
select id into n from t123; --When a column name has the same name as a variable, the variable takes precedence
dbe_output.print_line(n);
select number2 into number2 from t123;
RETURN number2;
END;
/
select ztest_f1112(number2, 2) from t123;

declare
c2 sys_refcursor;
type type_name is record
(c_int number2,
c_id number2);
number2 type_name;
begin
open c2 for select * from t123;
fetch c2 into number2;
close c2;
DBE_OUTPUT.PRINT_LINE('Happy new year ' || number2.c_int);
DBE_OUTPUT.PRINT_LINE('Happy new year ' || number2.c_id);
end;
/
drop table if exists t123;

declare
type type_name is record
(
c_num number(10),
c_num2 number2(10));
number3 type_name;
begin
number3.c_num := 9.9E127;
number3.c_num2 := 9.9E125;
DBE_OUTPUT.PRINT_LINE('Happy new year ' || number3.c_num);
DBE_OUTPUT.PRINT_LINE('Happy new year ' || number3.c_num2);
number3.c_num2 := 9.9E127;
end;
/
set serveroutput off;

drop table if exists tbl_number2_011;
create table tbl_number2_011
(c_id bigint auto_increment not null 	primary key,
c_clob clob,
c_time date,
c_num number2(10,2) check (c_num >=0),
c_name varchar2(100))  format csf ;
create unique index IDX_number2_011 on tbl_number2_011(c_num);
insert into tbl_number2_011(c_num) values(1);
insert into tbl_number2_011(c_num) values(0);
commit;
update tbl_number2_011 set c_num = 10 where c_clob is null;
drop table if exists tbl_number2_011;

drop table if exists tbl_number2_012;
create table tbl_number2_012
(c_id bigint auto_increment not null 	primary key,
c_clob clob,
c_time date,
c_num number2(10,2) check (c_num >=0),
c_name varchar2(100))  format csf crmode row;
create unique index IDX_number2_012 on tbl_number2_012(c_num);
insert into tbl_number2_012(c_num) values(1);
insert into tbl_number2_012(c_num) values(0);
commit;
update tbl_number2_012 set c_num = 10 where c_clob is null;
drop table if exists tbl_number2_012;

select acos(1) from dual;
select acos(-1) from dual;

drop table if exists tbl_number2_013;
create table tbl_number2_013(a1 varchar(8000),a2 varchar(8000),a3 varchar(8000),a4 varchar(8000),a5 varchar(8000),a6 varchar(8000),a7 varchar(8000),a8 varchar(8000),b number2);
insert into tbl_number2_013 select 
lpad('sbfacwjdafgjyjhfpyxcpmnutcjxrbfgxxbm',8000-4-8,'yxcfgdsgtcsdsjxrbxxbm'),
lpad('sbfacwjdafgjyjhfpyxcpmnutcjxrbfgxxbm',8000-4,'yxcfgdsgtcsdsjxrbxxbm'),
lpad('sbfacwjdafgjyjhfpyxcpmnutcjxrbfgxxbm',8000-4,'yxcfgdsgtcsdsjxrbxxbm'),
lpad('sbfacwjdafgjyjhfpyxcpmnutcjxrbfgxxbm',8000-4,'yxcfgdsgtcsdsjxrbxxbm'),
lpad('sbfacwjdafgjyjhfpyxcpmnutcjxrbfgxxbm',8000-4,'yxcfgdsgtcsdsjxrbxxbm'),
lpad('sbfacwjdafgjyjhfpyxcpmnutcjxrbfgxxbm',8000-4,'yxcfgdsgtcsdsjxrbxxbm'),
lpad('sbfacwjdafgjyjhfpyxcpmnutcjxrbfgxxbm',8000-4,'yxcfgdsgtcsdsjxrbxxbm'),
lpad('sbfacwjdafgjyjhfpyxcpmnutcjxrbfgxxbm',8000-4,'yxcfgdsgtcsdsjxrbxxbm'),
1 from sys_dummy;
drop table if exists tbl_number2_013;

drop table if exists tbl_number2_014;
create table tbl_number2_014(c_num number(10,1),c_name varchar(80)) format csf;

begin
for i in 0..100
loop
    insert into tbl_number2_014 values(i,'abs'||i) ;
end loop;
end;
/

exec DBE_STATS.COLLECT_TABLE_STATS(schema =>'NUMBER2_TESTER', name =>'TBL_NUMBER2_014', sample_ratio =>100);

select a.COL#,a.row_num,a.minvalue,a.maxvalue,a.dist_num from sys.sys_histgram_abstr a,sys.sys_tables b  where a.tab#=b.id and
 b.name=upper('TBL_NUMBER2_014')and a.USER#=b.USER#  and b.user#=( select id from sys.SYS_USERS where name='NUMBER2_TESTER' ) order by 1,2,3,4,5;

drop table if exists tbl_number2_015_part;
create table tbl_number2_015_part
(
c_int bigint unique ,
c_clob clob,
c_varchar varchar(80) ,
c_number number  check (c_number>=-10000),
c_date date
)partition by range (c_number) interval (2000900000)
(
 partition p1 values less than (1),
 partition p2 values less than (20),
 partition p3 values less than (10000),
 partition p4 values less than (1000000)
);

insert into tbl_number2_015_part values(999999999999999,5,'11',99999999999999,null);
insert into tbl_number2_015_part values(99999999999999,5,'11',99999999999999,null);
drop table if exists tbl_number2_015_part;
 
drop table if exists tbl_number2_016_part;
create table tbl_number2_016_part(f1 number2)
PARTITION BY RANGE(f1)
(
 PARTITION p1 values less than(-10),
 PARTITION p2 values less than(4),
 PARTITION p3 values less than(10),
 PARTITION p4 values less than(maxvalue)
) format csf;

insert into tbl_number2_016_part values(-5);
insert into tbl_number2_016_part values(0);
insert into tbl_number2_016_part values(2);
alter table tbl_number2_016_part split partition p2 at(-5) into (partition p21, partition p22);

select * from tbl_number2_016_part partition(p21);
select * from tbl_number2_016_part partition(p22);
drop table if exists tbl_number2_016_part;

drop table if exists tbl_number2_017;
create table tbl_number2_017(number_col1 number2);
alter table tbl_number2_017 add constraint PK_number2_002 primary key (number_col1);
ALTER TABLE tbl_number2_017 ADD logical log(PRIMARY KEY);

insert into tbl_number2_017 values(1.2364556);

insert into tbl_number2_017 values(1.0E-130);
commit;

update tbl_number2_017 set number_col1=0 where number_col1=1.2364556;
commit;
drop table if exists tbl_number2_017;

conn / as sysdba
drop user if exists number2_tester cascade;

drop table if exists subpart_csf_tbl_000;
drop table if exists subpart_csf_intevl_range_tbl_001;
drop sequence if exists subpart_csf_seq_000;
drop sequence if exists subpart_csf_seq_000_1;
create table subpart_csf_tbl_000(num int,c_id int,c_d_id bigint NOT NULL,c_w_id tinyint unsigned NOT NULL,c_uint UINT not null,c_first varchar(16) NOT NULL,c_middle char(2),c_last varchar(16) NOT NULL,c_street_1 varchar(20) NOT NULL,c_street_2 varchar(20),c_zero timestamp with time zone NOT NULL,c_start date NOT NULL,c_zip char(9) NOT NULL,c_phone char(16) NOT NULL,c_since timestamp,c_credit char(2),c_credit_lim numeric,c_discount numeric(5,2),c_balance numeric(12,2),c_ytd_payment real NOT NULL,c_payment_cnt number NOT NULL,c_delivery_cnt bool NOT NULL,c_end date NOT NULL,c_data1 varchar(7744),c_data2 varchar(7744),c_data3 varchar(7744),c_data4 varchar(7744),c_data5 varchar(7744),c_data6 varchar(7744),c_data7 varchar(7744),c_data8 varchar(7744),c_clob clob,c_blob blob);
insert into subpart_csf_tbl_000(num,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 0,0,0,0,0,'iscmRDs','OE','BARBar','RGF','SDG','2041-06-17 03:03:03.00 +08:00','2041-06-17 03:03:03','4801','940215','2041-06-17 03:03:03','GC',50000.0,0.4361328,-10.0,10.0,1,true,'2041-06-17 03:03:03',lpad('QVBRfSCC3484942ZCSfjvCF',500,'QVLDBURhlhfrc484ZCSfjF'),lpad('QVBUflcHOQNvmgfvdPFZSF',500,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',500,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',500,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',500,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',500,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',500,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',500,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',500,'QVLDfscHOQgfvmPFZDSF'),lpad('12314315487569809',500,'1435764ABC7890abcdef');
create sequence subpart_csf_seq_000 start with 1 MAXVALUE 10 increment by 1 CACHE 2 cycle;
create sequence subpart_csf_seq_000_1 start with 1 MAXVALUE 100 increment by 1 CACHE 2 cycle;
CREATE or replace procedure subpart_csf_proc(startall int,endall int)  as
i INT;
j int;
k int;
BEGIN
  FOR i IN startall..endall LOOP
    if i%8=1 then
        select subpart_csf_seq_000.nextval into j from sys_dummy;
            if i%40=1 then
               select subpart_csf_seq_000_1.nextval into k from sys_dummy;
               commit;
            end if;
        insert into subpart_csf_tbl_000(NUM,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 1,i,i%80,j,k,'iscmRDs'||i||'aa',C_MIDDLE,'BARBar'||(i%80)||'xx','RGF'||j||'AB','RGF'||k||'ABC',C_ZERO+i,C_START+(i%80),C_ZIP,C_PHONE,C_SINCE+j,C_CREDIT,i||'.'||i,i%80,j,C_YTD_PAYMENT,k,C_DELIVERY_CNT,C_END+k,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,lpad('QVBUflcHOQNvmgfvdPFZSF',2000,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',2000,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',1000,'QVLDfscHOQgfvmPFZDSF'),lpad('12314315487569809',2000,'1435764ABC7890abcdef') from subpart_csf_tbl_000 where c_id=0;
    elsif i%8=2 then
        insert into subpart_csf_tbl_000(NUM,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 2,i,i%80,j,k,'iscmRDs'||i||'aa',C_MIDDLE,'BARBar'||(i%80)||'xx','RGF'||j||'AB','RGF'||k||'ABC',C_ZERO+i,C_START+(i%80),C_ZIP,C_PHONE,C_SINCE+j,C_CREDIT,i||'.'||i,i%80,j,C_YTD_PAYMENT,k,C_DELIVERY_CNT,C_END+k,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,lpad('QVBUflcHOQNvmgfvdPFZSF',3000,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',3000,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',5000,'QVLDfscHOQgfvmPFZDSF'),lpad('12314315487569809',10000,'1435764ABC7890abcdef') from subpart_csf_tbl_000 where c_id=0;
    elsif i%8=3 then
        insert into subpart_csf_tbl_000(NUM,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 3,i,i%80,j,k,'iscmRDs'||i||'aa',C_MIDDLE,'BARBar'||(i%80)||'xx','RGF'||j||'AB','RGF'||k||'ABC',C_ZERO+i,C_START+(i%80),C_ZIP,C_PHONE,C_SINCE+j,C_CREDIT,i||'.'||i,i%80,j,C_YTD_PAYMENT,k,C_DELIVERY_CNT,C_END+k,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,lpad('QVBUflcHOQNvmgfvdPFZSF',3000,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',3000,'QVLDfscHOQgfvmPFZDSF'),null,null from subpart_csf_tbl_000 where c_id=0;
    elsif i%8=4 then
        insert into subpart_csf_tbl_000(NUM,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 4,i,i%80,j,k,'iscmRDs'||i||'aa',C_MIDDLE,'BARBar'||(i%80)||'xx','RGF'||j||'AB','RGF'||k||'ABC',C_ZERO+i,C_START+(i%80),C_ZIP,C_PHONE,C_SINCE+j,C_CREDIT,i||'.'||i,i%80,j,C_YTD_PAYMENT,k,C_DELIVERY_CNT,C_END+k,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,lpad('QVBUflcHOQNvmgfvdPFZSF',2000,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',2000,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',2000,'QVLDfscHOQgfvmPFZDSF'),lpad('12314315487569809',10000,'1435764ABC7890abcdef') from subpart_csf_tbl_000 where c_id=0;
    elsif i%8=5 then
        insert into subpart_csf_tbl_000(NUM,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 5,i,i%80,j,k,'iscmRDs'||i||'aa',C_MIDDLE,'BARBar'||(i%80)||'xx','RGF'||j||'AB','RGF'||k||'ABC',C_ZERO+i,C_START+(i%80),C_ZIP,C_PHONE,C_SINCE+j,C_CREDIT,i||'.'||i,i%80,j,C_YTD_PAYMENT,k,C_DELIVERY_CNT,C_END+k,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,lpad('QVBUflcHOQNvmgfvdPFZSF',100,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',100,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',100,'QVLDfscHOQgfvmPFZDSF'),lpad('12314315487569809',200,'1435764ABC7890abcdef') from subpart_csf_tbl_000 where c_id=0;
    elsif i%8=6 then
        insert into subpart_csf_tbl_000(NUM,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 6,i,i%80,j,k,'iscmRDs'||i||'aa',C_MIDDLE,'BARBar'||(i%80)||'xx','RGF'||j||'AB','RGF'||k||'ABC',C_ZERO+i,C_START+(i%80),C_ZIP,C_PHONE,C_SINCE+j,C_CREDIT,i||'.'||i,i%80,j,C_YTD_PAYMENT,k,C_DELIVERY_CNT,C_END+k,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,lpad('QVBUflcHOQNvmgfvdPFZSF',200,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',200,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',5000,'QVLDfscHOQgfvmPFZDSF'),lpad('12314315487569809',10000,'1435764ABC7890abcdef') from subpart_csf_tbl_000 where c_id=0;
    elsif i%8=7 then
        insert into subpart_csf_tbl_000(NUM,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 7,i,i%80,j,k,'iscmRDs'||i||'aa',C_MIDDLE,'BARBar'||(i%80)||'xx','RGF'||j||'AB','RGF'||k||'ABC',C_ZERO+i,C_START+(i%80),C_ZIP,C_PHONE,C_SINCE+j,C_CREDIT,i||'.'||i,i%80,j,C_YTD_PAYMENT,k,C_DELIVERY_CNT,C_END+k,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,lpad('QVBUflcHOQNvmgfvdPFZSF',200,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',200,'QVLDfscHOQgfvmPFZDSF'),null,null from subpart_csf_tbl_000 where c_id=0;
    elsif i%8=0 then
        insert into subpart_csf_tbl_000(NUM,C_ID,C_D_ID,C_W_ID,C_UINT,C_FIRST,C_MIDDLE,C_LAST,C_STREET_1,C_STREET_2,C_ZERO,C_START,C_ZIP,C_PHONE,C_SINCE,C_CREDIT,C_CREDIT_LIM,C_DISCOUNT,C_BALANCE,C_YTD_PAYMENT,C_PAYMENT_CNT,C_DELIVERY_CNT,C_END,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,C_DATA7,C_DATA8,C_CLOB,C_BLOB) select 8,i,i%80,j,k,'iscmRDs'||i||'aa',C_MIDDLE,'BARBar'||(i%80)||'xx','RGF'||j||'AB','RGF'||k||'ABC',C_ZERO+i,C_START+(i%80),C_ZIP,C_PHONE,C_SINCE+j,C_CREDIT,i||'.'||i,i%80,j,C_YTD_PAYMENT,k,C_DELIVERY_CNT,C_END+k,C_DATA1,C_DATA2,C_DATA3,C_DATA4,C_DATA5,C_DATA6,lpad('QVBUflcHOQNvmgfvdPFZSF',100,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',100,'QVLDfscHOQgfvmPFZDSF'),lpad('QVBUflcHOQNvmgfvdPFZSF',200,'QVLDfscHOQgfvmPFZDSF'),lpad('12314315487569809',10000,'1435764ABC7890abcdef') from subpart_csf_tbl_000 where c_id=0;
   end if;
  END LOOP;
END;
/
call subpart_csf_proc(1,400);
create table subpart_csf_intevl_range_tbl_001(num int,c_id number2(5),c_d_id number not null,c_w_id tinyint unsigned not null,c_uint uint not null,c_first varchar(500) not null,c_middle char(2),c_last varchar(500) not null,c_street_1 varchar(20) not null,c_street_2 varchar(500),c_zero timestamp not null,c_start date not null,c_zip char(9) not null,c_phone char(1600) not null,c_since timestamp,c_credit char(2),c_credit_lim numeric,c_discount numeric(5,2),c_balance number(12,2),c_ytd_payment real not null,c_payment_cnt number not null,c_delivery_cnt bool not null,c_end date not null,c_data1 varchar(7744),c_data2 varchar(7744),c_data3 varchar(7744),c_data4 varchar(7744),c_data5 varchar(7744),c_data6 varchar(7744),c_data7 varchar(7744),c_data8 varchar(7744),c_clob clob,c_blob blob)
partition by range(c_id) interval(80) subpartition by range(c_d_id)(
    partition p1 values less than(161) format csf (
	subpartition p11 values less than(16),
	subpartition p12 values less than(32),
	subpartition p13 values less than(48),
	subpartition p14 values less than(64),
	subpartition p15 values less than(maxvalue)),
    partition p2 values less than(321) format csf 
	(subpartition p21 values less than(16),
	subpartition p22 values less than(32),
	subpartition p23 values less than(48),
	subpartition p24 values less than(64),
	subpartition p25 values less than(maxvalue)),
    partition p3 values less than(481)  format csf 
	(subpartition p31 values less than(16),
	subpartition p32 values less than(32),
	subpartition p33 values less than(48),
	subpartition p34 values less than(64),
	subpartition p35 values less than(maxvalue)),
    partition p4 values less than(641) format asf (
	subpartition p41 values less than(16),
	subpartition p42 values less than(32),
	subpartition p43 values less than(48),
	subpartition p44 values less than(64),
	subpartition p45 values less than(maxvalue))
    );
insert into subpart_csf_intevl_range_tbl_001 (num,c_id,c_d_id,c_w_id,c_uint,c_first,c_middle,c_last,c_street_1,c_street_2,c_zero,c_start,c_zip,c_phone,c_since,c_credit,c_credit_lim,c_discount,c_balance,c_ytd_payment,c_payment_cnt,c_delivery_cnt,c_end,c_data1,c_data2,c_data3,c_data4,c_data5,c_data6,c_data7,c_data8,c_clob,c_blob)select num,c_id,c_d_id,c_w_id,c_uint,c_first,c_middle,c_last,c_street_1,c_street_2,c_zero,c_start,c_zip,c_phone,c_since,c_credit,c_credit_lim,c_discount,c_balance,c_ytd_payment,c_payment_cnt,c_delivery_cnt,c_end,c_data1,c_data2,c_data3,c_data4,c_data5,c_data6,c_data7,c_data8,c_clob,c_blob from subpart_csf_tbl_000 where mod(c_id,2)=0;
commit;
select count(0) from subpart_csf_tbl_000 where c_id>320 or c_id not in(select c_id from subpart_csf_intevl_range_tbl_001);
drop table subpart_csf_tbl_000;
drop table subpart_csf_intevl_range_tbl_001;
drop sequence subpart_csf_seq_000;
drop sequence subpart_csf_seq_000_1;