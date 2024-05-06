------------------------------------
-- JSONB_VALUE
------------------------------------
-- 1. create jsonb data.
drop table if exists tbl_jb_jbv_test_1;
create table tbl_jb_jbv_test_1(a jsonb);
drop table tbl_jb_jbv_test_1;

drop table if exists tbl_jb_jbv_test_1;
create table tbl_jb_jbv_test_1(a jsonb, b int);
insert into tbl_jb_jbv_test_1 values('{"id":null, "name":"andy", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{"A":1, "B":2, "C":3, "D":4}}', 1); --ok
insert into tbl_jb_jbv_test_1 values('[[1, 2, 3, 4], [11, 22, 33, 44], [31, 32, 33, 34], [41, 42, 43, 44], [51, 52, 53, 54], {"AA":111, "BB":222, "CC":333}]', 2); --ok
insert into tbl_jb_jbv_test_1 values('{"id":null, "name":"andy", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{A:1, "B":2, "C":3, "D":4}}', 1); --syntax error
insert into tbl_jb_jbv_test_1 values('"hello word"', 1); --error: can not be scaler
insert into tbl_jb_jbv_test_1 values('true', 1); --error: can not be scaler
insert into tbl_jb_jbv_test_1 values('32534.2555', 1); --error: can not be scaler
insert into tbl_jb_jbv_test_1 values('[true', 1); --error: can not be scaler

drop table if exists tbl_jv_jbv_test_1;
create table tbl_jv_jbv_test_1(a clob check(a is json), b int);
insert into tbl_jv_jbv_test_1 values('{"id":null, "name":"andy", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{"A":1, "B":2, "C":3, "D":4}}', 1); --ok
insert into tbl_jv_jbv_test_1 values('[[1, 2, 3, 4], [11, 22, 33, 44], [31, 32, 33, 34], [41, 42, 43, 44], [51, 52, 53, 54], {"AA":111, "BB":222, "CC":333}]', 2); --ok
insert into tbl_jv_jbv_test_1 values('{"id":null, "name":"andy", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{A:1, "B":2, "C":3, "D":4}}', 1); --constraint violated
insert into tbl_jv_jbv_test_1 values('"hello word"', 1); --constraint violated

select length(a), b from tbl_jb_jbv_test_1;
select length(a), b from tbl_jv_jbv_test_1;

-- 2. query jsonb data.
select jsonb_value(a, '$.id') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.name') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.age') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.addr') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.hob') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.hob' null on error) as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.hob' error on error) as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.hob[4][2].lov') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.hob[4][2].lov' returning varchar2(256)) as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.hob[4][2].lov' returning clob) as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs' null on error) as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs' error on error) as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs.A') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs.B') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs.C') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs.D') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs.E') as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs.E' null on error) as jbv_res from tbl_jb_jbv_test_1 where b = 1;
select jsonb_value(a, '$.attrs.E' error on error) as jbv_res from tbl_jb_jbv_test_1 where b = 1;

select jsonb_value(a, '$[0][2]') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
select jsonb_value(a, '$[1][2]') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
select jsonb_value(a, '$[2][2]') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
select jsonb_value(a, '$[3][2]') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
select jsonb_value(a, '$[4][2]') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
select jsonb_value(a, '$[5].AA') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
select jsonb_value(a, '$[5].BB') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
select jsonb_value(a, '$[5].CC') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
desc -q select jsonb_value(a, '$[5].CC') as jbv_res from tbl_jb_jbv_test_1 where b = 2;
desc -q select jsonb_value(a, '$[5].CC' returning varchar2(256)) as jbv_res from tbl_jb_jbv_test_1 where b = 2;
desc -q select jsonb_value(a, '$[5].CC' returning clob) as jbv_res from tbl_jb_jbv_test_1 where b = 2;
select jsonb_value(a, '$[5].CC' returning clob error on error) as jbv_res from tbl_jb_jbv_test_1 where b = 2;

drop table if exists tbl_jb_jbv_test_1;
drop table if exists tbl_jv_jbv_test_1;

-- 3. as function index
-- 3.1 testcase 1
drop table if exists jbv_func_indx_test;
create table jbv_func_indx_test(a jsonb);
insert into jbv_func_indx_test values('[{"AAA":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, {"BBB":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}, {"CCC":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}, {"DDD":"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"}, {"EEE":"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"}]');
insert into jbv_func_indx_test values('[{"AAA":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcccAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, {"BBB":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBccccBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}, {"CCC":"CCCCCCCCCCCCCCCCCCCCCCCCccccCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}, {"DDD":"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDccccDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"}, {"EEE":"EEEEEEEEEEEEEEEEEEEEEEEEEEccccEEEEEEEEEEEEEEEEEEE"}]');
commit;

drop index if exists jsonb_value_idx_jbv_func_indx_test on jbv_func_indx_test;
create index jsonb_value_idx_jbv_func_indx_test on jbv_func_indx_test(jsonb_value(a, '$[0].AAA'));

select jsonb_value(a, '$[0].AAA') as jbv_res from jbv_func_indx_test order by jbv_res;
select jsonb_value(a, '$[0].AAA' returning clob) as jbv_res from jbv_func_indx_test order by jbv_res;

select jsonb_value(a, '$[1].BBB') as jbv_res from jbv_func_indx_test order by jbv_res;
select jsonb_value(a, '$[2].CCC') as jbv_res from jbv_func_indx_test order by jbv_res;
select jsonb_value(a, '$[3].DDD') as jbv_res from jbv_func_indx_test order by jbv_res;
select jsonb_value(a, '$[4].EEE') as jbv_res from jbv_func_indx_test order by jbv_res;

-- 3.2 testcase 2
drop table if exists jbv_func_indx_test;
create table jbv_func_indx_test(a jsonb);

create unique index DDFDVFD on jbv_func_indx_test(jsonb_value(a, '$.AAA' returning varchar2(1024)), jsonb_value(a, '$.BBB' returning varchar2(1024)));
insert into jbv_func_indx_test values('{"AAA" : "111", "BBB" : "222", "CCC" : "333"}');
insert into jbv_func_indx_test values('{"AAA" : "111", "BBB" : "222", "CCC" : "333"}'); -- error
insert into jbv_func_indx_test values('{"AAA" : "111", "BBB" : "000", "CCC" : "333"}');
select jsonb_query(a, '$') as val from jbv_func_indx_test where jsonb_value(a, '$.AAA' returning varchar2(1024)) = '111';
select jsonb_query(a, '$') as val from jbv_func_indx_test where jsonb_value(a, '$.AAA' returning varchar2(1024)) = '111' and jsonb_value(a, '$.BBB' returning varchar2(1024)) = '222';

drop table if exists jbv_func_indx_test;

------------------------------------
-- JSONB_QUERY
------------------------------------
--1. basic use
drop table if exists tbl_jb_jbq_test_1;
create table tbl_jb_jbq_test_1(a jsonb, b int);
insert into tbl_jb_jbq_test_1 values('{"id":null, "name":"andy", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{"A":1, "B":2, "C":3, "D":4}}', 1); --ok
insert into tbl_jb_jbq_test_1 values('[[1, 2, 3, 4], [11, 22, 33, 44], [31, 32, 33, 34], [41, 42, 43, 44], [51, 52, 53, 54], {"AA":111, "BB":222, "CC":333}]', 2); --ok

select jsonb_query(a, '$') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.id') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.id' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.name') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.name' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.age') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.age' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.addr') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.addr' with conditional wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.hob') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.hob[2 to 4]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.hob[1, 4]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.hob[4]' with conditional wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.hob[4][*]' with conditional wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.hob[4][*].*' with conditional wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.attrs') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.attrs' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.attrs.A' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.attrs.B' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.attrs.C' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.attrs.D' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 1;

select jsonb_query(a, '$') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[0]') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[0][1, 3]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[1]') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[1][1, 3]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[2]') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[2][1, 3]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[3]') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[3][1, 3]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[4]') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[4][1, 3]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[5]') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[0,2,4]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[1,3,5]' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[5].AA' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[5].BB' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[5].CC' with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[5].DD' with wrapper error on error) as jbq_res from tbl_jb_jbq_test_1 where b = 2;

--returning && mixed with json_value
select jsonb_query(a, '$                      ') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
desc -q select jsonb_query(a, '$') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$' returning clob) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
desc -q select jsonb_query(a, '$' returning clob) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$' returning varchar2(256)) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
desc -q select jsonb_query(a, '$' returning varchar2(256)) as jbq_res from tbl_jb_jbq_test_1 where b = 1;

select jsonb_query(a, '$[2]' returning varchar2(128)) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[2]' returning jsonb) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(jsonb_query(a, '$[2]' returning jsonb), '$') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(jsonb_query(a, '$[2]' returning jsonb), '$[1,3]'with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(jsonb_query(a, '$[2]' returning jsonb), '$[1,3]' returning jsonb with wrapper) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_value(jsonb_query(jsonb_query(a, '$[2]' returning jsonb), '$[1,3]' returning jsonb with wrapper), '$[0]') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_value(jsonb_query(jsonb_query(a, '$[2]' returning jsonb), '$[1,3]' returning jsonb with wrapper), '$[1]') as jbq_res from tbl_jb_jbq_test_1 where b = 2;

select jsonb_query(a, '$[5]' returning clob) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_query(a, '$[5]' returning jsonb) as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select json_value(jsonb_query(a, '$[5]' returning clob), '$.AA') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select json_value(jsonb_query(a, '$[5]' returning clob), '$.BB') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select json_value(jsonb_query(a, '$[5]' returning clob), '$.CC') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_value(jsonb_query(a, '$[5]' returning jsonb), '$.AA') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_value(jsonb_query(a, '$[5]' returning jsonb), '$.BB') as jbq_res from tbl_jb_jbq_test_1 where b = 2;
select jsonb_value(jsonb_query(a, '$[5]' returning jsonb), '$.CC') as jbq_res from tbl_jb_jbq_test_1 where b = 2;

select jsonb_query(a, '$.attrs' returning clob) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.attrs' returning jsonb) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_value(jsonb_query(a, '$.attrs' returning jsonb), '$.A') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_value(jsonb_query(a, '$.attrs' returning jsonb), '$.B') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_value(jsonb_query(a, '$.attrs' returning jsonb), '$.C') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_value(jsonb_query(a, '$.attrs' returning jsonb), '$.D') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_value(jsonb_query(a, '$.attrs' returning jsonb), '$.D' returning jsonb) as jbq_res from tbl_jb_jbq_test_1 where b = 1;  --error

select jsonb_query(a, '$.hob[4]' returning clob) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(a, '$.hob[4]' returning jsonb) as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_value(jsonb_query(a, '$.hob[4]' returning jsonb), '$[0]') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_value(jsonb_query(a, '$.hob[4]' returning jsonb), '$[1]') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_query(jsonb_query(a, '$.hob[4]' returning jsonb), '$[2]') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select json_value(jsonb_query(jsonb_query(a, '$.hob[4]' returning jsonb), '$[2]'), '$.lov') as jbq_res from tbl_jb_jbq_test_1 where b = 1;
select jsonb_value(jsonb_query(jsonb_query(a, '$.hob[4]' returning jsonb), '$[2]' returning jsonb), '$.lov') as jbq_res from tbl_jb_jbq_test_1 where b = 1;

drop table if exists tbl_jb_jbq_test_1;

--sort keys in every object.
drop table if exists sort_jsonb_tbl;
create table sort_jsonb_tbl(a jsonb);
insert into sort_jsonb_tbl values('{"FFF":"dsds", "DDD":null, "EEE":12.25, "AAA":true, "CCC":false, "BBB":[1,2,3,4,5]}');
insert into sort_jsonb_tbl values('{"FFF":"dsds", "DDD":{"AA":{"id":null, "Name":"andy", "age":18, "addr":"China"}, "123":{"Id":null, "name":"andy", "Age":18, "addr":"China"}}}');
select jsonb_query(a, '$') as val from sort_jsonb_tbl;
commit;

drop table if exists sort_jsonb_tbl;
create table sort_jsonb_tbl(a jsonb);
truncate table sort_jsonb_tbl;
insert into sort_jsonb_tbl values('{"QQQ":"3454334", "FFF":"dsds", "DDD":null, "CCC":{"QWE":"234234", "KHGF":6776}, "ZZZ":"fvdvfdev", "SSS":12233.25, "EEE":12.25, "AAA":true, "WWW":"huawei.com", "CCC":false, "BBB":[1,2,3,4,5]}');
commit;

select jsonb_query(a, '$' with wrapper) as val from sort_jsonb_tbl;
select jsonb_query(a, '$.*' with wrapper) as val from sort_jsonb_tbl;
select jsonb_query(a, '$.CCC' with wrapper) as val from sort_jsonb_tbl;  --[false,{"KHGF":6776,"QWE":"234234"}]
select jsonb_query(a, '$.CCC' returning jsonb with wrapper) as val from sort_jsonb_tbl;
select jsonb_query(to_blob('01000000011180'), '$') as val;
select jsonb_query(to_blob('01000000011100'), '$') as val;
select jsonb_query(to_blob('01000000021100'), '$') as val;  --version is not correct
select jsonb_query(to_blob('01000000011100'), '$' error on error) as val;
select jsonb_query(to_blob('01000000011180'), '$' error on error) as val;
select jsonb_query(to_blob('01000000013180'), '$' error on error);  --error
select jsonb_query(to_blob('0200000001118011'), '$' error on error) as val;
select jsonb_query(to_blob('0200000001118211'), '$' error on error);  --error
select jsonb_array_length(to_blob('01000000013180'));  --error

select jsonb_query(to_blob('1B0000000111021504048243060A0D114B48474651574536373736323334323334'), '$') as val;  --[false,{"KHGF":6776,"QWE":"234234"}]
select jsonb_query(to_blob('1B0000000111021504048243060A0D114B48474651574536373736323334323334'), '$[1]' with wrapper) as val;  --[{"KHGF":6776,"QWE":"234234"}]
select jsonb_query(to_blob('1B0000000111021504048243060A0D124B48474651574536373736323334323334'), '$[1]' with wrapper) as val;  --change offset
select jsonb_query(to_blob('1B0000000111021504048243060A0D334B48474651574536373736323334323334'), '$[1]' with wrapper error on error) as val; -- error
select jsonb_query(to_blob('1B0000000111021504048243060A0D014B48474651574536373736323334323334'), '$[1]' with wrapper error on error) as val; -- error
select jsonb_query(to_blob('1B0000000111021504048243060A0D0D4B48474651574536373736323334323334'), '$[1]' with wrapper error on error) as val; -- error
select jsonb_query(to_blob('1B0000000111021504048243060A0D0E4B48474651574536373736323334323334'), '$[1]' with wrapper error on error) as val;
select jsonb_query(to_blob('1B00000001110215FF048243060A0D114B48474651574536373736323334323334'), '$[1]' with wrapper error on error) as val;

select jsonb_value(to_blob('1B0000000111021504048243060A0D114B48474651574536373736323334323334'), '$[0]') as val;
select jsonb_value(to_blob('1B0000000111021504048243060A0D114B48474651574536373736323334323334'), '$[1].KHGF') as val from sort_jsonb_tbl;
select jsonb_value(to_blob('1B0000000111021504048243060A99114B48474651574536373736323334323334'), '$[1].KHGF') as val from sort_jsonb_tbl; -- error
select jsonb_value(to_blob('1B0000000111021504048243060A0D114B48474651574536373736323334323334'), '$[1].QWE') as val from sort_jsonb_tbl;
select jsonb_query(to_blob('1B0000000111021504048243060A0D114B48474651574536373736414243446768'), '$') as val from sort_jsonb_tbl;  --[false,{"KHGF":6776,"QWE":"ABCDgh"}]
select jsonb_query(to_blob('4B0000000111021504048243060A0D114B48474651574536373736414243446768'), '$') as val from sort_jsonb_tbl;  --length is not correct
select jsonb_query(to_blob('000000000111'), '$') as val;  --length is not correct
select jsonb_query(to_blob('0000000111'), '$') as val;  --length is not correct
select jsonb_query(to_blob('1B0000000111021504048243060A0D114B4847465157453637373641424344676868686868'), '$') as val from sort_jsonb_tbl;  --length is not correct
select jsonb_query(to_blob('1B0000000211021504048243060A0D114B48474651574536373736414243446768'), '$') as val from sort_jsonb_tbl;  --version is not correct
select jsonb_query(to_blob('1B0000000151021504048243060A0D114B48474651574536373736414243446768'), '$') as val from sort_jsonb_tbl;  --head bytes number is not correct
select jsonb_query(to_blob('1B0000000115021504048243060A0D114B48474651574536373736414243446768'), '$') as val from sort_jsonb_tbl;  --entry bytes number is not correct
select jsonb_query(to_blob('1B0000000113021504048243060A0D114B48474651574536373736323334323334'), '$') as val from sort_jsonb_tbl;  --entry bytes number is not correct
select jsonb_query(to_blob('1B0000000110021504048243060A0D114B48474651574536373736323334323334'), '$') as val from sort_jsonb_tbl;  --entry bytes number is not correct
select jsonb_query(to_blob('0B00000001110444440708090A31323334'), '$' error on error) as val;
select jsonb_query(to_blob('0B00000001110444440788090A31323334'), '$' error on error); -- error
select jsonb_query(to_blob('0B00000001110444440701090A31323334'), '$' error on error); -- error
select jsonb_query(to_blob('0B00000001120444440701090A31323334'), '$' error on error); -- error
select jsonb_query(to_blob('0500000001110444440708'), '$' error on error); -- error

select jsonb_query(jsonb_query(jsonb_query(a, '$.*' returning jsonb with wrapper), '$' returning jsonb), '$') as val from sort_jsonb_tbl;
select jsonb_query(jsonb_query(jsonb_query(a, '$.*' returning jsonb with wrapper), '$' returning jsonb), '$[1,3,5,7]' with wrapper) as val from sort_jsonb_tbl;  --[[1,2,3,4,5],{"KHGF":6776,"QWE":"234234"},12.25,"3454334"]
select jsonb_query(jsonb_query(jsonb_query(a, '$.*' returning jsonb with wrapper), '$' returning jsonb), '$[1,3,5,7]' returning jsonb with wrapper) as val from sort_jsonb_tbl;
select jsonb_query(to_blob('38000000011104554307152C3105444440090A0B0C0D31323334358243060A0D114B4847465157453637373632333432333431322E323533343534333334'), '$') as val from sort_jsonb_tbl;  --[[1,2,3,4,5],{"KHGF":6776,"QWE":"234234"},12.25,"3454334"]
select jsonb_query(to_blob('38000000011104554307152C3105444440090A0B0C0D31323334358243060A0D114B4847465157453637373632333432333431322E323533343534333334'), '$[0]') as val from sort_jsonb_tbl;
select jsonb_query(to_blob('38000000011104554307152C3105444440090A0B0C0D31323334358243060A0D114B4847465157453637373632333432333431322E323533343534333334'), '$[0][0,2,4]' with wrapper) as val from sort_jsonb_tbl;
select jsonb_query(to_blob('38000000011104554307152C3105444440090A0B0C0D31323334358243060A0D114B4847465157453637373632333432333431322E323533343534333334'), '$[1]') as val from sort_jsonb_tbl;
select jsonb_value(to_blob('38000000011104554307152C3105444440090A0B0C0D31323334358243060A0D114B4847465157453637373632333432333431322E323533343534333334'), '$[1].KHGF') as val from sort_jsonb_tbl;
select jsonb_value(to_blob('38000000011104554307152C3105444440090A0B0C0D31323334358243060A0D114B4847465157453637373632333432333431322E323533343534333334'), '$[1].QWE') as val from sort_jsonb_tbl;
select jsonb_query(to_blob('38000000011104554307152C3105444440090A0B0C0D31323334358243060A0D114B4847465157453637373632333432333431322E323533343534333334'), '$[2, 3]' with wrapper) as val from sort_jsonb_tbl;

drop table if exists sort_jsonb_tbl;

drop table if exists binary_test_jsonb;
create table binary_test_jsonb(a jsonb, b int);
insert into binary_test_jsonb values('[1,2,3,true]', 1);
insert into binary_test_jsonb values('[1,2,3,4]', 2);
select * from binary_test_jsonb;
commit;

select jsonb_value(to_blob('0B00000001110444440708090A31323334'), '$[1]' error on error) as val;
select jsonb_value(to_blob('0B00000001110444440708990A31323334'), '$[1]' error on error) as val; --error
select jsonb_value(to_blob('0A00000001110444420708090A313233'), '$[3]' error on error) as val;

------------------------------------
-- JSONB_EXISTS
------------------------------------
drop table if exists tbl_jb_jbe_test_1;
create table tbl_jb_jbe_test_1(a jsonb, b int);
insert into tbl_jb_jbe_test_1 values('{"id":null, "name":"andy", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{"A":1, "B":2, "C":3, "D":4}}', 1); --ok
insert into tbl_jb_jbe_test_1 values('[[1, 2, 3, 4], [11, 22, 33, 44], [31, 32, 33, 34], [41, 42, 43, 44], [51, 52, 53, 54], {"AA":111, "BB":222, "CC":333}]', 2); --ok

select jsonb_exists(a, '$') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.id') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.name') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.age') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.addr') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[0]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[1]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[2]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[3]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[4]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[4][0]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[4][1]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[4][2]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.hob[4][2].lov') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.attrs') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.attrs.A') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.attrs.B') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.attrs.C') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(a, '$.attrs.D') as jbe_res from tbl_jb_jbe_test_1 where b = 1;

select jsonb_exists(a, '$.atstrs.B') as jbe_res from tbl_jb_jbe_test_1 where b = 1;  --false
select jsonb_exists(a, '$.attrs.EDCVD') as jbe_res from tbl_jb_jbe_test_1 where b = 1;  --false

select jsonb_exists(a, '$[0]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[0][0]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[0][1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[0][2]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[0][3]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[1][0]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[1][1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[1][2]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[1][3]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[2]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[2][0]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[2][1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[2][2]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[2][3]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[3]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[3][0]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[3][1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[3][2]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[3][3]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[4]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[4][0]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[4][1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[4][2]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[4][3]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[5]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[5].AA') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[5].BB') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[5].CC') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[5].AA[*]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[5].BB[*]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(a, '$[5].CC[*]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;

select jsonb_exists(a, '$[8][1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;  --false
select jsonb_exists(a, '$[4][9]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;  --false
select jsonb_exists(a, '$[5].AAs') as jbe_res from tbl_jb_jbe_test_1 where b = 2;  --false
select jsonb_exists(a, '$[5].AA[1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;  --false

--mixed
select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[0]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[1]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[2]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[3]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[4][0]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[4][1]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[4][2].lov') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.attrs' returning jsonb), '$.A') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.attrs' returning jsonb), '$.B') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.attrs' returning jsonb), '$.C') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$.attrs' returning jsonb), '$.D') as jbe_res from tbl_jb_jbe_test_1 where b = 1;
select jsonb_exists(jsonb_query(a, '$[2]' returning jsonb), '$[0]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(jsonb_query(a, '$[2]' returning jsonb), '$[1]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(jsonb_query(a, '$[2]' returning jsonb), '$[2]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(jsonb_query(a, '$[2]' returning jsonb), '$[3]') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(jsonb_query(a, '$[5]' returning jsonb), '$.AA') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(jsonb_query(a, '$[5]' returning jsonb), '$.BB') as jbe_res from tbl_jb_jbe_test_1 where b = 2;
select jsonb_exists(jsonb_query(a, '$[5]' returning jsonb), '$.CC') as jbe_res from tbl_jb_jbe_test_1 where b = 2;

select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[8]') as jbe_res from tbl_jb_jbe_test_1 where b = 1;  --false
select jsonb_exists(jsonb_query(a, '$.hob' returning jsonb), '$[4][65].lov') as jbe_res from tbl_jb_jbe_test_1 where b = 1;  --false
select jsonb_exists(jsonb_query(a, '$.attrs' returning jsonb), '$.Dsa') as jbe_res from tbl_jb_jbe_test_1 where b = 1;  --false
select jsonb_exists(jsonb_query(a, '$[5]' returning jsonb), '$.SFDVDF') as jbe_res from tbl_jb_jbe_test_1 where b = 2;  --false

drop table if exists tbl_jb_jbe_test_1;

------------------------------------
-- JSONB_MERGEPATCH
------------------------------------
drop table if exists jb_merpatch_tbl;
create table jb_merpatch_tbl(a jsonb, b int);
insert into jb_merpatch_tbl values('{"addres":"CHN", "id":"55185651515", "name":"zzzzzzzzzzzzzzzzzzzzzzzzzzzz", "age":4444444444444444444444444, "hobby":[1,2,34,5]}', 1);
insert into jb_merpatch_tbl values('[1,2,3,4,5,6]', 2);
insert into jb_merpatch_tbl values('{"AAA":{"BBB":{"CCC":"XXXXX"}}}', 3);
insert into jb_merpatch_tbl values('[1, 2, {"AAA":{"BBB":{"CCC":"XXXXX"}}}]', 4);
commit;

--replace
select jsonb_query(a, '$') from jb_merpatch_tbl;
select jsonb_mergepatch(a, '{"name":"andy", "age":12}') from jb_merpatch_tbl where b = 1;
select jsonb_mergepatch(a, '{"hobby":["basketball", "sing", "soccer", "moive", {"saly" : 6666}]}') from jb_merpatch_tbl where b = 1;
select jsonb_mergepatch(a, '{"addres":"www.huawei.com", "age":88, "name":{"lang":"JAVA"}}') from jb_merpatch_tbl where b = 1;
select jsonb_mergepatch(a, '{"AAA":{"BBB":{"CCC":"Andy"}}}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"AAA":{"BBB":[true, false, {}]}}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"name":"andy"}') from jb_merpatch_tbl where b = 2;
select jsonb_mergepatch(a, '[4,5,6,1,2,3]') from jb_merpatch_tbl where b = 2;
select jsonb_mergepatch(a, '[1,2,3,4]') from jb_merpatch_tbl where b = 1;
select jsonb_mergepatch(a, '{"name":"andy", "age":12}') from jb_merpatch_tbl where b = 2;
select jsonb_mergepatch(a, '[1,2,3,4,5,6]') from jb_merpatch_tbl where b = 2;
select jsonb_mergepatch(a, '{"CCC":"XXXXX"}') from jb_merpatch_tbl where b = 4;
select jsonb_mergepatch(a, '[{"CCC":"XXXXX"}]') from jb_merpatch_tbl where b = 4;
select jsonb_mergepatch(a, '{"AAA":85612}') from jb_merpatch_tbl where b = 4;

--delete
select jsonb_mergepatch(a, '{"name":null}') from jb_merpatch_tbl where b = 1;
select jsonb_mergepatch(a, '{"id":null}') from jb_merpatch_tbl where b = 1;
select jsonb_mergepatch(a, '{"addres":null}') from jb_merpatch_tbl where b = 1;
select jsonb_mergepatch(a, '{"addres":null}') from jb_merpatch_tbl where b = 2;
select jsonb_mergepatch(a, '{"AAA":{"BBB":{"CCC":null}}}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"AAA":{"BBB":null}}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"AAA":null}') from jb_merpatch_tbl where b = 3;

--insert
select jsonb_mergepatch(a, '{"AAA":{"BBB":{"CCC":"XXXXX"}}}') from jb_merpatch_tbl where b = 1;
select jsonb_mergepatch(a, '{"AAA":{"DDD":{"CCC":"XXXXX"}}}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"AAA":{"DDD":{"EEE":"XXXXX"}, "EEE":{"DDD":"XXXXX"}}}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"AAA":{"BBB":{"VVV":"YYYYY"}}}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"FFF":true, "GGG":false}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"FFF":{"BBB":{"VVV":"YYYYY", "oooo":"dsadcs"}}}') from jb_merpatch_tbl where b = 3;
select jsonb_mergepatch(a, '{"AAA":{"WWWW":{"VVV":"YYYYY"}}}') from jb_merpatch_tbl where b = 3;

------------------------------------
-- JSONB_SET
------------------------------------
drop table if exists jsonb_set_tbl;
create table jsonb_set_tbl(a jsonb, b int);
insert into jsonb_set_tbl values('[{"f1":1,"f2":null},2,null,3]', 1);
insert into jsonb_set_tbl values('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', 2);
insert into jsonb_set_tbl values('{"nickname": "gs", "avatar": "avatar_url", "tags": ["python", "golang", "db"]}', 3);
insert into jsonb_set_tbl values('[{"f2":1, "f0":1, "f1":null, "f5":null, "f4":null, "f7":null, "f8":null, "f6":null},2,null,3]', 4);
commit;

--replace
select jsonb_set(a, '$[0].f1', '[2,3,4]', false returning clob) from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[0].f1', '[2,3,4]', false returning jsonb) from jsonb_set_tbl where b = 1;
select jsonb_query(jsonb_set(a, '$[0].f1', '[2,3,4]', false returning jsonb), '$[0].f1') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[0].f2', '{"name":"hello world"}', false returning clob) from jsonb_set_tbl where b = 1;
select jsonb_query(jsonb_set(a, '$[0].f2', '{"name":"hello world"}', false returning jsonb), '$[0].f2') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[1]', 'true', false returning clob) from jsonb_set_tbl where b = 1;
select jsonb_value(jsonb_set(a, '$[1]', 'true', false returning jsonb), '$[1]') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[2]', '123456', false returning clob) from jsonb_set_tbl where b = 1;
select jsonb_value(jsonb_set(a, '$[2]', '123456', false returning jsonb), '$[2]') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[3]', 'false', false returning clob) from jsonb_set_tbl where b = 1;
select jsonb_value(jsonb_set(a, '$[3]', 'false', false returning jsonb), '$[3]') from jsonb_set_tbl where b = 1;

select jsonb_set(a, '$.name', '"JDD"') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.age', '1232') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.attrs', '["AA", true, {"ccc":34}, [1,2,3,4,5,6,7]]') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho', '[9,8,7,6]') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho[0]', '[9,8,7,6]') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho[1]', '[9,8,7,6]') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho[2]', '[9,8,7,6]') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho[3]', '[9,8,7,6]') from jsonb_set_tbl where b = 2;

select jsonb_set(a, '$.nickname', '"JDD"') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.avatar', '"JDD"') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags', '"JDD"') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags[0]', '"JDD"') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags[1]', '"JDD"') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags[2]', '"JDD"') from jsonb_set_tbl where b = 3;

--delete
select jsonb_set(a, '$[0]') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[0].f1') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[0].f2') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[1]') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[2]') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[3]') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$.name') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.age') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.addr') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho[1, 3]') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho[0, 2]') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.nickname') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.avatar') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags[0]') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags[1]') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags[2]') from jsonb_set_tbl where b = 3;

--add
select jsonb_set(a, '$[0].f3','[2,3,4]') from jsonb_set_tbl where b = 1;
select jsonb_query(jsonb_set(a, '$[0].f3','[2,3,4]' returning jsonb), '$[0].f3') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[8]','[2,3,4]') from jsonb_set_tbl where b = 1;
select jsonb_set(a, '$[4]', '[true, false]', true returning clob) from jsonb_set_tbl where b = 1;
select jsonb_query(jsonb_set(a, '$[4]', '[true, false]', true returning jsonb), '$[4]') from jsonb_set_tbl where b = 1;

select jsonb_set(a, '$.ccc', '"JDD"') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.AAA', '{"JDD":15}') from jsonb_set_tbl where b = 2;
select jsonb_set(a, '$.ho[8]', '{"JDD":15}') from jsonb_set_tbl where b = 2;

select jsonb_set(a, '$.heigth', '323') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.AUTO', '{"JDD":15}') from jsonb_set_tbl where b = 3;
select jsonb_set(a, '$.tags[8]', '["GaussDB", "Zenith", "openGauss"]') from jsonb_set_tbl where b = 3;

select jsonb_set(a, '$[0].A3','[2,3,4]') from jsonb_set_tbl where b = 4;
select jsonb_query(jsonb_set(a, '$[0].A3','[2,3,4]' returning jsonb), '$[0].A3') from jsonb_set_tbl where b = 4;

select jsonb_set(a, '$[0].f3','[2,3,4]') from jsonb_set_tbl where b = 4;
select jsonb_query(jsonb_set(a, '$[0].f3','[2,3,4]' returning jsonb), '$[0].f3') from jsonb_set_tbl where b = 4;

select jsonb_set(a, '$[0].gggg','[2,3,4]') from jsonb_set_tbl where b = 4;
select jsonb_query(jsonb_set(a, '$[0].gggg','[2,3,4]' returning jsonb), '$[0].gggg') from jsonb_set_tbl where b = 4;


------------------------------------
-- JSONB_ARRAY_LENGTH
------------------------------------
drop table if exists jbal_test_xy;
create table jbal_test_xy(a jsonb, b int);

insert into jbal_test_xy values('[]', 1);  
insert into jbal_test_xy values('[null]', 2);  
insert into jbal_test_xy values('[1]', 3);
insert into jbal_test_xy values('[{"one":3323233.24311}]', 4);  
insert into jbal_test_xy values('["one"]', 5);  
insert into jbal_test_xy values('[false]', 6);
insert into jbal_test_xy values('[3323233.24311]', 7);  
insert into jbal_test_xy values('[1,2,3,4]', 8);
insert into jbal_test_xy values('[{"1":1},{"2":2},{"3":3},{"4":4}]', 9);
insert into jbal_test_xy values('["one","two","three","four"]', 10);
insert into jbal_test_xy values('[true,false,false,true]', 11);
insert into jbal_test_xy values('[33.11,11.22,44.33,22.44]', 12);
insert into jbal_test_xy values('[null,null,null,null]', 13);
insert into jbal_test_xy values('[
[{ "firstName": "Brett", "lastName":"McLaughlin"},{ "firstName": "Jason", "lastName":"Hunter"}],
[{ "firstName": "Eric",   "lastName": "Clapton", "instrument": "guitar" },{ "firstName": "Sergei", "lastName": "Rachmaninoff", "instrument": "piano" }]
]', 14);
insert into jbal_test_xy values('[ [ [1,1,1,1], [1,1,2]],[[1,2,1],[1, 2, 2]],[[1,2,3],[1,2,3,1]]]', 15);
insert into jbal_test_xy values('[ ["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"key_1":1},{"key_2":2},{"key_3":3}] ]', 16);
insert into jbal_test_xy values('
[
[{ "firstName": "Brett"}, { "firstName": "Jason", "lastName":"Hunter" },{ "firstName": "Elliotte", "lastName":"Harold"} ],
[{ "firstName": "Isaac", "genre": "science fiction" },{ "firstName": "Tad"}],
[{ "firstName": "Eric", "lastName": "Clapton",  "BWH": [80.1,80.2,80.3]}],
[{ "firstName": "Echo", "lastName": "Hiton",  "BWH": [80.1,80.2,80.3]}],
[{ "firstName": "Kilt", "lastName": "Merbo",  "BWH": [80.1,80.2,80.3]}]
]', 17);
select jsonb_array_length(a), b from jbal_test_xy order by b;

truncate table jbal_test_xy;
insert into jbal_test_xy values('[343.1341, 11.242, 44.333, 22.4344]', 1);
insert into jbal_test_xy values('[{"osane":3323233.24311}]', 2);  
insert into jbal_test_xy values('{"key":[1,2,3,4,5,6]}', 3);
insert into jbal_test_xy values('{"key1":1,"key2":2,"key3":3,"key4":4}', 4);
insert into jbal_test_xy values('{
  "address" : "1007 Mountain Drive",
  "rooms" : [ {
    "roomNo" : "101",
    "personLivedInThisRoom" : "Super Man is rocking"
  }, {
    "roomNo" : "102",
    "personLivedInThisRoom" : "Bat Man is rocking"
  }, {
    "roomNo" : "201",
    "personLivedInThisRoom" : "Rachel is rocking"
  } ]
}', 5);
select jsonb_array_length(a), b from jbal_test_xy order by b;
select jsonb_array_length(a), b from jbal_test_xy where b < 3 order by b;
select jsonb_array_length(a), b from jbal_test_xy where b = 3 order by b;
select jsonb_array_length(a), b from jbal_test_xy where b > 3 order by b;

drop table if exists jbal_test_xy;

------------------------------------
-- JSONB TYPE
------------------------------------
drop table if exists jbt_test_jdd;
create table jbt_test_jdd(a jsonb, b int);
desc jbt_test_jdd;

insert into jbt_test_jdd values('dsfsdd', 1);  -- syntax error
insert into jbt_test_jdd values(123456, 1);  -- Inconsistent datatypes
insert into jbt_test_jdd values(1234.056, 1);  -- Inconsistent datatypes
insert into jbt_test_jdd values(true, 1);  -- Inconsistent datatypes
insert into jbt_test_jdd values(false, 1);  -- Inconsistent datatypes
insert into jbt_test_jdd values(current_timestamp, 1);  -- Inconsistent datatypes

insert into jbt_test_jdd values('{"count":234}', 1);
insert into jbt_test_jdd values('[{"count":234}]', 2);
select * from jbt_test_jdd;
select length(a) from jbt_test_jdd;
select jsonb_query(a, '$') from jbt_test_jdd;

--
drop table if exists inner_table_test;
create table inner_table_test(a clob check(a is json), b int);
insert into inner_table_test values('{"count":234}', 1);
insert into inner_table_test values('[{"count":234}]', 2);

truncate table jbt_test_jdd;
insert into jbt_test_jdd select * from inner_table_test;
select * from jbt_test_jdd;
select length(a) from jbt_test_jdd;
select jsonb_query(a, '$') from jbt_test_jdd;

--
drop table if exists inner_table_test;
create table inner_table_test(a varbinary(100), b int);
insert into inner_table_test select * from jbt_test_jdd;
select bin2hex(a) from inner_table_test;
select length(a) from inner_table_test;
select jsonb_query(a, '$') from inner_table_test;

truncate table jbt_test_jdd;
insert into jbt_test_jdd select * from inner_table_test;
select * from jbt_test_jdd;
select length(a) from jbt_test_jdd;
select jsonb_query(a, '$') from jbt_test_jdd;

--
drop table if exists inner_table_test;
create table inner_table_test(a blob, b int);
insert into inner_table_test select * from jbt_test_jdd;
select * from inner_table_test;
select length(a) from inner_table_test;
select jsonb_query(a, '$') from inner_table_test;

truncate table jbt_test_jdd;
insert into jbt_test_jdd select * from inner_table_test;
select * from jbt_test_jdd;
select length(a) from jbt_test_jdd;
select jsonb_query(a, '$') from jbt_test_jdd;

drop table if exists inner_table_test;
drop table if exists jbt_test_jdd;

------------------------------------
-- OTHER TEST
------------------------------------
drop table if exists tbl_jsonb_ft3_test;
create table tbl_jsonb_ft3_test(a jsonb, b int primary key);
insert into tbl_jsonb_ft3_test values('{"A":{"KMP":"1","ADC":{"BBC":"2"},"OME":3},"B":{"KMP_A":1,"ADC_A":{"BBC_A":2}, "OME_A":3}}',2);
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b = 2;
select jsonb_value(a, '$.A.OME') from tbl_jsonb_ft3_test where b = 2;
select json_query('{"A":{"OME":{"BBC":30}}}', '$.A.OME');
select jsonb_mergepatch(a, '{"A":{"OME":{"BBC":30}}}') from tbl_jsonb_ft3_test where b = 2;
select jsonb_mergepatch(a, '{"A":{"OME":89}}') from tbl_jsonb_ft3_test where b = 2;

insert into tbl_jsonb_ft3_test values('{"addres":{"home":"xxx","company":"xxx"}, "age":0, "name":"xxx", "hobby":[{"key1":{"key2":10}},"music","run","food"]}',3);
select jsonb_mergepatch(a, '{"addres":{"home":"xxx","company":"xxx"}, "age":0, "name":"xxx", "hobby":[{"key1":{"key8":8, "key2":5}}]}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_set(a, '$.hobby[0].key1.key2', 18) from tbl_jsonb_ft3_test where b = 3;
select jsonb_set(a, '$.hobby[0].key1', '{"key2":2}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_set(a, '$.hobby[0].key1', '{"key8":8, "key6":{"key8":{"key8":8, "key6":6, "key9":{"key8":{"key8":8, "key6":6, "key9":9}, "key6":6, "key9":9}}, "key6":6, "key9":9}, "key9":9}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b = 3;

select jsonb_mergepatch(a, '{"addres":{"home":{"BBC":30}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_mergepatch(a, '{"addres":{"home":"ccxbbbbbbbbbbbbbbsssssc"}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_mergepatch(a, '{"name":{"home":{"BBC":30}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_mergepatch(a, '{"addres":{"home":{"BBC":{"key8":8, "key6":{"key8":{"key8":8, "key6":6, "key9":{"key8":{"key8":8, "key6":6, "key9":9}, "key6":6, "key9":9}}, "key6":6, "key9":9}, "key9":9}}}}') from tbl_jsonb_ft3_test where b = 3;

insert into tbl_jsonb_ft3_test values('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}',4);
select jsonb_set(to_blob(a),'$.age') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.age') from tbl_jsonb_ft3_test where b=4;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":{"K3":1000, "K2":1000}}, "Z2":856}}}') from tbl_jsonb_ft3_test where b = 4;
drop table if exists tbl_jsonb_ft3_test;

--clob can not insert into non-jsonb column
drop table if exists jdd_jsonb_t1;
drop table if exists jdd_jsonb_t2;
create table jdd_jsonb_t1(a clob);
create table jdd_jsonb_t2(a blob);
insert into jdd_jsonb_t1 values('fsdffcwsdfcvrwefregfver#@%$&^^$%&#$%^$#@%@$%#$%$#');
insert into jdd_jsonb_t2 select * from jdd_jsonb_t1;
insert into jdd_jsonb_t2 values(to_clob('fsdffcwsdfcvrwefregfver#@%$&^^$%&#$%^$#@%@$%#$%$#'));
drop table if exists jdd_jsonb_t1;
drop table if exists jdd_jsonb_t2;
create table jdd_jsonb_t1(a clob check (a is json));
create table jdd_jsonb_t2(a jsonb);
insert into jdd_jsonb_t1 values('fsdffcwsdfcvrwefregfver#@%$&^^$%&#$%^$#@%@$%#$%$#');
insert into jdd_jsonb_t1 values('{"dscdsd":"dsa4334fdsc", "134":"3454343", "324324":"345", "dscds234325d":"dsafd3443sc"}');
insert into jdd_jsonb_t2 select * from jdd_jsonb_t1;
insert into jdd_jsonb_t2 values(to_clob('fsdffcwsdfcvrwefregfver#@%$&^^$%&#$%^$#@%@$%#$%$#'));
insert into jdd_jsonb_t2 values(to_clob('{"dscdsd":"dsa4334fdsc", "134":"3454343", "324324":"345", "dscds234325d":"dsafd3443sc"}'));
drop table if exists jdd_jsonb_t1;
drop table if exists jdd_jsonb_t2;

--valiate the binary data into jsonb column
drop table if exists jdd_jsonb_t2;
create table jdd_jsonb_t2(a jsonb);
insert into jdd_jsonb_t2 values(to_blob('01000000011100'));
insert into jdd_jsonb_t2 values(to_blob('01000000011200'));
insert into jdd_jsonb_t2 values(to_blob('01000000013100')); --error
insert into jdd_jsonb_t2 values(to_blob('01000000010100')); --error
insert into jdd_jsonb_t2 values(to_blob('01000000011800')); --error
insert into jdd_jsonb_t2 values(to_blob('01000000011100000000')); --error
insert into jdd_jsonb_t2 values(to_blob('11000000011100')); --error
insert into jdd_jsonb_t2 values(to_blob('111111111111111111111')); --error
insert into jdd_jsonb_t2 values(to_blob('2143534667532432142523525245245346356')); --error
insert into jdd_jsonb_t2 values(to_blob('01000000011100111111111111111111111')); --error
insert into jdd_jsonb_t2 values(to_clob('{"D":"dsa4334fdsc", "Z":"3454343", "A":"345", "R":"dsafd3443sc"}'));
insert into jdd_jsonb_t2 values(to_blob('2F00000001118433330B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433'));
insert into jdd_jsonb_t2 values(to_blob('2F00000001110433330B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433'));
insert into jdd_jsonb_t2 values(to_blob('2F00000001118333330B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433'));
insert into jdd_jsonb_t2 values(to_blob('2F00000001118443340B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433'));
insert into jdd_jsonb_t2 values(to_blob('2F00000001118533330B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433')); --error
insert into jdd_jsonb_t2 values(to_blob('5F00000001118433330B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433')); --error
insert into jdd_jsonb_t2 values(to_blob('2F00000003118433330B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433')); --error
insert into jdd_jsonb_t2 values(to_blob('2F00000001218433330B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433')); --error
insert into jdd_jsonb_t2 values(to_blob('2F00000001118433330B0C0D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433DDDDDDDDDDDDDD')); --error
insert into jdd_jsonb_t2 values(to_blob('2F00000001118433330B0C0D0E0F121D28414141414141414141414141414141414141414141414141414141414141414141414141'));
insert into jdd_jsonb_t2 values(to_blob('2F00000001118433330B0C0D0E0F121D284144525A3333333333333333333333333333333333333333333333333333333333333333'));
insert into jdd_jsonb_t2 values(to_blob('2F00000001118433330B0C2D0E0F121D284144525A3334356473613433333466647363647361666433343433736333343534333433')); --error
select jsonb_query(a, '$') val from jdd_jsonb_t2 order by val;
drop table if exists jdd_jsonb_t2;

--support raw tyype to store jsonb
drop table if exists tbl_jsonb_006;
CREATE GLOBAL TEMPORARY TABLE tbl_jsonb_006(
id BINARY_INTEGER not null,
c_jsonb jsonb default 0x390000000111044405070A0B0B2D313030024504063130024504063230024504063330024504063430823506080A0E6B317331676F6F640244040638303930
) ON COMMIT DELETE ROWS;
insert into tbl_jsonb_006 (id)values(1);
select jsonb_query(c_jsonb, '$' returning varchar2(32767)) from tbl_jsonb_006;
drop table if exists tbl_jsonb_006;

drop table if exists tbl_jsonb_006;
create table tbl_jsonb_006(a raw);
create table tbl_jsonb_006(a raw(256));
insert into tbl_jsonb_006 values(0x390000000111044405070A0B0B2D313030024504063130024504063230024504063330024504063430823506080A0E6B317331676F6F640244040638303930);
select jsonb_query(a, '$') from tbl_jsonb_006;
drop table if exists tbl_jsonb_006;

--create table as select
drop table if exists jdd_jsonb_tbl_test_1;
create table jdd_jsonb_tbl_test_1(a jsonb not null) format csf;

drop table if exists jdd_jsonb_tbl_test_2;
create table jdd_jsonb_tbl_test_2 as select * from jdd_jsonb_tbl_test_1;
select IS_JSONB from adm_tab_cols where TABLE_NAME = upper('jdd_jsonb_tbl_test_2');
insert into jdd_jsonb_tbl_test_2 values('{"name":"Andy"}');
select jsonb_query(a, '$') from jdd_jsonb_tbl_test_2;

drop table if exists jdd_jsonb_tbl_test_3;
create table jdd_jsonb_tbl_test_3 as select a from jdd_jsonb_tbl_test_1;
select IS_JSONB from adm_tab_cols where TABLE_NAME = upper('jdd_jsonb_tbl_test_3');
insert into jdd_jsonb_tbl_test_3 values('{"name":"Andy"}');
select jsonb_value(a, '$.name') from jdd_jsonb_tbl_test_3;

drop table if exists jdd_jsonb_tbl_test_1;
drop table if exists jdd_jsonb_tbl_test_2;
drop table if exists jdd_jsonb_tbl_test_3;

drop table if exists tbl_jsonb_025;
create table tbl_jsonb_025(id int,c_json clob,c_jsonb jsonb);
insert into tbl_jsonb_025 values(1,'[{"k1":[{"s1":["a","sd","-100",[0,100,[{"s2":"rr","s3":"周杰伦"}]]]},1000,"200we",{"d1":{"t1":"被子","t2":9999}}],"k2":{"q2":{"f2":"水杯","f3":"手机","f4":"fdfs","f5":["fdf",[100,200,"re",[1000,2000,[3000,{"w1":"终结者"}]]]]}},"k3":[{"g1":100},{"g2":{"g3":"nice"}},10000,{"g4":{"g5":{"g6":"2323","g7":-100000}}},"good boy","giraffe"]},{"":[null,0,-100,{"a2":null,"水果":"香蕉"},["富贵竹","panda","@#$$",[1000,"鼠标",null]]]},[100,[200,[300,[400,[500,[{"结果":"死机"}]]]]]],{"h1":{"h2":{"h3":{"h4":{"h5":["中国好娃娃"]}}}}}]','[{"k1":[{"s1":["a","sd","-100",[0,100,[{"s2":"rr","s3":"周杰伦"}]]]},1000,"200we",{"d1":{"t1":"被子","t2":9999}}],"k2":{"q2":{"f2":"水杯","f3":"手机","f4":"fdfs","f5":["fdf",[100,200,"re",[1000,2000,[3000,{"w1":"终结者"}]]]]}},"k3":[{"g1":100},{"g2":{"g3":"nice"}},10000,{"g4":{"g5":{"g6":"2323","g7":-100000}}},"good boy","giraffe"]},{"":[null,0,-100,{"a2":null,"水果":"香蕉"},["富贵竹","panda","@#$$",[1000,"鼠标",null]]]},[100,[200,[300,[400,[500,[{"结果":"死机"}]]]]]],{"h1":{"h2":{"h3":{"h4":{"h5":["中国好娃娃"]}}}}}]');
insert into tbl_jsonb_025 values(2,'["",""]', '["",""]');
commit;
select jsonb_query(c_jsonb,'$' with wrapper error on error ) from tbl_jsonb_025 order by id;
drop table if exists tbl_jsonb_025;

--DTS202107190GMSSWP1400
drop table if exists tbl_jsonb_025;
create table tbl_jsonb_025(id int,c_json clob,c_jsonb jsonb);
insert into tbl_jsonb_025 values(1,'[{"k1":"lili","k2":[10,{"k3":20}],"k3":{"k4":"语文","k5":"数学"}},{"k1":"luna","k2":[100,{"k3":200}],"k3":{"k4":"物理","k5":"化学"}},{"k1":"joyh","k2":[1000,{"k3":2000}],"k3":{"k4":"高数","k5":"生物"}}]','[{"k1":"lili","k2":[10,{"k3":20}],"k3":{"k4":"语文","k5":"数学"}},{"k1":"luna","k2":[100,{"k3":200}],"k3":{"k4":"物理","k5":"化学"}},{"k1":"joyh","k2":[1000,{"k3":2000}],"k3":{"k4":"高数","k5":"生物"}}]');
commit;

select jsonb_mergepatch(t1.c_jsonb,'[{"k1":"lili","k2":[10,{"k3":20}],"k3":{"k4":"语文","k5":"数学"}},{"k1":"luna","k2":[100,{"k3":200}],"k3":{"k4":"物理","k5":"化学"}},{"k1":"joyh","k2":[1000,{"k3":2000}],"k3":{"k4":"高数","k5":"生物"}},{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"数学"}}]' returning jsonb error on error) from tbl_jsonb_025 t1;
select jsonb_mergepatch(t1.c_jsonb,'[]' returning jsonb error on error) from tbl_jsonb_025 t1;
select t2.* from tbl_jsonb_025 t1,jsonb_table(jsonb_mergepatch(t1.c_jsonb,'[{"k1":"lili","k2":[10,{"k3":20}],"k3":{"k4":"语文","k5":"数学"}},{"k1":"luna","k2":[100,{"k3":200}],"k3":{"k4":"物理","k5":"化学"}},{"k1":"joyh","k2":[1000,{"k3":2000}],"k3":{"k4":"高数","k5":"生物"}},{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"数学"}}]' returning jsonb error on error),'$[*]' error on error columns(c1 varchar2(10) path '$.k1',c4 varchar2(10) path '$.k3.k4',c6 for ordinality)) t2;
drop table if exists tbl_jsonb_025;

--support string with any length.
drop table if exists test_json_src_1;
create table test_json_src_1(a clob);
insert into test_json_src_1 values(lpad('dscds', 8000, 'asdcsaf'));
update test_json_src_1 set a = a || a;
update test_json_src_1 set a = a || a;
update test_json_src_1 set a = a || a;
update test_json_src_1 set a = a || a;
update test_json_src_1 set a = a || lpad('dscds', 8000, 'asdcsaf');
update test_json_src_1 set a = '{"name":"' || a || '"}';
select length(a) from test_json_src_1;
select 1 from test_json_src_1 where a is json;
select length(json_value(a, '$.name' returning clob)) val from test_json_src_1;
select length(json_query(a, '$' returning clob)) val from test_json_src_1;

drop table if exists test_jsonb_dst;
create table test_jsonb_dst(a jsonb);
insert into test_jsonb_dst select * from test_json_src_1;
select length(jsonb_value(a, '$.name' returning clob)) val from test_jsonb_dst;
select length(jsonb_query(a, '$' returning clob)) val from test_jsonb_dst;

drop table if exists test_json_src_1;
drop table if exists test_jsonb_dst;

--DTS2021071905Y3BMP1D00
drop table if exists tbl_jsonb_025;
create table tbl_jsonb_025(id int,c_json clob,c_jsonb jsonb);
insert into tbl_jsonb_025 values(1,'[{"k1":"lili","k3":{"k4":"Chinese","k5":"math"}},{"k1":"luna","k3":{"k4":"PYH","k5":"CHEM"}},{"k1":"joyh","k3":{"k4":"High                         QQ                         Math","k5":"bio"}}]','[{"k1":"lili","k3":{"k4":"Chinese","k5":"math"}},{"k1":"luna","k3":{"k4":"PYH","k5":"CHEM"}},{"k1":"joyh","k3":{"k4":"High                         QQ                         Math","k5":"bio"}}]');
commit;

select jsonb_set(t1.c_jsonb,'$[4]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"Math"}}' returning varchar2(1000) error on error) from tbl_jsonb_025 t1;
select t2.* from tbl_jsonb_025 t1,json_table(jsonb_set(t1.c_jsonb,'$[4]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning varchar2(1000) error on error),'$[*]' columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,json_table(jsonb_set(jsonb_query(jsonb_query(jsonb_query(jsonb_query(t1.c_jsonb,'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$[4]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning varchar2(1000) error on error),'$[*]' columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,json_table(jsonb_set(jsonb_query(jsonb_query(jsonb_query(jsonb_query(jsonb_set(jsonb_set(t1.c_jsonb,'$[4]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning jsonb error on error),'$[5]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$[6]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning varchar2(1000) error on error),'$[*]' columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,json_table(json_set(t1.c_json,'$[4]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning varchar2(1000) error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select jsonb_query(t1.c_jsonb,'$' returning varchar2(1000) error on error) from tbl_jsonb_025 t1;
select t2.* from tbl_jsonb_025 t1,json_table(jsonb_query(t1.c_jsonb,'$' returning varchar2(1000) error on error),'$[*]'   columns(c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,json_table(jsonb_query(t1.c_jsonb,'$' returning varchar2(1000) error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;

select t2.* from tbl_jsonb_025 t1,json_table(jsonb_query(t1.c_jsonb,'$' returning clob error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,json_table(json_query(t1.c_json,'$' returning varchar2(1000) error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,json_table(t1.c_json,'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,jsonb_table(jsonb_query(t1.c_jsonb,'$' returning jsonb error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,jsonb_table(jsonb_query(jsonb_query(t1.c_jsonb,'$' returning jsonb error on error),'$' returning jsonb error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,jsonb_table(jsonb_query(jsonb_query(jsonb_query(t1.c_jsonb,'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,jsonb_table(jsonb_query(jsonb_query(jsonb_query(jsonb_query(jsonb_query(t1.c_jsonb,'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,jsonb_table(c_jsonb,'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,jsonb_table(jsonb_set(t1.c_jsonb,'$[4]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning jsonb error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;
select t2.* from tbl_jsonb_025 t1,jsonb_table(jsonb_set(jsonb_set(t1.c_jsonb,'$[4]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning jsonb error on error),'$[5]','{"k1":"esmen","k2":[10000,{"k3":20000}],"k3":{"k4":"english","k5":"math"}}' returning jsonb error on error),'$[*]'   columns(c1 varchar2(10) path '$.k1',c4 varchar2(100) path '$.k3.k4',c6 for ordinality)) t2 order by c6;

select json_query(t1.c_json,'$' returning varchar2(1000) error on error) from tbl_jsonb_025 t1;
select jsonb_query(jsonb_query(jsonb_query(jsonb_query(jsonb_query(t1.c_jsonb,'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning varchar2(1000) error on error) from tbl_jsonb_025 t1;
select json_query(jsonb_query(jsonb_query(jsonb_query(jsonb_query(t1.c_jsonb,'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning jsonb error on error),'$' returning varchar2(1000) error on error),'$' returning varchar2(1000) error on error) from tbl_jsonb_025 t1;
drop table if exists tbl_jsonb_025;

drop table if exists tbl_jsonb_025;
create table tbl_jsonb_025(id int,c_jsonb jsonb,c_json clob);
insert into tbl_jsonb_025 values(1,'[{"k1":[{"s1":["a","sd","-100",[0,100,[{"s2":"rr","s3":"周杰伦"}]]]},1000,"200we",{"d1":{"t1":"2021-7-21 09:23:45.66","t2":9999}}],"k2":{"q2":{"f2":"水杯","f3":"手机","f4":"fdfs","f5":["fdf",[100,200,"re",[1000,2000,[-1.234,{"w1":"终结者"}]]]]}},"k3":[{"g1":100},{"g2":{"g3":"nice"}},10000,{"g4":{"g5":{"g6":"2323","g7":-100000}}},"good boy","giraffe"]},{"s1#$%%@#":[null,0,-100,{"a2":null,"水果":"香蕉"},["富贵竹","panda","@#$$",[1000,"鼠标",null]]]},[100,[200,[300,[400,[500,[{"结果":"死机"}]]]]]],{"h1":{"h2":{"h3":{"h4":{"h5":["中国好娃娃"]}}}}}]','[{"k1":[{"s1":["a","sd","-100",[0,100,[{"s2":"rr","s3":"周杰伦"}]]]},1000,"200we",{"d1":{"t1":"2021-7-21 09:23:45.66","t2":9999}}],"k2":{"q2":{"f2":"水杯","f3":"手机","f4":"fdfs","f5":["fdf",[100,200,"re",[1000,2000,[-1.234,{"w1":"终结者"}]]]]}},"k3":[{"g1":100},{"g2":{"g3":"nice"}},10000,{"g4":{"g5":{"g6":"2323","g7":-100000}}},"good boy","giraffe"]},{"s1#$%%@#":[null,0,-100,{"a2":null,"水果":"香蕉"},["富贵竹","panda","@#$$",[1000,"鼠标",null]]]},[100,[200,[300,[400,[500,[{"结果":"死机"}]]]]]],{"h1":{"h2":{"h3":{"h4":{"h5":["中国好娃娃"]}}}}}]');
commit;

select c_jsonb from tbl_jsonb_025;
select jsonb_set(c_jsonb,'$[1]."s1#$%%@#"[3].a2','1000' returning jsonb error on error ) from tbl_jsonb_025;
select jsonb_set(c_jsonb,'$[1]."s1#$%%@#"[3].a2','1000' returning clob error on error ) from tbl_jsonb_025;
select jsonb_query(jsonb_set(c_jsonb,'$[1]."s1#$%%@#"[3].a2','1000' returning jsonb error on error ),'$[1]."s1#$%%@#"[3].a2' returning jsonb with wrapper error on error) from tbl_jsonb_025;
select jsonb_query(jsonb_set(c_jsonb,'$[1]."s1#$%%@#"[3].a2','1000' returning jsonb error on error ),'$[1]."s1#$%%@#"[3].a2' returning clob with wrapper error on error) from tbl_jsonb_025;
select jsonb_value(jsonb_query(jsonb_set(c_jsonb,'$[1]."s1#$%%@#"[3].a2','1000' returning jsonb error on error ),'$[1]."s1#$%%@#"[3].a2' returning jsonb with wrapper error on error) ,'$[0]' error on error)from tbl_jsonb_025;
select json_value(json_query(json_set(c_json,'$[1]."s1#$%%@#"[3].a2','1000' returning varchar2(1000) error on error ),'$[1]."s1#$%%@#"[3].a2' returning varchar2(100) with wrapper error on error) ,'$[0]' error on error )from tbl_jsonb_025;
drop table if exists tbl_jsonb_025;
