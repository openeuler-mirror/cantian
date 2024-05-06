--dv_mem_stats include json dynamic buffer 
select name from dv_mem_stats where name = 'json_dyn_buf';

--json parameter
show parameter _MAX_JSON_DYNAMIC_BUFFER_SIZE;

--_MAX_JSON_LEVEL is in [1M, 32T]
alter system set _MAX_JSON_DYNAMIC_BUFFER_SIZE = 0.1M;

--test single json array object, more than 1M
drop table if exists LOAD_CLOB_TABLE;
create TABLE LOAD_CLOB_TABLE(
	c1         clob
);
load data infile "./data/json_data_array.dat" into table LOAD_CLOB_TABLE
fields enclosed by '`' 
fields terminated by ',' 
lines terminated by '\n'
ignore 0 lines;
select length(c1) from load_clob_table;
select 1 from LOAD_CLOB_TABLE where c1 is json;
drop table if exists LOAD_CLOB_TABLE;

--test json level object, more than 32
drop table if exists LOAD_CLOB_TABLE;
create TABLE LOAD_CLOB_TABLE(
	c1         clob
);
load data infile "./data/json_data_level.dat" into table LOAD_CLOB_TABLE
fields enclosed by '`' 
fields terminated by ',' 
lines terminated by '\n'
ignore 0 lines;
select length(c1) from load_clob_table;
select 1 from LOAD_CLOB_TABLE where c1 is json;
drop table if exists LOAD_CLOB_TABLE;

--test json object pairs, more than 1M
drop table if exists LOAD_CLOB_TABLE;
create TABLE LOAD_CLOB_TABLE(
	c1         clob
);
load data infile "./data/json_data_object_pairs.dat" into table LOAD_CLOB_TABLE
fields enclosed by '`' 
fields terminated by ',' 
lines terminated by '\n'
ignore 0 lines;
select length(c1) from load_clob_table;
select 1 from LOAD_CLOB_TABLE where c1 is json;
drop table if exists LOAD_CLOB_TABLE;

--test JSON_LEVEL
select 1 from dual where '{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":"asdsadsa"}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}' is json;
select 1 from dual where '{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":{"A":"asdsadsa"}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}' is json;

--when the length of single element is more than 32767, it should display error info 
drop table if exists LOAD_CLOB_TABLE;
create TABLE LOAD_CLOB_TABLE(c1 clob);
insert into LOAD_CLOB_TABLE values('0123456789');
update LOAD_CLOB_TABLE set c1 = c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1;
update LOAD_CLOB_TABLE set c1 = c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1;
update LOAD_CLOB_TABLE set c1 = c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1;
update LOAD_CLOB_TABLE set c1 = c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1 || c1;
update LOAD_CLOB_TABLE set c1 = '["' || c1;
update LOAD_CLOB_TABLE set c1 = c1 || '"]';
select length(c1) from LOAD_CLOB_TABLE;
select 1 from LOAD_CLOB_TABLE where c1 is json;
drop table if exists LOAD_CLOB_TABLE;

drop table if exists test_json_src;
create table test_json_src(a clob);
insert into test_json_src values(lpad('dscds', 8000, 'asdcsaf'));
update test_json_src set a = a || lpad('dscds', 8000, 'asdcsaf');
update test_json_src set a = a || lpad('dscds', 8000, 'asdcsaf');
update test_json_src set a = a || lpad('dscds', 8000, 'asdcsaf');
update test_json_src set a = a || lpad('dscds', 8000, 'asdcsaf');
update test_json_src set a = a || lpad('dscds', 8000, 'asdcsaf');
update test_json_src set a = a || lpad('dscds', 8000, 'asdcsaf');
select length(a) from test_json_src;
update test_json_src set a = '{"name":"' || a || '"}';
select length(a) from test_json_src;
select 1 from test_json_src where a is json;
select length(json_value(a, '$.name' returning clob)) from test_json_src;
select length(json_query(a, '$' returning clob)) from test_json_src;

drop table if exists test_json_dst;
create table test_json_dst(a clob check (a is json));
insert into test_json_dst select * from test_json_src;
select length(json_value(a, '$.name' returning clob)) from test_json_dst;
select length(json_query(a, '$' returning clob)) from test_json_dst;
drop table if exists test_json_src;
drop table if exists test_json_dst;
