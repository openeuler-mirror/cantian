---test json 
select * from SYS_DUMMY where 'dsd' is not json;
select * from SYS_DUMMY where '{' is not json;
select * from SYS_DUMMY where '{}' is not json;
select * from SYS_DUMMY where '{"name":"er"}' is json;
select * from SYS_DUMMY where NULL is not json;
select * from SYS_DUMMY where NULL is json;

drop table if exists student;
create table student(id int,info varchar2(8000) check (info is json), teachers varchar2(8000) check(teachers is JSON));
--test unipue index
create unique index ind_unique_json on student(JSON_VALUE(info,'$.name'));
insert into student values(1,'{"name":"merry","birthday":"2012-04-08","class":"02-1"}','{"Liberal_arts":{"History":"Aaron","Chinese":"lilei"}}');
insert into student values(1,'{"name":"merry","birthday":"2012-05-08","class":"03-1"}','{"Liberal_arts":{"History":"Aaron","Chinese":"lilei"}}');
drop index ind_unique_json on student;

create index ind_t on student(JSON_VALUE(info,'$.name'));
insert into student values(1,'{"name":"merry","birthday":"2012-04-08","class":"02-1"}','{"Liberal_arts":{"History":"Abraham ","Chinese":"Adolph"}}');
insert into student values(2,'{"name":"kite","birthday":"2012-06-08","class":"03-1"}','');
insert into student values(3,'{"name":"hanmeimei","birthday":"2012-07-08","class":"04-1"}','{"Liberal_arts":{"History":"Abraham ","Chinese":"Adolph"}}');
----test JSON_QUERY and JSON_VALUE
SELECT JSON_VALUE(info,'$.birthday') as birthday from student where JSON_VALUE(info,'$.name')='merry';
SELECT JSON_VALUE(teachers,'$') from student;
SELECT JSON_VALUE(teachers,'$.Liberal_arts') from student;
SELECT JSON_VALUE(teachers,'$.Liberal_arts.History') from student;
SELECT JSON_QUERY(teachers, '$' ERROR ON ERROR) FROM student;
SELECT JSON_QUERY(teachers, '$.Liberal_arts' ERROR ON ERROR) FROM student;
SELECT JSON_QUERY(teachers, '$.Liberal_arts.History' ERROR ON ERROR) FROM student;
---test json_mergepatch
SELECT json_mergepatch(info,'{"name":"merry1"}') from student where JSON_VALUE(info, '$.name')='merry';
SELECT info from student where JSON_VALUE(info, '$.name')='merry';
SELECT json_mergepatch(info,'{"name":"merry1","birthday":"2012-05-08","class":"03-1"}') from student where JSON_VALUE(info, '$.name')='merry';
SELECT JSON_VALUE(info,'$.name') from student where id = 1;
---test json_array
SELECT json_array('true','test','','NULL') from SYS_DUMMY;
SELECT json_array('true' format json, null format json ABSENT on null) from SYS_DUMMY;
SELECT json_array('true' format json, null format json NULL on null returning varchar2(23)) from SYS_DUMMY;
select json_array('["sd","123",NULL]') from SYS_DUMMY;
select json_array('["sd","123",NULL]' FORMAT json) from SYS_DUMMY;
---test json_object
select json_object(key 'class' is '"05-1"' FORMAT json,key 'name' is NULL ABSENT on null) from SYS_DUMMY;
select json_object(key 'class' is '"05-1"' FORMAT json,key 'name' is NULL NULL on null) from SYS_DUMMY;
select json_object(key 'class' is '"05-1"' FORMAT json,key 'name' is '"NULL"' ABSENT on null) from SYS_DUMMY;
---test json_exists
select json_exists(teachers,'$.Liberal_arts') from student where id = 1;
select json_exists(teachers,'$.Liberal_arts.History') from student where id = 1;
select json_exists(teachers,'$.Liberal_arts') from student where id = 1;
select json_exists('{"name":"NULL"}','$.name') from SYS_DUMMY;
select json_exists('{"name":"NULL"}','$.class') from SYS_DUMMY;
---test json_array_length, Exception scenarios
select json_array_length() from SYS_DUMMY;
select json_array_length(NULL) from SYS_DUMMY;
select json_array_length("sd":"de") from SYS_DUMMY;
select json_array_length('["sd":"de"') from SYS_DUMMY;
select json_array_length('["sd":"de"]') from SYS_DUMMY;
select json_array_length('[{"sd":"de"]') from SYS_DUMMY;
select json_array_length('["sd":"de"}]') from SYS_DUMMY;
---test json_array_length, the depth is one
select json_array_length('["sd"]') from SYS_DUMMY;
select json_array_length('[{"sd":"de"}]') from SYS_DUMMY;
select json_array_length('["sd","wd"]') from SYS_DUMMY;
select json_array_length('[{"sd":"de"},{"qa":"ret"}]') from SYS_DUMMY;
select json_array_length('["sd",{"qa":"ret"}]') from SYS_DUMMY;
select json_array_length('["sd",{"qa":"ret"}]') from SYS_DUMMY;
select json_array_length('[{"qa":"ret"},"sd"]') from SYS_DUMMY;
select json_array_length('[{"qa":"ret"},"sd",{"qa":"ret"}]') from SYS_DUMMY;
select json_array_length('[{"qa":"ret"},"sd","qa"]') from SYS_DUMMY;
select json_array_length('["sd",{"qa":"ret"},"qa"]') from SYS_DUMMY;
select json_array_length('["sd","qa",{"qa":"ret"}]') from SYS_DUMMY;
---test json_array_length, the depth is two
select json_array_length('[{"qa":{"er":"rt"}}]') from SYS_DUMMY;
select json_array_length('[{"qa":{"er":"rt"}}]') from SYS_DUMMY;
select json_array_length('["as",{"qa":{"er":"rt"}}]') from SYS_DUMMY;
select json_array_length('[{"qa":{"er":"rt"}},"as"]') from SYS_DUMMY;
select json_array_length('[{"qa":{"er":"rt"}},"as","sd"]') from SYS_DUMMY;
select json_array_length('["as",{"qa":{"er":"rt"}},"sd"]') from SYS_DUMMY;
select json_array_length('["as","sd",{"qa":{"er":"rt"}}]') from SYS_DUMMY;
select json_array_length('[{"as":"sd"},{"qa":{"er":"rt"}}]') from SYS_DUMMY;
select json_array_length('["as",{"as":"sd"},{"qa":{"er":"rt"}}]') from SYS_DUMMY;
select json_array_length('[{"as":"sd"},"as",{"qa":{"er":"rt"}}]') from SYS_DUMMY;
select json_array_length('[{"as":"sd"},{"qa":{"er":"rt"}},"as"]') from SYS_DUMMY;
select json_array_length('["df",{"as":"sd"},{"qa":{"er":"rt"}},"as"]') from SYS_DUMMY;
select json_array_length('[{"as":"sd"},"df",{"qa":{"er":"rt"}},"as"]') from SYS_DUMMY;
select json_array_length('[{"as":"sd"},{"qa":{"er":"rt"}},"df","as"]') from SYS_DUMMY;

drop table if exists student;

drop table if exists test;
create table test(a int, b varchar(300));
insert into test values(1, 'aaaaaaaa');
insert into test values(2,'bbbb				bbbb');
insert into test values(3, 'cc
cc
c
ccc');
select length(b) from test;
select json_object('b' is b) from test;
select length(json_value(json_object('b' is b), '$.b')) from test;

--test when the length of second parameter is 32
select json_value('[1,2,3,4]', '$[12345678901234567890123456789000]') from dual;