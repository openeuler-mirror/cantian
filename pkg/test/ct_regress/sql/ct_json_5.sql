--do delete
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.name');
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.age');
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho');
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[0,2]');
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[0,2, 5, 15, 86]');

select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$');  --null
select 1 from SYS_DUMMY where json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$') is null;  --null

select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.name', '{"bbb":66, "aaa":54}');  --replace
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[0]', '{"bbb":66, "aaa":54}');  --replace
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[1 to 3]', '{"bbb":66, "aaa":54}');  --replace
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[1 to 3, 8, 9]', '{"bbb":66, "aaa":54}');  --replace
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[8, 9]', '{"bbb":66, "aaa":54}');  --add
select json_set(json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[8, 9]', '{"bbb":66, "aaa":54}'), '$.ho[8, 9]', '{"bbb":66, "aaa":54}');  --add
select json_set(json_set(json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[8, 9]', '{"bbb":66, "aaa":54}'), '$.ho[8, 9]', '{"bbb":66, "aaa":54}'), '$.ho[8, 9]', '{"bbb":66, "aaa":54}');  --add
select json_set(json_set(json_set(json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.ho[1 to 3, 8, 9]', '{"bbb":66, "aaa":54}'), '$.ho[8, 9]', '{"bbb":66, "aaa":54}'), '$.ho[8, 9]', '{"bbb":66, "aaa":54}'), '$.ho[8, 9]', '{"bbb":66, "aaa":54}');  --add

select json_set('{"A":{"B":{"C":true}}}', '$.A.B.C', '{"bbb":66, "aaa":54}');  --replace
select json_set('{"A":{"B":{"C":true}}}', '$.A.B.C', '{"D":{"bbb":66, "aaa":54}}');  --replace
select json_set('{"A":{"B":{"C":true}}}', '$.A.B.C.D', '{"bbb":66, "aaa":54}');  --no change
select json_set('{"A":{"B":{"C":{}}}}', '$.A.B.C.D', '{"bbb":66, "aaa":54}');  --add
select json_set('{"A":{"B":{"C":{}}}}', '$.A.B.C.D.D.D.D.D.D.D', '{"bbb":66, "aaa":54}');  --no change
select json_set('{"A":{"B":{"C":true}}}', '$.A.B.C.H.K.K.F', 'false');  --no change
select json_set('{"A":{"B":{"C":[15, 16]}}}', '$.A.B.C.D', '{"bbb":66, "aaa":54}');  --no change
select json_set('{"A":{"B":{"C":true}}}', '$.A.B.D', 'false');  --add

--insert, add item into an array
select json_set('{"A":{"B":{"C":[15, 16]}}}', '$.A.B.C[6]', '{"bbb":66, "aaa":54}');  --insert
select json_query(json_set('{"A":{"B":{"C":[15, 16]}}}', '$.A.B.C[6]', '{"bbb":66, "aaa":54}'), '$.A.B.C[2]'); 
select json_set('{"A":{"B":{"C":[15, 16]}}}', '$.A.B.C[7]', '{"bbb":66, "aaa":54}');
select json_query(json_set('{"A":{"B":{"C":[15, 16]}}}', '$.A.B.C[7]', '{"bbb":66, "aaa":54}'), '$.A.B.C[2]'); 
select json_set('{"A":{"B":{"C":[15, 16]}}}', '$.A.B.C[8]', '{"bbb":66, "aaa":54}');
select json_query(json_set('{"A":{"B":{"C":[15, 16]}}}', '$.A.B.C[8]', '{"bbb":66, "aaa":54}'), '$.A.B.C[2]'); 

select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.aaaa', '{"xxxx":54}');  --add
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.aaaa', '[1,2,3]');  --add
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.aaaa.bbbb', '[1,2,3]');  --no change

--replace
select json_set('[[1,2,3,4]]', '$[0][0]', '"csdvcfedvef"');
select json_set('[[1,2,3,4]]', '$[0][0]', 'true');
select json_set('[[1,2,3,4]]', '$[0][0]', 'false');
select json_set('[[1,2,3,4]]', '$[0][0]', 'null');
select json_set('[[1,2,3,4]]', '$[0][0]', '1235.25632');
select json_set('[[1,2,3,4]]', '$[0][0]', 1235.25632);
select json_set('[[1,2,3,4]]', '$[0][0]', '{"aaa":54}');
select json_set('[[1,2,3,4]]', '$[0][0]', '[[[[123]]]]');
select json_set('[[1,2,3,4]]', '$[0][1 to 2]', '{"aaa":54}');
select json_set('[[1,2,3,4]]', '$[0][*]', '{"aaa":54}');
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[*]', '{"aaa":54}');
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[*][*]', '{"aaa":54}');
select json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}');  --add
select json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}', true);  --add
select json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}', true returning clob);  --add
select json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}', true returning clob error on error);  --add
select json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}', false);  --no change
select json_set('[[1,2,3,4]]', '$[1 to 55]', '{"aaa":54}');  --add

select json_set('[{"f1":1,"f2":null},2,null,3]', '$[0].f1', '[2,3,4]', false);  --replace
select json_set('[{"f1":1,"f2":null},2]', '$[0].f3', '[2,3,4]');  --add
select json_set('[{"f1":1,"f2":null},2]', '$[0].f3', '[2,3,4]', true);  --add
select json_set('[{"f1":1,"f2":null},2]', '$[0].f3', '[2,3,4]', false);  --no change

select json_set('[{"f2":1, "f0":1, "f1":null, "f5":null, "f4":null, "f7":null, "f8":null, "f6":null},2,null,3]', '$[0].a3', '[2,3,4]');  --add
select json_query(json_set('[{"f2":1, "f0":1, "f1":null, "f5":null, "f4":null, "f7":null, "f8":null, "f6":null},2,null,3]', '$[0].a3', '[2,3,4]'), '$[0].a3');  --add
select json_set('[{"f2":1, "f0":1, "f1":null, "f5":null, "f4":null, "f7":null, "f8":null, "f6":null},2,null,3]', '$[0].f3', '[2,3,4]');  --add
select json_query(json_set('[{"f2":1, "f0":1, "f1":null, "f5":null, "f4":null, "f7":null, "f8":null, "f6":null},2,null,3]', '$[0].f3', '[2,3,4]'), '$[0].f3');  --add
select json_set('[{"f2":1, "f0":1, "f1":null, "f5":null, "f4":null, "f7":null, "f8":null, "f6":null},2,null,3]', '$[0].gggg', '[2,3,4]');  --add
select json_query(json_set('[{"f2":1, "f0":1, "f1":null, "f5":null, "f4":null, "f7":null, "f8":null, "f6":null},2,null,3]', '$[0].gggg', '[2,3,4]'), '$[0].gggg');  --add

--====================================== replacement ======================================
--For replacement, no matter what type of data is matched, the replacement can be performed only when the number of data is matched.
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[*][*]', '{"aaa":54}');  --replace
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[0][*]', '{"aaa":54}');  --replace
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[1][1 to 2]', '{"aaa":54}');  --replace
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[8][*]', '{"aaa":54}');  --no change
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[*][8]', '{"aaa":54}');  --no match so insert

--====================================== deletion ======================================
--For deletion, the element found in the last path must belong to an existing object or array, because only objects and arrays can delete data.
--In addition, no matter what type of data is matched, the data can be deleted only when the number of data is matched.
--If the last searched element belongs to an array, delete itself.
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[*][*]');  --delete
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[*]');  --delete
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[8]');  --no change
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[*][8]');  --no change
--If the last searched element belongs to an object, delete the object.
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.age');  --delete
select json_set('{"name":"andy", "age":18, "addr":"China", "ho":[1,2,3,4]}', '$.agessss');  --no change

--====================================== addition ======================================
--For addition, the last searched element must belong to an existing object or array, because only objects and arrays can be added.
--If the last searched element belongs to an object, the key value of the last step must not exist, and other path steps must exist.
select json_set('{"A":{"B":{"C":true}}}', '$.A.B.D', 'false');  --add
select json_set('{"A":{"B":{"C":true}}}', '$.A.B.C.D', '{"aaa":54}');  --no change
select json_set('{"A":{"B":{"C":{}}}}', '$.A.B.C.D', '{"aaa":54}');  --add
select json_set('{"A":{"B":{"C":true}}}', '$.XX.B.C.D', '{"aaa":54}');  --no change
--If the last searched element belongs to an array, the element subscript of the last path in the path expression does not exist. The element subscript of the last path can be added only when the number of elements in the array is greater than or equal to the number of elements in the array. Other paths must exist. Otherwise, the element subscript of the last path cannot be added.
select json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}');  --add
select json_set('[[1,2,3,4]]', '$[1][6]', '{"aaa":54}', false);  --no change
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[*][8]', '"hello"');  --add
select json_set('[[1,2,3,4],[1,2,3,4]]', '$[5][8]', '"hello"');  --no change

select json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}');  --add
select json_set(json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}'), '$[0][4].bbb', '"hello"');  --add
select json_set(json_set(json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}'), '$[0][4].bbb', '"hello"'), '$[0][4].bbb', '"world"');  --replace
select json_set(json_set(json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}'), '$[0][4].bbb', '"hello"'), '$[1]', '"world"');  --add
select json_set(json_set(json_set(json_set('[[1,2,3,4]]', '$[0][6]', '{"aaa":54}'), '$[0][4].bbb', '"hello"'), '$[1]', '"world"'), '$[1]');  --delete

------------------------------------
-- BASE FUNC TEST:DDL
------------------------------------
drop table if exists tbl_json_base_test; ---Succeed.
create table tbl_json_base_test(a CLOB check(a IS JSON), b int);  ---Succeed.
drop table if exists tbl_json_base_test; ---Succeed.
create table tbl_json_base_test(a CLOB check(a IS JSON) primary key, b int); ---  Cannot create index on 'BLOB'
create table tbl_json_base_test(a CLOB check(a IS JSON), b int);  ---Succeed.
drop table if exists tbl_json_base_test; ---Succeed.
truncate table tbl_json_base_test; ---table does not exist
create table tbl_json_base_test(a CLOB check(a IS JSON), b int primary key);---Succeed.
insert into tbl_json_base_test values('{"kex_1":{"kex_2":{"kex_3":{"kex_4":{"kex_5":[{"kex_6":"six"}]}}}}}',19);   ---1 rows affected.
create table tbl_json_base_test(a CLOB check(a IS JSON), b int primary key);---Succeed.
truncate table tbl_json_base_test; ---Succeed.
insert into tbl_json_base_test values('{"kex_1":{"kex_2":{"kex_3":{"kex_4":{"kex_5":[{"kex_6":"six"}]}}}}}',19);   ---1 rows affected.                            
drop table if exists tbl_json_base_test; ---Succeed.
create table tbl_json_base_test(a CLOB check(a IS JSON));
insert into tbl_json_base_test values('[{"AAA":"AAA"}, {"BBB":"BBB"}, {"CCC":"CCC"}, {"DDD":"DDD"}, {"EEE":"EEE"}]');
insert into tbl_json_base_test values('[{"AAA":"AAA"}, {"BBB":"BBB"}, {"CCC":"CCC"}, {"DDD":"DDD"}, {"EEE":"EEE"}]');
insert into tbl_json_base_test values('[{"AAA":"AAAa"}, {"BBB":"BBBa"}, {"CCC":"CCCa"}, {"DDD":"DDDa"}, {"EEE":"EEEa"}]');
commit;
drop index if exists jsonb_index on tbl_json_base_test;---Succeed.
create index jsonb_index on tbl_json_base_test(jsonb_value(a, '$[0].AAA')); ---Succeed.
drop index if exists jsonb_index on tbl_json_base_test; ---Succeed.
drop table if exists tbl_json_base_test; ---Succeed.
drop table if exists tbl_json_base_test;
create table tbl_json_base_test(a jsonb);
create unique index tbl_json_base_test_idx on tbl_json_base_test(jsonb_value(a, '$.AAA' returning varchar2(1024)), jsonb_value(a, '$.BBB' returning varchar2(1024)));
insert into tbl_json_base_test values('{"AAA" : "111", "BBB" : "222", "CCC" : "333"}');
insert into tbl_json_base_test values('{"AAA" : "111", "BBB" : "222", "CCC" : "333"}'); -- error
insert into tbl_json_base_test values('{"AAA" : "111", "BBB" : "000", "CCC" : "333"}');
select jsonb_query(a, '$') as val from tbl_json_base_test where jsonb_value(a, '$.AAA' returning varchar2(1024)) = '111';
select jsonb_query(a, '$') as val from tbl_json_base_test where jsonb_value(a, '$.AAA' returning varchar2(1024)) = '111' and jsonb_value(a, '$.BBB' returning varchar2(1024)) = '222';
drop table if exists tbl_json_base_test;
------------------------------------
-- BASE FUNC TEST:DML
------------------------------------
drop table if exists tbl_json_base_test; ---Succeed.
drop table if exists tbl_json_base_test; ---Succeed.
create table tbl_json_base_test(a CLOB check(a IS JSON), b int primary key);  ---Succeed.
insert into tbl_json_base_test values('[]',1);     ---1 rows affected.    
insert into tbl_json_base_test values('[null]',2); ---1 rows affected. 
insert into tbl_json_base_test values('["string"]',3);  ---1 rows affected.       
insert into tbl_json_base_test values('[true]',4);   ---1 rows affected. 
insert into tbl_json_base_test values('[false]',5);   ---1 rows affected. 
insert into tbl_json_base_test values('[-101998]',6);  ---1 rows affected. 
insert into tbl_json_base_test values('[101998]',7);   ---1 rows affected. 
insert into tbl_json_base_test values('[-101998545554.101454455451998]',8);---1 rows affected.  
insert into tbl_json_base_test values('[101998545554.101454455451998]',9); ---1 rows affected. 
insert into tbl_json_base_test values('[1,2,3,4]',10);---1 rows affected. 
insert into tbl_json_base_test values('["world","time","room","chairman"]',11); ---1 rows affected.       
insert into tbl_json_base_test values('[true,false,true,false]', 12); ---1 rows affected.                  
insert into tbl_json_base_test values('[-124554.115454582,124554.115454582,565656556454787512121212,565656556454787512121212]',13); ---1 rows affected. 
insert into tbl_json_base_test values('[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]',14); --1 rows affected.
insert into tbl_json_base_test values('[["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]]',15); --1 rows affected.   
insert into tbl_json_base_test values('
 [ {"programmers": [
    { "firstName": "Brett", "lastName":"McLaughlin", "email": "brett@newInstance.com" },
    { "firstName": "Jason", "lastName":"Hunter", "email": "jason@servlets.com" },
    { "firstName": "Elliotte", "lastName":"Harold", "email": "elharo@macfaq.com" }
   ]},
  {"authors": [
    { "firstName": "Isaac", "lastName": "Asimov", "genre": "science fiction" },
    { "firstName": "Tad", "lastName": "Williams", "genre": "fantasy" },
    { "firstName": "Frank", "lastName": "Peretti", "genre": "christian fiction" }
   ]},
  {"musicians": [
    { "firstName": "Eric", "lastName": "Clapton", "instrument": "guitar" },
    { "firstName": "Sergei", "lastName": "Rachmaninoff", "instrument": "piano" }
   ]}
  ]',16);   ---1 rows affected.   
insert into tbl_json_base_test values('{"kex_1":2738937798.925638525,"kex_2":"string","kex_3":false,"kex_4":[1,2,3,4],"kex_5":{"k_1":1,"k_2":"string"}}',17);     --1 rows affected.
insert into tbl_json_base_test values('{"kex_1":44454547.28534326,"kex_2":"string","kex_3":false,"kex_4":{"k_1":"string","k_2":123,"kex_3":
[["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]]}}',18);   --1 rows affected.
insert into tbl_json_base_test values('{"kex_1":{"kex_2":{"kex_3":{"kex_4":{"kex_5":[{"kex_6":"six"}]}}}}}',19);   --1 rows affected.
insert into tbl_json_base_test values('{"count":4,"filename":"chiefbook","line":{
"one":{"a":0,"b":0,"c":0.292,"d":820,"ex":852,"ey":571,"id":0,"sx":0,"sy":820},
"two":{"a":0,"b":0,"c":-1.187,"d":1680.5999755859375,"ex":934,"ey":572,"id":1,"sx":506,"sy":1080},
"three":{"a":0,"b":0,"c":0.531,"d":26.270000457763672,"ex":1919,"ey":1045,"id":2,"sx":1028,"sy":572},
"four":{"a":0,"b":0,"c":0.316,"d":232.5,"ex":1919,"ey":838,"id":3,"sx":1076,"sy":572}},"timeStamp":{"nesc:":5678,"sec:":1234}}',20);   --1 rows affected.
delete tbl_json_base_test where b=1; ---1 rows affected.
delete tbl_json_base_test where b=1;---0 rows affected.
select b from tbl_json_base_test; ---19 rows affected.
select count(*) from tbl_json_base_test; ---19
delete tbl_json_base_test where b=2; ---1 rows affected.
delete tbl_json_base_test where b=3; ---1 rows affected.
delete tbl_json_base_test where b=4;  ---1 rows affected.
select b from tbl_json_base_test; ---16 rows affected.
select count(*) from tbl_json_base_test; ---1 rows affected.
delete tbl_json_base_test where b > 20; ---0 rows affected.
delete tbl_json_base_test where b > 18;  ---2 rows affected.
select b from tbl_json_base_test; ---14 rows fetched.
select count(*) from tbl_json_base_test;---1 rows affected.
delete tbl_json_base_test where b < 10; ---5 rows affected.
select count(*) from tbl_json_base_test;---1 rows affected:9
delete tbl_json_base_test where b>15 or b<12;---5 rows affected.
delete tbl_json_base_test where b<15 and b>12; ---2 rows affected.
delete tbl_json_base_test where b = 15; ---1 rows affected.
delete tbl_json_base_test where b = 12; ---1 rows affected.
select count(*) from tbl_json_base_test; ---1 rows affected:0
insert into tbl_json_base_test values('[]',1);     ---1 rows affected.    
insert into tbl_json_base_test values('[null]',2); ---1 rows affected. 
insert into tbl_json_base_test values('["string"]',3);  ---1 rows affected.       
insert into tbl_json_base_test values('[true]',4);   ---1 rows affected. 
insert into tbl_json_base_test values('[false]',5);   ---1 rows affected. 
insert into tbl_json_base_test values('[-101998]',6);  ---1 rows affected. 
insert into tbl_json_base_test values('[101998]',7);   ---1 rows affected. 
insert into tbl_json_base_test values('[-101998545554.101454455451998]',8);---1 rows affected.  
insert into tbl_json_base_test values('[101998545554.101454455451998]',9); ---1 rows affected. 
insert into tbl_json_base_test values('[1,2,3,4]',10);---1 rows affected. 
insert into tbl_json_base_test values('["world","time","room","chairman"]',11); ---1 rows affected.       
insert into tbl_json_base_test values('[true,false,true,false]', 12); ---1 rows affected.                  
insert into tbl_json_base_test values('[-124554.115454582,124554.115454582,565656556454787512121212,565656556454787512121212]',13); ---1 rows affected. 
insert into tbl_json_base_test values('[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]',14); --1 rows affected.
insert into tbl_json_base_test values('[["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]]',15); --1 rows affected.   
insert into tbl_json_base_test values('
 [ {"programmers": [
    { "firstName": "Brett", "lastName":"McLaughlin", "email": "brett@newInstance.com" },
    { "firstName": "Jason", "lastName":"Hunter", "email": "jason@servlets.com" },
    { "firstName": "Elliotte", "lastName":"Harold", "email": "elharo@macfaq.com" }
   ]},
  {"authors": [
    { "firstName": "Isaac", "lastName": "Asimov", "genre": "science fiction" },
    { "firstName": "Tad", "lastName": "Williams", "genre": "fantasy" },
    { "firstName": "Frank", "lastName": "Peretti", "genre": "christian fiction" }
   ]},
  {"musicians": [
    { "firstName": "Eric", "lastName": "Clapton", "instrument": "guitar" },
    { "firstName": "Sergei", "lastName": "Rachmaninoff", "instrument": "piano" }
   ]}
  ]',16);   ---1 rows affected.   
insert into tbl_json_base_test values('{"kex_1":2738937798.925638525,"kex_2":"string","kex_3":false,"kex_4":[1,2,3,4],"kex_5":{"k_1":1,"k_2":"string"}}',17);     --1 rows affected.
insert into tbl_json_base_test values('{"kex_1":44454547.28534326,"kex_2":"string","kex_3":false,"kex_4":{"k_1":"string","k_2":123,"kex_3":
[["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]]}}',18);   --1 rows affected.
insert into tbl_json_base_test values('{"kex_1":{"kex_2":{"kex_3":{"kex_4":{"kex_5":[{"kex_6":"six"}]}}}}}',19);   --1 rows affected.
insert into tbl_json_base_test values('{"count":4,"filename":"chiefbook","line":{
"one":{"a":0,"b":0,"c":0.292,"d":820,"ex":852,"ey":571,"id":0,"sx":0,"sy":820},
"two":{"a":0,"b":0,"c":-1.187,"d":1680.5999755859375,"ex":934,"ey":572,"id":1,"sx":506,"sy":1080},
"three":{"a":0,"b":0,"c":0.531,"d":26.270000457763672,"ex":1919,"ey":1045,"id":2,"sx":1028,"sy":572},
"four":{"a":0,"b":0,"c":0.316,"d":232.5,"ex":1919,"ey":838,"id":3,"sx":1076,"sy":572}},"timeStamp":{"nesc:":5678,"sec:":1234}}',20);   --1 rows affected
update tbl_json_base_test set a = '[{"key":"value"}]' where b=1; ---1 rows affected.
select a from tbl_json_base_test where b=1;---0F0000000111015003813004076B657976616C7565
update tbl_json_base_test set a = '[{"one":1}]' where b=1; ---1 rows affected.
select a from tbl_json_base_test where b=1; ---0B0000000111015003814004076F6E6531
delete tbl_json_base_test where b=20;---1 rows affected.
delete tbl_json_base_test where b=20;---0 rows affected.
update tbl_json_base_test set a = '[{"one":1}]' where b=20; ---0 rows affected.
update tbl_json_base_test set a = '[{"one":1}]' where b <=10; ---10 rows affected.
select a from tbl_json_base_test where b<=10; ---10* 0B0000000111015003814004076F6E6531
update tbl_json_base_test set a = '[{"one":1}]' where b >=10 and b <=15;---6 rows affected.
select a from tbl_json_base_test where b >=10 and b <=15; ---6* 0B0000000111015003814004076F6E6531
delete tbl_json_base_test where b =16;---1 rows affected.
delete tbl_json_base_test where b =17;---1 rows affected.
delete tbl_json_base_test where b =18;---1 rows affected.
delete from tbl_json_base_test where b =19;---1 rows affected.
select a from tbl_json_base_test where b >15;---0 rows fetched.
select length(a) from tbl_json_base_test;--- 15* 17
drop table if exists tbl_json_base_test; ---Succeed.
------------------------------------
--JSONB_VALUE
------------------------------------
drop table if exists tbl_json_ft1_test;          ---Succeed.
create table tbl_json_ft1_test(a CLOB check(a IS JSON), b int primary key);  ---Succeed.
insert into tbl_json_ft1_test values('{"user name":"jsonb","id":"123456789abcdefghijk", "age":35, "phone number":"033-5578456978251","vip level":3,"new user ?":false,"preference":["book","music","run"]}', 0); ---1 rows affected.
select jsonb_value(a, '$."user name"') from tbl_json_ft1_test where b = 1; ---1 rows fetched. jsonb
insert into tbl_json_ft1_test values('{ "user_name":"jsonb","id":"123456789abcdefghijk", "age":35, "phone_number":"033-5578456978251","vip_level":3,"new_user_?":false,"preference":["book","music","run"]}', 2);  ---1 rows affected.
select json_value(a, '$.user_name') from tbl_json_ft1_test where b = 2;---1 rows fetched.
select json_value(a, '$.id') from tbl_json_ft1_test where b = 2;---1 rows fetched.
select json_value(a, '$.age') from tbl_json_ft1_test where b = 2;---1 rows fetched.
select json_value(a, '$.phone_number') from tbl_json_ft1_test where b = 2;---1 rows fetched
select json_value(a, '$.vip_level') from tbl_json_ft1_test where b = 2;---1 rows fetched
select json_value(a, '$.preference[0]') from tbl_json_ft1_test where b = 2;---1 rows fetched
select json_value(a, '$.preference[1]') from tbl_json_ft1_test where b = 2;---1 rows fetched
select json_value(a, '$.preference[2]') from tbl_json_ft1_test where b = 2;---1 rows fetched
insert into tbl_json_ft1_test values('{"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMN":1}', 3);
select json_value(a, '$.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMN') from tbl_json_ft1_test where b = 3;---1 rows fetched 
insert into tbl_json_ft1_test values('[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1,"z"],2],3],4],5],6],7],8],9],10],11],12],13],14],15],16],17],18],19],20],21],22],23],24],25],26],27],28],29],30],31],32],33],34],35],36],37],38],39],40],41],42],43],44],45]',4); //find troble 未校验
select json_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][1]') from tbl_json_ft1_test where b = 4;
insert into tbl_json_ft1_test values('[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1,"z"],2],3],4],5],6],7],8],9],10],11],12],13],14],15],16],17],18],19],20],21],22],23],24],25],26],27],28],29],30],31],32]',5); //未校验
select json_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][1]') from tbl_json_ft1_test where b = 5;  ----1 rows fetched  z
select json_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0]') from tbl_json_ft1_test where b = 5;  ----1 rows fetched. 1
select json_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][1]') from tbl_json_ft1_test where b = 5; ---1 rows fetched 2
insert into tbl_json_ft1_test values('{"key":123456789123456789123456789123456789}',6);
select json_value(a,'$.key') from tbl_json_ft1_test where b=6;---1 rows fetched:123456789123456789123456789123456789
insert into tbl_json_ft1_test values('{"key":123456789123456789123456789123456789123456789}',7); ---1 rows affected.
select json_value(a,'$.key') from tbl_json_ft1_test where b=7;  ---123456789123456789123456789123456789123456789
insert into tbl_json_ft1_test values('{"key":123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789}',8); ---1 rows affected.
select json_value(a,'$.key') from tbl_json_ft1_test where b=8;  
---123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789
insert into tbl_json_ft1_test values('{"key":123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789}',9); ---1 rows affected.
select json_value(a,'$.key') from tbl_json_ft1_test where b=9;
 ---123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789
insert into tbl_json_ft1_test values('{"key":12345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912}',10); ---1 rows affected.
select json_value(a,'$.key') from tbl_json_ft1_test where b=10;
---12345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912
insert into tbl_json_ft1_test values('{"key":123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123}',11); ---invalid json number
insert into tbl_json_ft1_test values('{"one_order":[1],"two_order":[[1,2,3],[4,5,6],[7,8,9]]}',11);
select json_value(a,'$.two_order[0][0]') from tbl_json_ft1_test where b=11;---1
select json_value(a,'$.two_order[1][1]') from tbl_json_ft1_test where b=11;---5
select json_value(a,'$.two_order[2][2]') from tbl_json_ft1_test where b=11;---9
insert into tbl_json_ft1_test values('{"one_order":[1],"two_order":[[1,2,3],[4,5,6],[7,8,9]],
"three_order":[[[111,112,113],[121,122,123],[131,132,133]],[[211,212,213],[221,222,223],[231,232,233]],[[311,312,313],[321,322,323],[331,332,333]]]
}',12); ---1 rows affected.
select json_value(a,'$.three_order[0][0][0]') from tbl_json_ft1_test where b=12;---111
select json_value(a,'$.three_order[1][1][1]') from tbl_json_ft1_test where b=12;---222
select json_value(a,'$.three_order[2][2][2]') from tbl_json_ft1_test where b=12;---333
select json_value(a,'$.three_order[0][1][2]') from tbl_json_ft1_test where b=12;---123
select json_value(a,'$.three_order[2][1][0]') from tbl_json_ft1_test where b=12;---321
insert into tbl_json_ft1_test values('{"one_order":[1],"two_order":[[1,2,3],[4,5,6],[7,8,9]],
"three_order":[[[111,112,113],[121,122,123],[131,132,133]],[[211,212,213],[221,222,223],[231,232,233]],[[311,312,313],[321,322,323],[331,332,333]]],
"four_order":[[[[4111,112,113],[4121,122,123],[4131,4132,4133]],[[4211,4212,4213],[4221,4222,4223],[4231,4232,4233]],[[4311,4312,4313],[4321,4322,4323],[4331,4332,4333]]],
               [[[4111,4112,4113],[4121,4122,4123],[4131,4132,4133]],[[4211,4212,4213],[4221,4222,4223],[4231,4232,4233]],[[4311,4312,4313],[4321,4322,4323],[4331,4332,4333]]],
               [[[4111,4112,4113],[4121,4122,4123],[4131,4132,4133]],[[4211,4212,4213],[4221,4222,4223],[4231,4232,4233]],[[4311,4312,4313],[4321,4322,4323],[4331,4332,4333]]]]
}',13); ---1 rows affected.
select json_value(a,'$.four_order[0][0][0][0]') from tbl_json_ft1_test where b=13;---4111
select json_value(a,'$.four_order[1][1][1][1]') from tbl_json_ft1_test where b=13;---4222
select json_value(a,'$.four_order[2][2][2][2]') from tbl_json_ft1_test where b=13;---4333
select json_value(a,'$.four_order[0][1][2][2]') from tbl_json_ft1_test where b=13;---4233
select json_value(a,'$.four_order[2][2][1][0]') from tbl_json_ft1_test where b=13;---4321
insert into tbl_json_ft1_test values('{"one_order":[1],"two_order":[[1,2,3],[4,5,6],[7,8,9]],
"three_order":[[[111,112,113],[121,122,123],[131,132,133]],[[211,212,213],[221,222,223],[231,232,233]],[[311,312,313],[321,322,323],[331,332,333]]],
"four_order":[[[[1111,1112,1113],[1121,1122,1123],[1131,1132,1133]],[[1211,1212,1213],[1221,1222,1223],[1231,1232,1233]],[[1311,1312,1313],[1321,1322,1323],[1331,1332,1333]]],
               [[[2111,2112,2113],[2121,2122,2123],[2131,2132,2133]],[[2211,2212,2213],[2221,2222,2223],[2231,2232,2233]],[[2311,2312,2313],[2321,2322,2323],[2331,2332,2333]]],
               [[[3111,3112,3113],[3121,3122,3123],[3131,3132,3133]],[[3211,3212,3213],[3221,3222,3223],[3231,3232,3233]],[[3311,3312,3313],[3321,3322,3323],[3331,3332,3333]]]]
}',14); ---1 rows affected.
select json_value(a,'$.four_order[0][0][0][0]') from tbl_json_ft1_test where b=14; ---1111
select json_value(a,'$.four_order[1][1][1][1]') from tbl_json_ft1_test where b=14;---2222
select json_value(a,'$.four_order[2][2][2][2]') from tbl_json_ft1_test where b=14;---3333
select json_value(a,'$.four_order[0][1][2][2]') from tbl_json_ft1_test where b=14;---1233
select json_value(a,'$.four_order[2][2][1][0]') from tbl_json_ft1_test where b=14;---3321
drop table if exists tbl_json_ft1_test; ---1 rows affected.
------------------------------------
--JSONB_QUERY |JSONB_EXIST
------------------------------------
drop table if exists tbl_json_ft2_test; ---Succeed.
create table tbl_json_ft2_test(a CLOB check(a IS JSON), b int primary key);---Succeed.
insert into tbl_json_ft2_test values('{
"A1":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"A2":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"A3":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"A4":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"A5":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"A6":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"A7":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"A8":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"A9":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"AA":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"AB":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"AC":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"AD":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"AE":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}},
"AF":{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2, "three"],"B6":{"C1":1,"C2":2,"C3":3}}
}',1);---affected.
select json_query(a, '$')  from tbl_json_ft2_test where b = 1; ---ok
select json_query(a, '$.A1')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.A3')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.A5')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.A7')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.A9')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.AB')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.AD')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.AE')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.AF')  from tbl_json_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select json_query(a, '$.A1.B1')  from tbl_json_ft2_test where b = 1; ---find trouble
select json_query(a, '$.A1.B2')  from tbl_json_ft2_test where b = 1;
select json_query(a, '$.A1.B3')  from tbl_json_ft2_test where b = 1;
select json_query(a, '$.A1.B4')  from tbl_json_ft2_test where b = 1;
select json_query(a, '$.A1.B5')  from tbl_json_ft2_test where b = 1;
select json_query(a, '$.A1.B6')  from tbl_json_ft2_test where b = 1;
select json_query(a, '$.A1.B7')  from tbl_json_ft2_test where b = 1;
select json_exists(a, '$')  from tbl_json_ft2_test where b = 1; ---ok
select json_exists(a, '$.A1' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.A3' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.A5' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.A7' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.A9' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.AB' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.AD' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.AE' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.AF' with wrapper)  from tbl_json_ft2_test where b = 1;---TRUE
select json_exists(a, '$.A1.B1' with wrapper)  from tbl_json_ft2_test where b = 1; ---TRUE
select json_exists(a, '$.A1.B2' with wrapper)  from tbl_json_ft2_test where b = 1; ---TRUE
select json_exists(a, '$.A1.B3' with wrapper)  from tbl_json_ft2_test where b = 1; ---TRUE
select json_exists(a, '$.A1.B4' with wrapper)  from tbl_json_ft2_test where b = 1; ---TRUE
select json_exists(a, '$.A1.B5' with wrapper)  from tbl_json_ft2_test where b = 1; ---TRUE
select json_exists(a, '$.A1.B6' with wrapper)  from tbl_json_ft2_test where b = 1; ---TRUE
select json_exists(a, '$.A1.B7' with wrapper)  from tbl_json_ft2_test where b = 1; ---TRUE
select json_exists(a, '$.Aa' with wrapper)  from tbl_json_ft2_test where b = 1;---FALSE
select json_exists(a, '$.AK' with wrapper)  from tbl_json_ft2_test where b = 1;---FALSE
select json_exists(a, '$.AM' with wrapper)  from tbl_json_ft2_test where b = 1;---FALSE
select json_exists(a, '$.AX' with wrapper)  from tbl_json_ft2_test where b = 1;---FALSE
select json_exists(a, '$.A1.BA' with wrapper)  from tbl_json_ft2_test where b = 1; ---FALSE
select json_exists(a, '$.A1.BD' with wrapper)  from tbl_json_ft2_test where b = 1; ---FALSE
select json_exists(a, '$.A1.B6x.C5' with wrapper)  from tbl_json_ft2_test where b = 1; ---FALSE
insert into tbl_json_ft2_test values('{
"A1x":{"B1x":"JSONB1","B2x":10001,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":1,"C2x":2,"C3x":3}},
"A2x":{"B1x":"JSONB2","B2x":10002,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":2,"C2x":2,"C3x":3}},
"A3x":{"B1x":"JSONB3","B2x":10003,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":3,"C2x":2,"C3x":3}},
"A4x":{"B1x":"JSONB4","B2x":10004,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":4,"C2x":2,"C3x":3}},
"A5x":{"B1x":"JSONB5","B2x":10005,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":5,"C2x":2,"C3x":3}},
"A6x":{"B1x":"JSONB6","B2x":10006,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":6,"C2x":2,"C3x":3}},
"A7x":{"B1x":"JSONB7","B2x":10007,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":7,"C2x":2,"C3x":3}},
"A8x":{"B1x":"JSONB8","B2x":10008,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":8,"C2x":2,"C3x":3}},
"A9x":{"B1x":"JSONB9","B2x":10009,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":9,"C2x":2,"C3x":3}},
"AAx":{"B1x":"JSONBa","B2x":100010,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":10,"C2x":2,"C3x":3}},
"ABx":{"B1x":"JSONBb","B2x":100011,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":11,"C2x":2,"C3x":3}},
"ACx":{"B1x":"JSONBc","B2x":100012,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":12,"C2x":2,"C3x":3}},
"ADx":{"B1x":"JSONBd","B2x":100013,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":13,"C2x":2,"C3x":3}},
"AEx":{"B1x":"JSONBe","B2x":100014,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":14,"C2x":2,"C3x":3}},
"AFx":{"B1x":"JSONBf","B2x":100015,"B3x":false,"B4x":true,"B5x":[true,2, "three"],"B6x":{"C1x":15,"C2x":2,"C3x":3}}
}',2);---1 rows affected.
select json_query(a, '$.A1x')  from tbl_json_ft2_test where b = 2;---{"B1x":"JSONB1","B2x":10001,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":1,"C2x":2,"C3x":3}}
select json_query(a, '$.A3x')  from tbl_json_ft2_test where b = 2;---{"B1x":"JSONB3","B2x":10003,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":3,"C2x":2,"C3x":3}}
select json_query(a, '$.A5x')  from tbl_json_ft2_test where b = 2;---{"B1x":"JSONB5","B2x":10005,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":5,"C2x":2,"C3x":3}}
select json_query(a, '$.A7x')  from tbl_json_ft2_test where b = 2;---{"B1x":"JSONB7","B2x":10007,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":7,"C2x":2,"C3x":3}}
select json_query(a, '$.ABx')  from tbl_json_ft2_test where b = 2;---{"B1x":"JSONBb","B2x":100011,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":11,"C2x":2,"C3x":3}}
select json_query(a, '$.ADx')  from tbl_json_ft2_test where b = 2;---{"B1x":"JSONBd","B2x":100013,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":13,"C2x":2,"C3x":3}}
select json_query(a, '$.A1x.B1x'  with wrapper)  from tbl_json_ft2_test where b = 2; --- 1 rows fetched
select json_query(a, '$.A1x.B1x' with wrapper)  from tbl_json_ft2_test where b = 2;---1 rows fetched.  ["JSONB1"]
select json_query(a, '$.A1x.B2x' with wrapper)  from tbl_json_ft2_test where b = 2;---1 rows fetched.  [10001];
select json_query(a, '$.A1x.B3x' with wrapper)  from tbl_json_ft2_test where b = 2;---1 rows fetched.  [false]
select json_query(a, '$.A1x.B4x' with wrapper)  from tbl_json_ft2_test where b = 2;---1 rows fetched.  [true]
select json_query(a, '$.A1x.B5x' with wrapper)  from tbl_json_ft2_test where b = 2;---1 rows fetched.  [[true,2,"three"]]
select json_query(a, '$.A1x.B6x' with wrapper)  from tbl_json_ft2_test where b = 2;---1 rows fetched.  [{"C1x":1,"C2x":2,"C3x":3}]
select json_query(a, '$.A1x.B7x' error on error)  from tbl_json_ft2_test where b = 2; ---JSON_VALUE evaluated to no value
select json_query(a, '$.A1x.B5x')  from tbl_json_ft2_test where b = 2;---1 rows fetched. ---[true,2,"three"]
select json_query(a, '$.A1x.B6x')  from tbl_json_ft2_test where b = 2;---1 rows fetched. ---{"C1x":1,"C2x":2,"C3x":3}
select json_query(a, '$.A1x.B6x.C1x') from tbl_json_ft2_test where b = 2;---nothing
select json_query(a, '$.A1x.B6x.C2x' with wrapper) from tbl_json_ft2_test where b = 2;---1 rows fetched.: [2]
select json_query(a, '$.A1x.B6x.C3x' with wrapper) from tbl_json_ft2_test where b = 2;---1 rows fetched.: [3]
select json_query(a, '$.A1x.B6x.C3x' returning varchar2(256) with wrapper) from tbl_json_ft2_test where b = 2;---1 rows fetched.: [3]
select json_query(a, '$.A1x.B6x.C3x' returning varchar2(256) with wrapper) as jbv_res from tbl_json_ft2_test where b = 2;---1 rows fetched.: [3]
select json_query(a, '$.A1x.B6x.C4x' error on error) from tbl_json_ft2_test where b = 2;---JSON_VALUE evaluated to no value
select json_exists(a, '$.A1x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A3x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A5x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A7x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.ABx')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.ADx')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B1x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B1x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B2x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B3x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B4x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B5x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B6x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B5x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B6x')  from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B6x.C1x') from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B6x.C2x') from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B6x.C3x') from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B6x.C3x') from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B6x.C3x') as jbv_res from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.A1x.B6x.C4x') from tbl_json_ft2_test where b = 2;---TRUE
select json_exists(a, '$.AHx')  from tbl_json_ft2_test where b = 2;---FALSE
select json_exists(a, '$.AKx')  from tbl_json_ft2_test where b = 2;---FALSE
select json_exists(a, '$.A1x.B7x')  from tbl_json_ft2_test where b = 2;---FALSE
insert into tbl_json_ft2_test values('{"id":null, "name":"andy", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{"A":1, "B":2, "C":3, "D":4}}', 3); --ok
select json_query(a, '$') as jbq_res from tbl_json_ft2_test where b = 3;---{"addr":"China","age":18,"attrs":{"A":1,"B":2,"C":3,"D":4},"hob":[1,2,3,4,[5,6,{"lov":true}]],"id":null,"name":"andy"}
select json_query(a, '$.id') as jbq_res from tbl_json_ft2_test where b = 3;---nothing
select json_query(a, '$.id' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---null
select json_query(a, '$.name') as jbq_res from tbl_json_ft2_test where b = 3;---nothing
select json_query(a, '$.name' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---["andy"]
select json_query(a, '$.age') as jbq_res from tbl_json_ft2_test where b = 3;---nothing
select json_query(a, '$.age' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[18]
select json_query(a, '$.addr' with conditional wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---["China"]
select json_query(a, '$.hob[2 to 4]' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[3,4,[5,6,{"lov":true}]]
select json_query(a, '$.hob[2 to 4]') as jbq_res from tbl_json_ft2_test where b = 3;---nothing
select json_query(a, '$.hob') as jbq_res from tbl_json_ft2_test where b = 3;---[1,2,3,4,[5,6,{"lov":true}]]
select json_query(a, '$.hob[1, 4]' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[2,[5,6,{"lov":true}]]
select json_query(a, '$.hob[1, 4]') as jbq_res from tbl_json_ft2_test where b = 3;---nothing
select json_query(a, '$.hob[4]' with conditional wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[5,6,{"lov":true}]
select json_query(a, '$.hob[4][*]' with conditional wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[5,6,{"lov":true}]
select json_query(a, '$.hob[4][*].*' with conditional wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[true]
select json_query(a, '$.attrs.A' with wrapper) from tbl_json_ft2_test where b = 3;---[1]
select json_query(a, '$.attrs' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[{"A":1,"B":2,"C":3,"D":4}]
select json_query(a, '$.attrs.A' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[1]
select json_query(a, '$.attrs.B' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[2]
select json_query(a, '$.attrs.C' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[3]
select json_query(a, '$.attrs.D' with wrapper) as jbq_res from tbl_json_ft2_test where b = 3;---[4]
insert into tbl_json_ft2_test values('{"id":0004, "name":"liucf", "age":21, "addr":"China", "hob":[2, 2, 3, 8, [1, 8, {"lov":true}]], "attrs":{"A":1, "B":8, "C":3, "D":4}}', 4); 
insert into tbl_json_ft2_test values('{"id":0005, "name":"yinmhd", "age":22, "addr":"China", "hob":[1, 4, 0, 8, [5, 1, {"lov":false}]], "attrs":{"A":0, "B":1, "C":3, "D":4}}', 5); 
insert into tbl_json_ft2_test values('{"id":0006, "name":"anxi", "age":34, "addr":"China", "hob":[4, 2, 0, 3, [2, 3, {"lov":true}]], "attrs":{"A":1, "B":2, "C":9, "D":8}}', 6); 
insert into tbl_json_ft2_test values('{"id":0008, "name":"tyth", "age":19, "addr":"China", "hob":[1, 2, 9, 7, [7, 5, {"lov":false}]], "attrs":{"A":4, "B":5, "C":3, "D":4}}', 7); 
insert into tbl_json_ft2_test values('{"id":0017, "name":"sunwq", "age":18, "addr":"China", "hob":[9, 4, 4, 5, [9, 1, {"lov":true}]], "attrs":{"A":1, "B":3, "C":2, "D":7}}', 8); 
insert into tbl_json_ft2_test values('{"id":0108, "name":"lami", "age":22, "addr":"China", "hob":[1, 2, 5, 1, [0, 2, {"lov":false}]], "attrs":{"A":5, "B":2, "C":3, "D":0}}', 9);
insert into tbl_json_ft2_test values('{"id":0128, "name":"dsasd", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{"A":1, "B":2, "C":3, "D":4}}', 10);
select json_query(a, '$.attrs.D' with wrapper) as jbq_res from tbl_json_ft2_test where b > 3; ---7 rows fetched. [4][4][8][4][7][0][4]
select json_query(a, '$.hob[1, 4]' with wrapper) as jbq_res from tbl_json_ft2_test where b > 3;---7 rows fetched. ok
select json_query(a, '$.name' with wrapper) as jbq_res from tbl_json_ft2_test where b > 3;---7 rows fetched.ok
select json_query(a, '$.id' with wrapper) as jbq_res from tbl_json_ft2_test where b > 3;---7 rows fetched.ok
select json_query(a, '$.hob[4][2].lov' with wrapper) as jbq_res from tbl_json_ft2_test where b > 3;--- ok,nice
select json_query(a, '$.attrs.A' with wrapper) as jbq_res from tbl_json_ft2_test where b > 3;---ok,nice
select json_value(a, '$.attrs.D') as jbq_res from tbl_json_ft2_test where b > 3; ---7 rows fetched. 4 4 8 4 7 0 4
select json_value(a, '$.hob[1, 4]' ) as jbq_res from tbl_json_ft2_test where b > 3;---nothing
select json_query(a, '$.hob[1, 4]' with wrapper)as jbq_res from tbl_json_ft2_test where b > 3;
select json_value(a, '$.name' ) as jbq_res from tbl_json_ft2_test where b > 3;---7 rows fetched.ok
select json_value(a, '$.id') as jbq_res from tbl_json_ft2_test where b > 3;---7 rows fetched.ok
select json_value(a, '$.hob[4][2].lov' ) as jbq_res from tbl_json_ft2_test where b > 3;--- ok,nice
select json_value(a, '$.attrs.A') as jbq_res from tbl_json_ft2_test where b > 3;---ok,nice
insert into tbl_json_ft2_test values('[{"name":"sdf","age":15,"fans":false,"xiaodi":[1]},{"name":"xsa","age":16,"fans":true, "xiaodi":[1]}]',1001);
insert into tbl_json_ft2_test values('[{"name":"sdf","age":15,"fans":false,"xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]}]',1002);
insert into tbl_json_ft2_test values('[
                                       {"name":"sdf","age":15,"fans":false,"xiaodi":
                                       [{"name":"sdf","age":15,"fans":false,"xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]}]},
                                        
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":
                                        [{"name":"sdf","age":15,"fans":false,"xiaodi":[null]},
                                         {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                         {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                         {"name":"xsa","age":16,"fans":true, "xiaodi":[null]}]},                                       
                                        {"name":"xsa","age":17,"fans":false, "xiaodi":
                                        [{"name":"sdf","age":15,"fans":false,"xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]}]},                                        
                                        {"name":"xsa","age":18,"fans":true, "xiaodi":
                                        [{"name":"sdf","age":15,"fans":false,"xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]}]}]',13);                                                         
select json_query(a, '$[0 to 4].name' with wrapper)as jbq_res from tbl_json_ft2_test where b = 13; ---ok
select json_query(a, '$[*].name' with wrapper)as jbq_res from tbl_json_ft2_test where b = 13;---ok
select json_query(a, '$[0 to 4].age' with wrapper)as jbq_res from tbl_json_ft2_test where b = 13; ---ok
select json_query(a, '$[0 to 4].fans' with wrapper)as jbq_res from tbl_json_ft2_test where b = 13; ---ok     
select json_query(a, '$[0 to 4].xiaodi.name' with wrapper)as jbq_res from tbl_json_ft2_test where b = 13; ---ok 
select json_query(a, '$[0 to 4].xiaodi.fans' with wrapper)as jbq_res from tbl_json_ft2_test where b = 13; ---ok 
select json_query(a, '$[0 to 4].xiaodi.xiaodi' with wrapper)as jbq_res from tbl_json_ft2_test where b = 13;---ok
select json_exists(a, '$')  from tbl_json_ft2_test where b > 3; ---OK
select json_exists(a, '$.attrs.A')  from tbl_json_ft2_test where b > 3; ---OK
select json_exists(a, '$.age')  from tbl_json_ft2_test where b > 3; ---OK
select json_exists(a, '$.fans')  from tbl_json_ft2_test where b > 3; ---OK
------------------------------------
-- JSONB_MERGEPATCH
------------------------------------
drop table if exists tbl_json_ft3_test;          ---Succeed.
create table tbl_json_ft3_test(a CLOB check(a IS JSON), b int primary key);  ---Succeed.
insert into tbl_json_ft3_test values('{"addres":{"home":"xxx","company":"xxx"}, "age":0, "name":"xxx", "hobby":["book","music","run","food"]}',1);
select json_query(a, '$') from tbl_json_ft3_test where b =1;
select jsonb_mergepatch(a, '{"name":"adc007"}') from tbl_json_ft3_test where b = 1;
select json_query(a, '$') from tbl_json_ft3_test where b =1;
select jsonb_mergepatch(a, '{"addres":{"home":"I no"}}') from tbl_json_ft3_test where b = 1;
select json_query(a, '$') from tbl_json_ft3_test where b =1;
select jsonb_mergepatch(a,  '{"addres":{"company":"HHHKKK"}}') from tbl_json_ft3_test where b = 1;
select json_query(a, '$') from tbl_json_ft3_test where b =1;
select jsonb_mergepatch(a, '{"age":"22"}') from tbl_json_ft3_test where b = 1;
select json_query(a, '$') from tbl_json_ft3_test where b =1;
select jsonb_mergepatch(a, '{"age":22}') from tbl_json_ft3_test where b = 1;
select json_query(a, '$') from tbl_json_ft3_test where b =1;
select jsonb_mergepatch(a, '{"hobby":[123,"123"]}') from tbl_json_ft3_test where b = 1;
select json_query(a, '$') from tbl_json_ft3_test where b =1;
select json_mergepatch(a, '{"addres":{"home":"xzx","moe":"cdf"}}') from tbl_json_ft3_test where b = 1;
insert into tbl_json_ft3_test values('{"A":{"KMP":"1","ADC":{"BBC":"2"},"OME":3},"B":{"KMP_A":1,"ADC_A":{"BBC_A":2}, "OME_A":3}}',2);
select json_query(a, '$') from tbl_json_ft3_test where b =2;
select json_mergepatch(a, '{"A":{"KMP":10}}') from tbl_json_ft3_test where b = 2;
select json_query(a, '$') from tbl_json_ft3_test;
select json_mergepatch(a, '{"A":{"ADC":{"BBC":20}}}') from tbl_json_ft3_test where b = 2;
select json_query(a, '$') from tbl_json_ft3_test;
select json_mergepatch(a, '{"A":{"OME":{"A":2}}}') from tbl_json_ft3_test where b = 2;---ok
select json_query(a, '$') from tbl_json_ft3_test;
select json_mergepatch(a, '{"A":{"OME":30}}') from tbl_json_ft3_test where b = 2;
select json_query(a, '$') from tbl_json_ft3_test;
select json_mergepatch(a, '{"B":{"KMP_A":10}}') from tbl_json_ft3_test where b = 2;
select json_query(a, '$') from tbl_json_ft3_test;
select json_mergepatch(a, '{"B":{"ADC_A":30}}') from tbl_json_ft3_test where b = 2;
select json_query(a, '$') from tbl_json_ft3_test;
select json_mergepatch(a, '{"B":{"ADC_A":{"BBC_A":{"LOL":400}}}}') from tbl_json_ft3_test where b = 2;
insert into tbl_json_ft3_test values('{"A":{"P1":"1","P2":{"Z1":"2","Z2":"3","Z3":{"T1":4,"T2":{"K1":5,"K2":6}}},"P3":7},"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":10}}}}}}',3);
----replace
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"KEY":100}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"KEY":100}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P1":{"KEY":100}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"KEY":100}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z2":20}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T1":40}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K1":50}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":100}}}}}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
----delete
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":null}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":null}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P3":null}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P4":null}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z1":null}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T1":null}}}}') from tbl_json_ft3_test where b = 3; ---不支持大写
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K1":null}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K2":null}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K3":null}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K4":null}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"B":{"P":{"Z":{"T":{"E":{"C":null}}}}}}') from tbl_json_ft3_test where b = 3;
---insert
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"C":{"P1":1}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P4":{"KEY":121}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z4":{"T1":[1,2,3,4,5]}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":[1,2,3,4,5]}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":{"K3":1000}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":123}}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":10}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}') from tbl_json_ft3_test where b = 3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
select json_query(a, '$') from tbl_json_ft3_test where b =3;
------------------------------------
-- JSONB_SET
------------------------------------
insert into tbl_json_ft3_test values('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}',4);
---delete
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.name') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.manny') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.addr') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.ho') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.ho[3].o') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.ho[3]') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.case') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.case.A') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.case.B') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.case.C') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age','$.case.D') from tbl_json_ft3_test where b=4;

---replece
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.age',100) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.name','"ZHANGFEI"') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.manny',false) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.addr','"CHANBANPO"') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho',[1,3,4,5]) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho[3].o','"LING"') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho[3]',123) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.case','{"M":"LINGDANFA"}') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.case.A',101) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.case.B',false) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.case.C','"ONE"') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.case.D',123) from tbl_json_ft3_test where b=4;

---insert
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ADD1',100) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho[6]',1234) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho[3].k','"K"' error on error) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.case.D',100) from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.case.E','{"kay":"val"}') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho[5].case.A','{"kay":"val"}') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho[4].case.A','{"kay":"val"}') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho[4]','{"kay":"val"}') from tbl_json_ft3_test where b=4;
select json_set('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}','$.ho[5]','{"kay":"val"}') from tbl_json_ft3_test where b=4;

drop table if exists tbl_jsonb_ft4_test;          ---Succeed.
create table tbl_jsonb_ft4_test(a CLOB check(a IS JSON), b int primary key);  ---Succeed.
------------------------------------
-- JSON_ARRAY_LENGTH
------------------------------------
select json_array_length('[]');
select json_array_length('[{}]');
select json_array_length('[[],[],[],[]]');
select json_array_length('[[[1],[2],[3],[4]],[[1,2,3,4],[3,4,5,6],[7,8,9,1],[1,3,4,5]],[1,1,2,1],[2,2,2,1]]');
select json_array_length('[[[1],[2],[3],[4]],[[1,2,3,{"ket":1}],[3,4,5,6],[7,8,9,1],[1,3,4,5]],[1,1,2,1],[2,2,2,1]]');
------------------------------------
-- JSON_OBJECT
------------------------------------
select json_object(key 'NAME' is 1);---{"NAME":1}
select json_object(key 'NAME' is 'adc');---{"NAME":"adc"}
select json_object(key 'NAME' is 'true');---{"NAME":"true"}
select json_object(key 'NAME' is '[1,2,3,5]' format json);---{"NAME":[1,2,3,5]}
select json_object(key 'NAME' is 'true' format json);---{"NAME":true}
select json_object(key 'NAME' is 'null'  format json);---{"NAME":null}
select json_object(key 'NAME' is '{"A":[1,2,3,4]}'  format json);---{"NAME":{"A":[1,2,3,4]}}

------------------------------------
-- JSON_ERROR
------------------------------------
select json_array_length('{}');  ---CT-02504, [1:27]JSON syntax error, unexpected { found
select json_object(key 'NAME' is true);---CT-02504, [1:35]JSON syntax error, unexpected T found

drop table if exists tbl_js_eror_test_xy; ---Succeed.
create table tbl_js_eror_test_xy(a CLOB check(a IS JSON));---Succeed.
insert into tbl_js_eror_test_xy values('[aaa]');    ---CT-01222, Check constraint violated
insert into tbl_js_eror_test_xy values('[123,]');   ---CT-00601, Check constraint violated
insert into tbl_js_eror_test_xy values('[123,[NULL]]'); ---CT-00601, Sql syntax error: too many value expressions
insert into tbl_js_eror_test_xy values('[aaa]'); ---CT-00601, Sql syntax error: too many value expressions
insert into tbl_js_eror_test_xy values('[123,]');---CT-00601, Sql syntax error: too many value expressions
insert into tbl_js_base_test_xy values('{"kex_1":2738937798.925638525,"kex_2":"string","kex_3":false,"kex_4":[1,2,3,4],"kex_5":{"k_1":1,"k_2":'string'}}');---  CT-00601, [1:144]Sql syntax error: , expected but string foun

insert into tbl_js_eror_test_xy values('{"kex_1":2738937798.925638525,"kex_2":"string","kex_3":false,"kex_4":[1,2,3,4],"kex_5":{"k_1":1,"k_2":"string"}}');     --1 rows affected.
select json_value(a, '$[0].programmers[0].firstName' error on error) as jb_res from tbl_js_eror_test_xy ; ---CT-02506, JSON_VALUE evaluated to no value
select json_value(a, '$[0].kex_' error on error) as jb_res from tbl_js_eror_test_xy ; ---CT-02506, JSON_VALUE evaluated to no value
select json_value(a, '$[0].kex_4' error on error) as jb_res from tbl_js_eror_test_xy ; ---CT-02506, JSON_VALUE evaluated to non-scalar value
select json_query(a, '$' ,returning varchar2(512) with wrapper ) as jbq_res from tbl_js_eror_test_xy ; ---CT-02501, Invalid RETURNING/ON clause
select json_query(a, '$.kex_1' returning varchar2(512) error on error) as jbq_res from tbl_js_eror_test_xy ; ---CT-02506, JSON_VALUE evaluated to scalar value

drop table if exists tbl_js_eror_test_xy; ---Succeed.
create table tbl_js_eror_test_xy(a CLOB check(a IS JSON),b int primary key);---Succeed.
insert into tbl_js_eror_test_xy values('[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1,"z"],2],3],4],5],6],7],8],9],10],11],12],13],14],15],16],17],18],19],20],21],22],23],24],25],26],27],28],29],30],31],32],33],34],35],36],37],38],39],40],41],42],43],44],45]',1);

select json_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][1]') from tbl_js_eror_test_xy  where b=1;---CT-02503, JSON path expression syntax error, exceed max path nest level(maximum: 32)
select json_mergepatch(a,'{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"B":{"C":{"D":{"E":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":10}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}') from tbl_js_eror_test_xy where b=1; ---1 rows fetched.
