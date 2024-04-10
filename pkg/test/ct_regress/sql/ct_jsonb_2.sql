------------------------------------
-- BASE FUNC TEST:DDL
------------------------------------
drop table if exists tbl_jsonb_base_test; ---Succeed.
create table tbl_jsonb_base_test(a jsonb, b int);  ---Succeed.
drop table if exists tbl_jsonb_base_test; ---Succeed.
create table tbl_jsonb_base_test(a jsonb  primary key, b int); ---  Cannot create index on 'BLOB'
create table tbl_jsonb_base_test(a jsonb, b int primary key);  ---Succeed.
drop table if exists tbl_jsonb_base_test; ---Succeed.
truncate table tbl_jsonb_base_test; ---table does not exist
create table tbl_jsonb_base_test(a jsonb, b int primary key);---Succeed.
insert into tbl_jsonb_base_test values('{"kex_1":{"kex_2":{"kex_3":{"kex_4":{"kex_5":[{"kex_6":"six"}]}}}}}',19);   ---1 rows affected.
create table tbl_jsonb_base_test(a jsonb, b int primary key);---Succeed.
truncate table tbl_jsonb_base_test; ---Succeed.
insert into tbl_jsonb_base_test values('{"kex_1":{"kex_2":{"kex_3":{"kex_4":{"kex_5":[{"kex_6":"six"}]}}}}}',19);   ---1 rows affected.                            
drop table if exists tbl_jsonb_base_test; ---Succeed.
create table tbl_jsonb_base_test(a jsonb);
insert into tbl_jsonb_base_test values('[{"AAA":"AAA"}, {"BBB":"BBB"}, {"CCC":"CCC"}, {"DDD":"DDD"}, {"EEE":"EEE"}]');
insert into tbl_jsonb_base_test values('[{"AAA":"AAA"}, {"BBB":"BBB"}, {"CCC":"CCC"}, {"DDD":"DDD"}, {"EEE":"EEE"}]');
insert into tbl_jsonb_base_test values('[{"AAA":"AAAa"}, {"BBB":"BBBa"}, {"CCC":"CCCa"}, {"DDD":"DDDa"}, {"EEE":"EEEa"}]');
commit;
drop index if exists jsonb_index on tbl_jsonb_base_test;---Succeed.
create index jsonb_index on tbl_jsonb_base_test(jsonb_value(a, '$[0].AAA')); ---Succeed.
drop index if exists jsonb_index on tbl_jsonb_base_test; ---Succeed.
drop table if exists tbl_jsonb_base_test; ---Succeed.
drop table if exists tbl_jsonb_base_test;
create table tbl_jsonb_base_test(a jsonb);
create unique index tbl_jsonb_base_test_idx on tbl_jsonb_base_test(jsonb_value(a, '$.AAA' returning varchar2(1024)), jsonb_value(a, '$.BBB' returning varchar2(1024)));
insert into tbl_jsonb_base_test values('{"AAA" : "111", "BBB" : "222", "CCC" : "333"}');
insert into tbl_jsonb_base_test values('{"AAA" : "111", "BBB" : "222", "CCC" : "333"}'); -- error
insert into tbl_jsonb_base_test values('{"AAA" : "111", "BBB" : "000", "CCC" : "333"}');
select jsonb_query(a, '$') as val from tbl_jsonb_base_test where jsonb_value(a, '$.AAA' returning varchar2(1024)) = '111';
select jsonb_query(a, '$') as val from tbl_jsonb_base_test where jsonb_value(a, '$.AAA' returning varchar2(1024)) = '111' and jsonb_value(a, '$.BBB' returning varchar2(1024)) = '222';
drop table if exists tbl_jsonb_base_test;
------------------------------------
-- BASE FUNC TEST:DML
------------------------------------
drop table if exists tbl_jsonb_base_test; ---Succeed.
drop table if exists tbl_jsonb_base_test; ---Succeed.
create table tbl_jsonb_base_test(a jsonb, b int primary key);  ---Succeed.
insert into tbl_jsonb_base_test values('[]',1);     ---1 rows affected.    
insert into tbl_jsonb_base_test values('[null]',2); ---1 rows affected. 
insert into tbl_jsonb_base_test values('["string"]',3);  ---1 rows affected.       
insert into tbl_jsonb_base_test values('[true]',4);   ---1 rows affected. 
insert into tbl_jsonb_base_test values('[false]',5);   ---1 rows affected. 
insert into tbl_jsonb_base_test values('[-101998]',6);  ---1 rows affected. 
insert into tbl_jsonb_base_test values('[101998]',7);   ---1 rows affected. 
insert into tbl_jsonb_base_test values('[-101998545554.101454455451998]',8);---1 rows affected.  
insert into tbl_jsonb_base_test values('[101998545554.101454455451998]',9); ---1 rows affected. 
insert into tbl_jsonb_base_test values('[1,2,3,4]',10);---1 rows affected. 
insert into tbl_jsonb_base_test values('["world","time","room","chairman"]',11); ---1 rows affected.       
insert into tbl_jsonb_base_test values('[true,false,true,false]', 12); ---1 rows affected.                  
insert into tbl_jsonb_base_test values('[-124554.115454582,124554.115454582,565656556454787512121212,565656556454787512121212]',13); ---1 rows affected. 
insert into tbl_jsonb_base_test values('[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]',14); --1 rows affected.
insert into tbl_jsonb_base_test values('[["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]]',15); --1 rows affected.   
insert into tbl_jsonb_base_test values('
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
insert into tbl_jsonb_base_test values('{"kex_1":2738937798.925638525,"kex_2":"string","kex_3":false,"kex_4":[1,2,3,4],"kex_5":{"k_1":1,"k_2":"string"}}',17);     --1 rows affected.
insert into tbl_jsonb_base_test values('{"kex_1":44454547.28534326,"kex_2":"string","kex_3":false,"kex_4":{"k_1":"string","k_2":123,"kex_3":
[["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]]}}',18);   --1 rows affected.
insert into tbl_jsonb_base_test values('{"kex_1":{"kex_2":{"kex_3":{"kex_4":{"kex_5":[{"kex_6":"six"}]}}}}}',19);   --1 rows affected.
insert into tbl_jsonb_base_test values('{"count":4,"filename":"chiefbook","line":{
"one":{"a":0,"b":0,"c":0.292,"d":820,"ex":852,"ey":571,"id":0,"sx":0,"sy":820},
"two":{"a":0,"b":0,"c":-1.187,"d":1680.5999755859375,"ex":934,"ey":572,"id":1,"sx":506,"sy":1080},
"three":{"a":0,"b":0,"c":0.531,"d":26.270000457763672,"ex":1919,"ey":1045,"id":2,"sx":1028,"sy":572},
"four":{"a":0,"b":0,"c":0.316,"d":232.5,"ex":1919,"ey":838,"id":3,"sx":1076,"sy":572}},"timeStamp":{"nesc:":5678,"sec:":1234}}',20);   --1 rows affected.
delete tbl_jsonb_base_test where b=1; ---1 rows affected.
delete tbl_jsonb_base_test where b=1;---0 rows affected.
select b from tbl_jsonb_base_test; ---19 rows affected.
select count(*) from tbl_jsonb_base_test; ---19
delete tbl_jsonb_base_test where b=2; ---1 rows affected.
delete tbl_jsonb_base_test where b=3; ---1 rows affected.
delete tbl_jsonb_base_test where b=4;  ---1 rows affected.
select b from tbl_jsonb_base_test; ---16 rows affected.
select count(*) from tbl_jsonb_base_test; ---1 rows affected.
delete tbl_jsonb_base_test where b > 20; ---0 rows affected.
delete tbl_jsonb_base_test where b > 18;  ---2 rows affected.
select b from tbl_jsonb_base_test; ---14 rows fetched.
select count(*) from tbl_jsonb_base_test;---1 rows affected.
delete tbl_jsonb_base_test where b < 10; ---5 rows affected.
select count(*) from tbl_jsonb_base_test;---1 rows affected:9
delete tbl_jsonb_base_test where b>15 or b<12;---5 rows affected.
delete tbl_jsonb_base_test where b<15 and b>12; ---2 rows affected.
delete tbl_jsonb_base_test where b = 15; ---1 rows affected.
delete tbl_jsonb_base_test where b = 12; ---1 rows affected.
select count(*) from tbl_jsonb_base_test; ---1 rows affected:0
insert into tbl_jsonb_base_test values('[]',1);     ---1 rows affected.    
insert into tbl_jsonb_base_test values('[null]',2); ---1 rows affected. 
insert into tbl_jsonb_base_test values('["string"]',3);  ---1 rows affected.       
insert into tbl_jsonb_base_test values('[true]',4);   ---1 rows affected. 
insert into tbl_jsonb_base_test values('[false]',5);   ---1 rows affected. 
insert into tbl_jsonb_base_test values('[-101998]',6);  ---1 rows affected. 
insert into tbl_jsonb_base_test values('[101998]',7);   ---1 rows affected. 
insert into tbl_jsonb_base_test values('[-101998545554.101454455451998]',8);---1 rows affected.  
insert into tbl_jsonb_base_test values('[101998545554.101454455451998]',9); ---1 rows affected. 
insert into tbl_jsonb_base_test values('[1,2,3,4]',10);---1 rows affected. 
insert into tbl_jsonb_base_test values('["world","time","room","chairman"]',11); ---1 rows affected.       
insert into tbl_jsonb_base_test values('[true,false,true,false]', 12); ---1 rows affected.                  
insert into tbl_jsonb_base_test values('[-124554.115454582,124554.115454582,565656556454787512121212,565656556454787512121212]',13); ---1 rows affected. 
insert into tbl_jsonb_base_test values('[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]',14); --1 rows affected.
insert into tbl_jsonb_base_test values('[["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]]',15); --1 rows affected.   
insert into tbl_jsonb_base_test values('
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
insert into tbl_jsonb_base_test values('{"kex_1":2738937798.925638525,"kex_2":"string","kex_3":false,"kex_4":[1,2,3,4],"kex_5":{"k_1":1,"k_2":"string"}}',17);     --1 rows affected.
insert into tbl_jsonb_base_test values('{"kex_1":44454547.28534326,"kex_2":"string","kex_3":false,"kex_4":{"k_1":"string","k_2":123,"kex_3":
[["one","two","three"],[1,2,3],[1.1,1.2,2.343],[false,false,true],[{"kex_1":1},{"kex_2":"string"},{"kex_3":12323323.21233},{"kex_4":false}]]}}',18);   --1 rows affected.
insert into tbl_jsonb_base_test values('{"kex_1":{"kex_2":{"kex_3":{"kex_4":{"kex_5":[{"kex_6":"six"}]}}}}}',19);   --1 rows affected.
insert into tbl_jsonb_base_test values('{"count":4,"filename":"chiefbook","line":{
"one":{"a":0,"b":0,"c":0.292,"d":820,"ex":852,"ey":571,"id":0,"sx":0,"sy":820},
"two":{"a":0,"b":0,"c":-1.187,"d":1680.5999755859375,"ex":934,"ey":572,"id":1,"sx":506,"sy":1080},
"three":{"a":0,"b":0,"c":0.531,"d":26.270000457763672,"ex":1919,"ey":1045,"id":2,"sx":1028,"sy":572},
"four":{"a":0,"b":0,"c":0.316,"d":232.5,"ex":1919,"ey":838,"id":3,"sx":1076,"sy":572}},"timeStamp":{"nesc:":5678,"sec:":1234}}',20);   --1 rows affected
update tbl_jsonb_base_test set a = '[{"key":"value"}]' where b=1; ---1 rows affected.
select a from tbl_jsonb_base_test where b=1;---0F0000000111015003813004076B657976616C7565
update tbl_jsonb_base_test set a = '[{"one":1}]' where b=1; ---1 rows affected.
select a from tbl_jsonb_base_test where b=1; ---0B0000000111015003814004076F6E6531
delete tbl_jsonb_base_test where b=20;---1 rows affected.
delete tbl_jsonb_base_test where b=20;---0 rows affected.
update tbl_jsonb_base_test set a = '[{"one":1}]' where b=20; ---0 rows affected.
update tbl_jsonb_base_test set a = '[{"one":1}]' where b <=10; ---10 rows affected.
select a from tbl_jsonb_base_test where b<=10; ---10* 0B0000000111015003814004076F6E6531
update tbl_jsonb_base_test set a = '[{"one":1}]' where b >=10 and b <=15;---6 rows affected.
select a from tbl_jsonb_base_test where b >=10 and b <=15; ---6* 0B0000000111015003814004076F6E6531
delete tbl_jsonb_base_test where b =16;---1 rows affected.
delete tbl_jsonb_base_test where b =17;---1 rows affected.
delete tbl_jsonb_base_test where b =18;---1 rows affected.
delete from tbl_jsonb_base_test where b =19;---1 rows affected.
select a from tbl_jsonb_base_test where b >15;---0 rows fetched.
select length(a) from tbl_jsonb_base_test;--- 15* 17
drop table if exists tbl_jsonb_base_test; ---Succeed.
------------------------------------
--JSONB_VALUE
------------------------------------
drop table if exists tbl_jsonb_ft1_test;          ---Succeed.
create table tbl_jsonb_ft1_test(a jsonb, b int primary key);  ---Succeed.
insert into tbl_jsonb_ft1_test values('{ "user name":"jsonb","id":"123456789abcdefghijk", "age":35, "phone number":"033-5578456978251","vip level":3,"new user ?":false,"preference":["book","music","run"]}', 1); ---1 rows affected.
select jsonb_value(a, '$."user name"') from tbl_jsonb_ft1_test where b = 1; ---1 rows fetched. jsonb
insert into tbl_jsonb_ft1_test values('{ "user_name":"jsonb","id":"123456789abcdefghijk", "age":35, "phone_number":"033-5578456978251","vip_level":3,"new_user_?":false,"preference":["book","music","run"]}', 2);  ---1 rows affected.
select jsonb_value(a, '$.user_name') from tbl_jsonb_ft1_test where b = 2;---1 rows fetched.
select jsonb_value(a, '$.id') from tbl_jsonb_ft1_test where b = 2;---1 rows fetched.
select jsonb_value(a, '$.age') from tbl_jsonb_ft1_test where b = 2;---1 rows fetched.
select jsonb_value(a, '$.phone_number') from tbl_jsonb_ft1_test where b = 2;---1 rows fetched
select jsonb_value(a, '$.vip_level') from tbl_jsonb_ft1_test where b = 2;---1 rows fetched
select jsonb_value(a, '$.preference[0]') from tbl_jsonb_ft1_test where b = 2;---1 rows fetched
select jsonb_value(a, '$.preference[1]') from tbl_jsonb_ft1_test where b = 2;---1 rows fetched
select jsonb_value(a, '$.preference[2]') from tbl_jsonb_ft1_test where b = 2;---1 rows fetched
insert into tbl_jsonb_ft1_test values('{"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMN":1}', 3);
select jsonb_value(a, '$.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMN') from tbl_jsonb_ft1_test where b = 3;---1 rows fetched 
insert into tbl_jsonb_ft1_test values('[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1,"z"],2],3],4],5],6],7],8],9],10],11],12],13],14],15],16],17],18],19],20],21],22],23],24],25],26],27],28],29],30],31],32],33],34],35],36],37],38],39],40],41],42],43],44],45]',4); //find troble 未校验
select jsonb_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][1]') from tbl_jsonb_ft1_test where b = 4;
insert into tbl_jsonb_ft1_test values('[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1,"z"],2],3],4],5],6],7],8],9],10],11],12],13],14],15],16],17],18],19],20],21],22],23],24],25],26],27],28],29],30],31],32]',5); //未校验
select jsonb_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][1]') from tbl_jsonb_ft1_test where b = 5;  ----1 rows fetched  z
select jsonb_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0]') from tbl_jsonb_ft1_test where b = 5;  ----1 rows fetched. 1
select jsonb_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][1]') from tbl_jsonb_ft1_test where b = 5; ---1 rows fetched 2
insert into tbl_jsonb_ft1_test values('{"key":123456789123456789123456789123456789}',6);
select jsonb_value(a,'$.key') from tbl_jsonb_ft1_test where b=6;---1 rows fetched:123456789123456789123456789123456789
insert into tbl_jsonb_ft1_test values('{"key":123456789123456789123456789123456789123456789}',7); ---1 rows affected.
select jsonb_value(a,'$.key') from tbl_jsonb_ft1_test where b=7;  ---123456789123456789123456789123456789123456789
insert into tbl_jsonb_ft1_test values('{"key":123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789}',8); ---1 rows affected.
select jsonb_value(a,'$.key') from tbl_jsonb_ft1_test where b=8;  
---123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789
insert into tbl_jsonb_ft1_test values('{"key":123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789}',9); ---1 rows affected.
select jsonb_value(a,'$.key') from tbl_jsonb_ft1_test where b=9;
 ---123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789
insert into tbl_jsonb_ft1_test values('{"key":12345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912}',10); ---1 rows affected.
select jsonb_value(a,'$.key') from tbl_jsonb_ft1_test where b=10;
---12345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912
insert into tbl_jsonb_ft1_test values('{"key":123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123}',11); ---invalid json number
insert into tbl_jsonb_ft1_test values('{"one_order":[1],"two_order":[[1,2,3],[4,5,6],[7,8,9]]}',11);
select jsonb_value(a,'$.two_order[0][0]') from tbl_jsonb_ft1_test where b=11;---1
select jsonb_value(a,'$.two_order[1][1]') from tbl_jsonb_ft1_test where b=11;---5
select jsonb_value(a,'$.two_order[2][2]') from tbl_jsonb_ft1_test where b=11;---9
insert into tbl_jsonb_ft1_test values('{"one_order":[1],"two_order":[[1,2,3],[4,5,6],[7,8,9]],
"three_order":[[[111,112,113],[121,122,123],[131,132,133]],[[211,212,213],[221,222,223],[231,232,233]],[[311,312,313],[321,322,323],[331,332,333]]]
}',12); ---1 rows affected.
select jsonb_value(a,'$.three_order[0][0][0]') from tbl_jsonb_ft1_test where b=12;---111
select jsonb_value(a,'$.three_order[1][1][1]') from tbl_jsonb_ft1_test where b=12;---222
select jsonb_value(a,'$.three_order[2][2][2]') from tbl_jsonb_ft1_test where b=12;---333
select jsonb_value(a,'$.three_order[0][1][2]') from tbl_jsonb_ft1_test where b=12;---123
select jsonb_value(a,'$.three_order[2][1][0]') from tbl_jsonb_ft1_test where b=12;---321
insert into tbl_jsonb_ft1_test values('{"one_order":[1],"two_order":[[1,2,3],[4,5,6],[7,8,9]],
"three_order":[[[111,112,113],[121,122,123],[131,132,133]],[[211,212,213],[221,222,223],[231,232,233]],[[311,312,313],[321,322,323],[331,332,333]]],
"four_order":[[[[4111,112,113],[4121,122,123],[4131,4132,4133]],[[4211,4212,4213],[4221,4222,4223],[4231,4232,4233]],[[4311,4312,4313],[4321,4322,4323],[4331,4332,4333]]],
               [[[4111,4112,4113],[4121,4122,4123],[4131,4132,4133]],[[4211,4212,4213],[4221,4222,4223],[4231,4232,4233]],[[4311,4312,4313],[4321,4322,4323],[4331,4332,4333]]],
               [[[4111,4112,4113],[4121,4122,4123],[4131,4132,4133]],[[4211,4212,4213],[4221,4222,4223],[4231,4232,4233]],[[4311,4312,4313],[4321,4322,4323],[4331,4332,4333]]]]
}',13); ---1 rows affected.
select jsonb_value(a,'$.four_order[0][0][0][0]') from tbl_jsonb_ft1_test where b=13;---4111
select jsonb_value(a,'$.four_order[1][1][1][1]') from tbl_jsonb_ft1_test where b=13;---4222
select jsonb_value(a,'$.four_order[2][2][2][2]') from tbl_jsonb_ft1_test where b=13;---4333
select jsonb_value(a,'$.four_order[0][1][2][2]') from tbl_jsonb_ft1_test where b=13;---4233
select jsonb_value(a,'$.four_order[2][2][1][0]') from tbl_jsonb_ft1_test where b=13;---4321
insert into tbl_jsonb_ft1_test values('{"one_order":[1],"two_order":[[1,2,3],[4,5,6],[7,8,9]],
"three_order":[[[111,112,113],[121,122,123],[131,132,133]],[[211,212,213],[221,222,223],[231,232,233]],[[311,312,313],[321,322,323],[331,332,333]]],
"four_order":[[[[1111,1112,1113],[1121,1122,1123],[1131,1132,1133]],[[1211,1212,1213],[1221,1222,1223],[1231,1232,1233]],[[1311,1312,1313],[1321,1322,1323],[1331,1332,1333]]],
               [[[2111,2112,2113],[2121,2122,2123],[2131,2132,2133]],[[2211,2212,2213],[2221,2222,2223],[2231,2232,2233]],[[2311,2312,2313],[2321,2322,2323],[2331,2332,2333]]],
               [[[3111,3112,3113],[3121,3122,3123],[3131,3132,3133]],[[3211,3212,3213],[3221,3222,3223],[3231,3232,3233]],[[3311,3312,3313],[3321,3322,3323],[3331,3332,3333]]]]
}',14); ---1 rows affected.
select jsonb_value(a,'$.four_order[0][0][0][0]') from tbl_jsonb_ft1_test where b=14; ---1111
select jsonb_value(a,'$.four_order[1][1][1][1]') from tbl_jsonb_ft1_test where b=14;---2222
select jsonb_value(a,'$.four_order[2][2][2][2]') from tbl_jsonb_ft1_test where b=14;---3333
select jsonb_value(a,'$.four_order[0][1][2][2]') from tbl_jsonb_ft1_test where b=14;---1233
select jsonb_value(a,'$.four_order[2][2][1][0]') from tbl_jsonb_ft1_test where b=14;---3321
drop table if exists tbl_jsonb_ft1_test; ---1 rows affected.
------------------------------------
--JSONB_QUERY |JSONB_EXIST
------------------------------------
drop table if exists tbl_jsonb_ft2_test; ---Succeed.
create table tbl_jsonb_ft2_test(a jsonb, b int primary key);---Succeed.
insert into tbl_jsonb_ft2_test values('{
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
select jsonb_query(a, '$')  from tbl_jsonb_ft2_test where b = 1; ---ok
select jsonb_query(a, '$.A1')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.A3')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.A5')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.A7')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.A9')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.AB')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.AD')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.AE')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.AF')  from tbl_jsonb_ft2_test where b = 1;---{"B1":"JSONB","B2":1000,"B3":false,"B4":true,"B5":[true,2,"three"],"B6":{"C1":1,"C2":2,"C3":3}}
select jsonb_query(a, '$.A1.B1')  from tbl_jsonb_ft2_test where b = 1; ---find trouble
select jsonb_query(a, '$.A1.B2')  from tbl_jsonb_ft2_test where b = 1;
select jsonb_query(a, '$.A1.B3')  from tbl_jsonb_ft2_test where b = 1;
select jsonb_query(a, '$.A1.B4')  from tbl_jsonb_ft2_test where b = 1;
select jsonb_query(a, '$.A1.B5')  from tbl_jsonb_ft2_test where b = 1;
select jsonb_query(a, '$.A1.B6')  from tbl_jsonb_ft2_test where b = 1;
select jsonb_query(a, '$.A1.B7')  from tbl_jsonb_ft2_test where b = 1;
select jsonb_exists(a, '$')  from tbl_jsonb_ft2_test where b = 1; ---ok
select jsonb_exists(a, '$.A1' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.A3' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.A5' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.A7' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.A9' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.AB' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.AD' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.AE' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.AF' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---TRUE
select jsonb_exists(a, '$.A1.B1' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---TRUE
select jsonb_exists(a, '$.A1.B2' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---TRUE
select jsonb_exists(a, '$.A1.B3' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---TRUE
select jsonb_exists(a, '$.A1.B4' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---TRUE
select jsonb_exists(a, '$.A1.B5' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---TRUE
select jsonb_exists(a, '$.A1.B6' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---TRUE
select jsonb_exists(a, '$.A1.B7' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---TRUE
select jsonb_exists(a, '$.Aa' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---FALSE
select jsonb_exists(a, '$.AK' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---FALSE
select jsonb_exists(a, '$.AM' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---FALSE
select jsonb_exists(a, '$.AX' with wrapper)  from tbl_jsonb_ft2_test where b = 1;---FALSE
select jsonb_exists(a, '$.A1.BA' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---FALSE
select jsonb_exists(a, '$.A1.BD' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---FALSE
select jsonb_exists(a, '$.A1.B6x.C5' with wrapper)  from tbl_jsonb_ft2_test where b = 1; ---FALSE
insert into tbl_jsonb_ft2_test values('{
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
select jsonb_query(a, '$.A1x')  from tbl_jsonb_ft2_test where b = 2;---{"B1x":"JSONB1","B2x":10001,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":1,"C2x":2,"C3x":3}}
select jsonb_query(a, '$.A3x')  from tbl_jsonb_ft2_test where b = 2;---{"B1x":"JSONB3","B2x":10003,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":3,"C2x":2,"C3x":3}}
select jsonb_query(a, '$.A5x')  from tbl_jsonb_ft2_test where b = 2;---{"B1x":"JSONB5","B2x":10005,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":5,"C2x":2,"C3x":3}}
select jsonb_query(a, '$.A7x')  from tbl_jsonb_ft2_test where b = 2;---{"B1x":"JSONB7","B2x":10007,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":7,"C2x":2,"C3x":3}}
select jsonb_query(a, '$.ABx')  from tbl_jsonb_ft2_test where b = 2;---{"B1x":"JSONBb","B2x":100011,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":11,"C2x":2,"C3x":3}}
select jsonb_query(a, '$.ADx')  from tbl_jsonb_ft2_test where b = 2;---{"B1x":"JSONBd","B2x":100013,"B3x":false,"B4x":true,"B5x":[true,2,"three"],"B6x":{"C1x":13,"C2x":2,"C3x":3}}
select jsonb_query(a, '$.A1x.B1x'  with wrapper)  from tbl_jsonb_ft2_test where b = 2; --- 1 rows fetched
select jsonb_query(a, '$.A1x.B1x' with wrapper)  from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.  ["JSONB1"]
select jsonb_query(a, '$.A1x.B2x' with wrapper)  from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.  [10001];
select jsonb_query(a, '$.A1x.B3x' with wrapper)  from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.  [false]
select jsonb_query(a, '$.A1x.B4x' with wrapper)  from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.  [true]
select jsonb_query(a, '$.A1x.B5x' with wrapper)  from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.  [[true,2,"three"]]
select jsonb_query(a, '$.A1x.B6x' with wrapper)  from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.  [{"C1x":1,"C2x":2,"C3x":3}]
select jsonb_query(a, '$.A1x.B7x' error on error)  from tbl_jsonb_ft2_test where b = 2; ---JSONB_VALUE evaluated to no value
select jsonb_query(a, '$.A1x.B5x')  from tbl_jsonb_ft2_test where b = 2;---1 rows fetched. ---[true,2,"three"]
select jsonb_query(a, '$.A1x.B6x')  from tbl_jsonb_ft2_test where b = 2;---1 rows fetched. ---{"C1x":1,"C2x":2,"C3x":3}
select jsonb_query(a, '$.A1x.B6x.C1x') from tbl_jsonb_ft2_test where b = 2;---nothing
select jsonb_query(a, '$.A1x.B6x.C2x' with wrapper) from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.: [2]
select jsonb_query(a, '$.A1x.B6x.C3x' with wrapper) from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.: [3]
select jsonb_query(a, '$.A1x.B6x.C3x' returning varchar2(256) with wrapper) from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.: [3]
select jsonb_query(a, '$.A1x.B6x.C3x' returning varchar2(256) with wrapper) as jbv_res from tbl_jsonb_ft2_test where b = 2;---1 rows fetched.: [3]
select jsonb_query(a, '$.A1x.B6x.C4x' error on error) from tbl_jsonb_ft2_test where b = 2;---JSONB_VALUE evaluated to no value
select jsonb_exists(a, '$.A1x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A3x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A5x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A7x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.ABx')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.ADx')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B1x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B1x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B2x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B3x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B4x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B5x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B6x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B5x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B6x')  from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B6x.C1x') from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B6x.C2x') from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B6x.C3x') from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B6x.C3x') from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B6x.C3x') as jbv_res from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.A1x.B6x.C4x') from tbl_jsonb_ft2_test where b = 2;---TRUE
select jsonb_exists(a, '$.AHx')  from tbl_jsonb_ft2_test where b = 2;---FALSE
select jsonb_exists(a, '$.AKx')  from tbl_jsonb_ft2_test where b = 2;---FALSE
select jsonb_exists(a, '$.A1x.B7x')  from tbl_jsonb_ft2_test where b = 2;---FALSE
insert into tbl_jsonb_ft2_test values('{"id":null, "name":"andy", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{"A":1, "B":2, "C":3, "D":4}}', 3); --ok
select jsonb_query(a, '$') as jbq_res from tbl_jsonb_ft2_test where b = 3;---{"addr":"China","age":18,"attrs":{"A":1,"B":2,"C":3,"D":4},"hob":[1,2,3,4,[5,6,{"lov":true}]],"id":null,"name":"andy"}
select jsonb_query(a, '$.id') as jbq_res from tbl_jsonb_ft2_test where b = 3;---nothing
select jsonb_query(a, '$.id' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---null
select jsonb_query(a, '$.name') as jbq_res from tbl_jsonb_ft2_test where b = 3;---nothing
select jsonb_query(a, '$.name' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---["andy"]
select jsonb_query(a, '$.age') as jbq_res from tbl_jsonb_ft2_test where b = 3;---nothing
select jsonb_query(a, '$.age' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[18]
select jsonb_query(a, '$.addr' with conditional wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---["China"]
select jsonb_query(a, '$.hob[2 to 4]' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[3,4,[5,6,{"lov":true}]]
select jsonb_query(a, '$.hob[2 to 4]') as jbq_res from tbl_jsonb_ft2_test where b = 3;---nothing
select jsonb_query(a, '$.hob') as jbq_res from tbl_jsonb_ft2_test where b = 3;---[1,2,3,4,[5,6,{"lov":true}]]
select jsonb_query(a, '$.hob[1, 4]' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[2,[5,6,{"lov":true}]]
select jsonb_query(a, '$.hob[1, 4]') as jbq_res from tbl_jsonb_ft2_test where b = 3;---nothing
select jsonb_query(a, '$.hob[4]' with conditional wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[5,6,{"lov":true}]
select jsonb_query(a, '$.hob[4][*]' with conditional wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[5,6,{"lov":true}]
select jsonb_query(a, '$.hob[4][*].*' with conditional wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[true]
select jsonb_query(a, '$.attrs.A' with wrapper) from tbl_jsonb_ft2_test where b = 3;---[1]
select jsonb_query(a, '$.attrs' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[{"A":1,"B":2,"C":3,"D":4}]
select jsonb_query(a, '$.attrs.A' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[1]
select jsonb_query(a, '$.attrs.B' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[2]
select jsonb_query(a, '$.attrs.C' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[3]
select jsonb_query(a, '$.attrs.D' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b = 3;---[4]
insert into tbl_jsonb_ft2_test values('{"id":0004, "name":"liucf", "age":21, "addr":"China", "hob":[2, 2, 3, 8, [1, 8, {"lov":true}]], "attrs":{"A":1, "B":8, "C":3, "D":4}}', 4); 
insert into tbl_jsonb_ft2_test values('{"id":0005, "name":"yinmhd", "age":22, "addr":"China", "hob":[1, 4, 0, 8, [5, 1, {"lov":false}]], "attrs":{"A":0, "B":1, "C":3, "D":4}}', 5); 
insert into tbl_jsonb_ft2_test values('{"id":0006, "name":"anxi", "age":34, "addr":"China", "hob":[4, 2, 0, 3, [2, 3, {"lov":true}]], "attrs":{"A":1, "B":2, "C":9, "D":8}}', 6); 
insert into tbl_jsonb_ft2_test values('{"id":0008, "name":"tyth", "age":19, "addr":"China", "hob":[1, 2, 9, 7, [7, 5, {"lov":false}]], "attrs":{"A":4, "B":5, "C":3, "D":4}}', 7); 
insert into tbl_jsonb_ft2_test values('{"id":0017, "name":"sunwq", "age":18, "addr":"China", "hob":[9, 4, 4, 5, [9, 1, {"lov":true}]], "attrs":{"A":1, "B":3, "C":2, "D":7}}', 8); 
insert into tbl_jsonb_ft2_test values('{"id":0108, "name":"lami", "age":22, "addr":"China", "hob":[1, 2, 5, 1, [0, 2, {"lov":false}]], "attrs":{"A":5, "B":2, "C":3, "D":0}}', 9);
insert into tbl_jsonb_ft2_test values('{"id":0128, "name":"dsasd", "age":18, "addr":"China", "hob":[1, 2, 3, 4, [5, 6, {"lov":true}]], "attrs":{"A":1, "B":2, "C":3, "D":4}}', 10);
select jsonb_query(a, '$.attrs.D' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b > 3; ---7 rows fetched. [4][4][8][4][7][0][4]
select jsonb_query(a, '$.hob[1, 4]' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b > 3;---7 rows fetched. ok
select jsonb_query(a, '$.name' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b > 3;---7 rows fetched.ok
select jsonb_query(a, '$.id' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b > 3;---7 rows fetched.ok
select jsonb_query(a, '$.hob[4][2].lov' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b > 3;--- ok,nice
select jsonb_query(a, '$.attrs.A' with wrapper) as jbq_res from tbl_jsonb_ft2_test where b > 3;---ok,nice
select jsonb_value(a, '$.attrs.D') as jbq_res from tbl_jsonb_ft2_test where b > 3; ---7 rows fetched. 4 4 8 4 7 0 4
select jsonb_value(a, '$.hob[1, 4]' ) as jbq_res from tbl_jsonb_ft2_test where b > 3;---nothing
select jsonb_query(a, '$.hob[1, 4]' with wrapper)as jbq_res from tbl_jsonb_ft2_test where b > 3;
select jsonb_value(a, '$.name' ) as jbq_res from tbl_jsonb_ft2_test where b > 3;---7 rows fetched.ok
select jsonb_value(a, '$.id') as jbq_res from tbl_jsonb_ft2_test where b > 3;---7 rows fetched.ok
select jsonb_value(a, '$.hob[4][2].lov' ) as jbq_res from tbl_jsonb_ft2_test where b > 3;--- ok,nice
select jsonb_value(a, '$.attrs.A') as jbq_res from tbl_jsonb_ft2_test where b > 3;---ok,nice
insert into tbl_jsonb_ft2_test values('[{"name":"sdf","age":15,"fans":false,"xiaodi":[1]},{"name":"xsa","age":16,"fans":true, "xiaodi":[1]}]',1001);
insert into tbl_jsonb_ft2_test values('[{"name":"sdf","age":15,"fans":false,"xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]},
                                        {"name":"xsa","age":16,"fans":true, "xiaodi":[null]}]',1002);
insert into tbl_jsonb_ft2_test values('[
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
select jsonb_query(a, '$[0 to 4].name' with wrapper)as jbq_res from tbl_jsonb_ft2_test where b = 13; ---ok
select jsonb_query(a, '$[*].name' with wrapper)as jbq_res from tbl_jsonb_ft2_test where b = 13;---ok
select jsonb_query(a, '$[0 to 4].age' with wrapper)as jbq_res from tbl_jsonb_ft2_test where b = 13; ---ok
select jsonb_query(a, '$[0 to 4].fans' with wrapper)as jbq_res from tbl_jsonb_ft2_test where b = 13; ---ok     
select jsonb_query(a, '$[0 to 4].xiaodi.name' with wrapper)as jbq_res from tbl_jsonb_ft2_test where b = 13; ---ok 
select jsonb_query(a, '$[0 to 4].xiaodi.fans' with wrapper)as jbq_res from tbl_jsonb_ft2_test where b = 13; ---ok 
select jsonb_query(a, '$[0 to 4].xiaodi.xiaodi' with wrapper)as jbq_res from tbl_jsonb_ft2_test where b = 13;---ok
select jsonb_exists(a, '$')  from tbl_jsonb_ft2_test where b > 3; ---OK
select jsonb_exists(a, '$.attrs.A')  from tbl_jsonb_ft2_test where b > 3; ---OK
select jsonb_exists(a, '$.age')  from tbl_jsonb_ft2_test where b > 3; ---OK
select jsonb_exists(a, '$.fans')  from tbl_jsonb_ft2_test where b > 3; ---OK
------------------------------------
-- JSONB_MERGEPATCH
------------------------------------
drop table if exists tbl_jsonb_ft3_test;          ---Succeed.
create table tbl_jsonb_ft3_test(a jsonb, b int primary key);  ---Succeed.
insert into tbl_jsonb_ft3_test values('{"addres":{"home":"xxx","company":"xxx"}, "age":0, "name":"xxx", "hobby":["book","music","run","food"]}',1);
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =1;
select jsonb_mergepatch(a, '{"name":"adc007"}') from tbl_jsonb_ft3_test where b = 1;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =1;
select jsonb_mergepatch(a, '{"addres":{"home":"I no"}}') from tbl_jsonb_ft3_test where b = 1;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =1;
select jsonb_mergepatch(a,  '{"addres":{"company":"HHHKKK"}}') from tbl_jsonb_ft3_test where b = 1;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =1;
select jsonb_mergepatch(a, '{"age":"22"}') from tbl_jsonb_ft3_test where b = 1;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =1;
select jsonb_mergepatch(a, '{"age":22}') from tbl_jsonb_ft3_test where b = 1;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =1;
select jsonb_mergepatch(a, '{"hobby":[123,"123"]}') from tbl_jsonb_ft3_test where b = 1;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =1;
select jsonb_mergepatch(a, '{"addres":{"home":"xzx","moe":"cdf"}}') from tbl_jsonb_ft3_test where b = 1;
insert into tbl_jsonb_ft3_test values('{"A":{"KMP":"1","ADC":{"BBC":"2"},"OME":3},"B":{"KMP_A":1,"ADC_A":{"BBC_A":2}, "OME_A":3}}',2);
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =2;
select jsonb_mergepatch(a, '{"A":{"KMP":10}}') from tbl_jsonb_ft3_test where b = 2;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test;
select jsonb_mergepatch(a, '{"A":{"ADC":{"BBC":20}}}') from tbl_jsonb_ft3_test where b = 2;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test;
select jsonb_mergepatch(a, '{"A":{"OME":{"A":2}}}') from tbl_jsonb_ft3_test where b = 2;---ok
select jsonb_query(a, '$') from tbl_jsonb_ft3_test;
select jsonb_mergepatch(a, '{"A":{"OME":30}}') from tbl_jsonb_ft3_test where b = 2;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test;
select jsonb_mergepatch(a, '{"B":{"KMP_A":10}}') from tbl_jsonb_ft3_test where b = 2;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test;
select jsonb_mergepatch(a, '{"B":{"ADC_A":30}}') from tbl_jsonb_ft3_test where b = 2;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test;
select jsonb_mergepatch(a, '{"B":{"ADC_A":{"BBC_A":{"LOL":400}}}}') from tbl_jsonb_ft3_test where b = 2;
insert into tbl_jsonb_ft3_test values('{"A":{"P1":"1","P2":{"Z1":"2","Z2":"3","Z3":{"T1":4,"T2":{"K1":5,"K2":6}}},"P3":7},"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":10}}}}}}',3);
----replace
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"KEY":100}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"KEY":100}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P1":{"KEY":100}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"KEY":100}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z2":20}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T1":40}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K1":50}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":100}}}}}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
----delete
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":null}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":null}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P3":null}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P4":null}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z1":null}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T1":null}}}}') from tbl_jsonb_ft3_test where b = 3; ---不支持大写
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K1":null}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K2":null}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K3":null}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T2":{"K4":null}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"B":{"P":{"Z":{"T":{"E":{"C":null}}}}}}') from tbl_jsonb_ft3_test where b = 3;
---insert
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"C":{"P1":1}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P4":{"KEY":121}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z4":{"T1":[1,2,3,4,5]}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":[1,2,3,4,5]}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":{"K3":1000}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":123}}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":10}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}') from tbl_jsonb_ft3_test where b = 3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
select jsonb_query(a, '$') from tbl_jsonb_ft3_test where b =3;
------------------------------------
-- JSONB_SET
------------------------------------
insert into tbl_jsonb_ft3_test values('{"name":"xxx","age":0,"manny":false,"addr":"xxx","ho":[0,0,0,{"o":0}],"case":{"A":1,"B":2,"C":3}}',4);
---delete
select jsonb_set(to_blob(a),'$.age') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.age') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.name') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.name') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.manny') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.manny') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.addr') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.addr') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ho') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[3].o') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ho[3].o') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[3]') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ho[3]') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.A') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.A') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.B') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.B') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.C') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.C') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.D') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.D') from tbl_jsonb_ft3_test where b=4;
---replece
select jsonb_set(to_blob(a),'$.age',100) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.age',100) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.name','"ZHANGFEI"') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.name','"ZHANGFEI"') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.manny',false) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.manny',false) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.addr','"CHANBANPO"') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.addr','"CHANGBANPO"') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho',[1,3,4,5]) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ho',[1,3,4,5]) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[3].o','"LING"') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ho[3].o','"LING"') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[3]',123) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ho[3]',123) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case','{"M":"LINGDANFA"}') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case','{"M":"LINGDANFA"}') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.A',101) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.A',101) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.B',false) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.B',true) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.C','"ONE"') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.C','"ONE"') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.D',123) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.D',123) from tbl_jsonb_ft3_test where b=4;
---insert
select jsonb_set(to_blob(a),'$.ADD1',100) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ADD1',100) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[6]',1234) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ho[6]',1234) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[3].k','"K"' error on error) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.ho[3].k','"K"' error on error) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.D',100) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(a,'$.case.D',100) from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.case.E','{"kay":"val"}') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[5].case.A','{"kay":"val"}') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[4].case.A','{"kay":"val"}') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[4]','{"kay":"val"}') from tbl_jsonb_ft3_test where b=4;
select jsonb_set(to_blob(a),'$.ho[5]','{"kay":"val"}') from tbl_jsonb_ft3_test where b=4;

------------------------------------
-- JSONB_ERROR
------------------------------------
drop table if exists tbl_jb_eror_test_xy; ---Succeed.
create table tbl_jb_eror_test_xy(a jsonb);---Succeed.
insert into tbl_jb_eror_test_xy values('[aaa]',1);    ---CT-00601, Sql syntax error: too many value expressions
insert into tbl_jb_eror_test_xy values('[123,]',1);   ---CT-00601, Sql syntax error: too many value expressions
insert into tbl_jb_eror_test_xy values('[123,[NULL]]',1); ---CT-00601, Sql syntax error: too many value expressions
insert into tbl_jb_eror_test_xy values('[aaa]'); ---CT-02504, JSON syntax error, unexpected a found
insert into tbl_jb_eror_test_xy values('[123,]');---CT-02504, JSON syntax error, unexpected ] found
insert into tbl_jb_base_test_xy values('{"kex_1":2738937798.925638525,"kex_2":"string","kex_3":false,"kex_4":[1,2,3,4],"kex_5":{"k_1":1,"k_2":'string'}}');     --CT-00601, [1:144]Sql syntax error: , expected but string found


insert into tbl_jb_eror_test_xy values('{"kex_1":2738937798.925638525,"kex_2":"string","kex_3":false,"kex_4":[1,2,3,4],"kex_5":{"k_1":1,"k_2":"string"}}');     --1 rows affected.
select jsonb_value(a, '$[0].programmers[0].firstName' error on error) as jb_res from tbl_jb_eror_test_xy ; ---CT-02506, JSONB_VALUE evaluated to no value
select jsonb_value(a, '$[0].kex_' error on error) as jb_res from tbl_jb_eror_test_xy ; ---CT-02506, JSONB_VALUE evaluated to no value
select jsonb_value(a, '$[0].kex_4' error on error) as jb_res from tbl_jb_eror_test_xy ; ---CT-02506, JSONB_VALUE evaluated to non-scalar value
select jsonb_query(a, '$' ,returning varchar2(512) with wrapper ) as jbq_res from tbl_jb_eror_test_xy ; ---CT-02501, Invalid RETURNING/ON clause
select jsonb_query(a, '$.kex_1' returning varchar2(512) error on error) as jbq_res from tbl_jb_eror_test_xy ; ---CT-02506, JSONB_VALUE evaluated to scalar value
select jsonb_query(to_blob('0B00000001110444440708090A31323334'), '$') as val;---[1,2,3,4]
select jsonb_query(to_blob('0B00000001110444440708090A3132333'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_query(to_blob('0B10000001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_query(to_blob('0B01000001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_query(to_blob('0B00100001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_query(to_blob('0B00010001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_query(to_blob('0B00001001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_query(to_blob('0B00000101110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_query(to_blob('0B00000011110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, version is not correct.
select jsonb_query(to_blob('0B00000000110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, version is not correct.
select jsonb_query(to_blob('0B00000001010444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, head bytes number is not correct.
select jsonb_query(to_blob('0B00000001100444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, entry bytes number is not correct.
select jsonb_query(to_blob('0B00000001111444440708090A31323334'), '$') as val;--[1,2,3,4] troble

select jsonb_query(to_blob('0B00000001110344440708090A31323334'), '$') as val;------[1,2,34] --troble
---insert into tbl_jb_eror_test_xy values('[1,2,34]');---0A000000011103444006070831323334
---select * from tbl_jb_eror_test_xy;


select jsonb_query(to_blob('370000000111065555550A0F171D2227810004054181300405426F6E658140040543318120040544811004054581500405460444440708090A31323334'), '$') ; ---[{"A":null},{"B":"one"},{"C":1},{"D":true},{"E":false},{"F":[1,2,3,4]}]
select jsonb_query(to_blob('370000000111065555550A0F171D2227810004054181300405426F6E658140040543318120040544811004054581500405460444440708090A31323334'), '$[0].B' error on error) ;---CT-02506, JSONB_VALUE evaluated to no value
select jsonb_query(to_blob('370100000111065555550A0F171D2227810004054181300405426F6E658140040543318120040544811004054581500405460444440708090A31323334'), '$[0].A' error on error) ;---CT-02508, JSONB format error, length is not correct.


select jsonb_value(to_blob('370000000111065555550A0F171D2227810004054181300405426F6E658140040543318120040544811004054581500405460444440708090A31323334'), '$' error on error) ; ---CT-02506, JSONB_VALUE evaluated to non-scalar value
select jsonb_value(to_blob('370000000111065555550A0F171D2227810004054181300405426F6E658140040543318120040544811004054581500405460444440708090A31323334'), '$[0].B' error on error) ;---CT-02506, JSONB_VALUE evaluated to no value
select jsonb_value(to_blob('370100000111065555550A0F171D2227810004054181300405426F6E658140040543318120040544811004054581500405460444440708090A31323334'), '$[0].A' error on error) ;---CT-02508, JSONB format error, length is not correct.



select jsonb_exists(to_blob('0B00000001110444440708090A3132333'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_exists(to_blob('0B10000001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_exists(to_blob('0B01000001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_exists(to_blob('0B00100001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_exists(to_blob('0B00010001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_exists(to_blob('0B00001001110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_exists(to_blob('0B00000101110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, length is not correct.
select jsonb_exists(to_blob('0B00000011110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, version is not correct.
select jsonb_exists(to_blob('0B00000000110444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, version is not correct.
select jsonb_exists(to_blob('0B00000001010444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, head bytes number is not correct.
select jsonb_exists(to_blob('0B00000001100444440708090A31323334'), '$') as val;---CT-02508, JSONB format error, entry bytes number is not correct.



drop table if exists tbl_jb_eror1_test_xy; ---Succeed.
create table tbl_jb_eror1_test_xy(a jsonb, b int primary key);---Succeed.

insert into tbl_jb_eror1_test_xy values(to_blob('230000000111834340090B0F14181E69646E616D65736C617279303030317875796F6E673130303030'), 1);---1 rows affected.
select jsonb_query(a,'$.di' error on error)  from tbl_jb_eror1_test_xy where b=1;---CT-02506, JSONB_VALUE evaluated to no value



insert into tbl_jb_eror1_test_xy values('[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1,"z"],2],3],4],5],6],7],8],9],10],11],12],13],14],15],16],17],18],19],20],21],22],23],24],25],26],27],28],29],30],31],32],33],34],35],36],37],38],39],40],41],42],43],44],45]',2);
select jsonb_value(a, '$.[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][1]') from tbl_jb_eror1_test_xy where b=2;---CT-02503, JSON path expression syntax error, exceed max path nest level(maximum: 32)
select jsonb_mergepatch(a, '{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"B":{"C":{"D":{"E":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":10}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}') from tbl_jb_eror1_test_xy where b = 2; ---1 rows affected.

insert into tbl_jb_eror1_test_xy values('{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"P2":{"Z3":{"T2":{"K2":{"M1":{"M2":{"M3":{"M4":{"A":{"B":{"C":{"D":{"E":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"A":{"P2":{"Z3":{"T3":{"K3":{"LL":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":{"B":{"P":{"Z":{"T":{"E":{"C":8,"B":9,"D":10}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}',3);---1 rows affected.

drop table if exists tbl_jsonb_026;
create table tbl_jsonb_026(id int,c_jsonb jsonb,c_json clob);
insert into tbl_jsonb_026 values(1,'[{"k1":[{"s1":["a","sd","-100",[0,100,[{"s2":"rr","s3":"周杰伦"}]]]},1000,"200we",{"d1":{"t1":"2021-7-21 09:23:45.66","t2":9999}}],"k2":{"q2":{"f2":"水杯","f3":"手机","f4":"fdfs","f5":["fdf",[100,200,"re",[1000,2000,[-1.234,{"w1":"终结者"}]]]]}},"k3":[{"g1":100},{"g2":{"g3":"nice"}},10000,{"g4":{"g5":{"g6":"2323","g7":-100000}}},"good boy","giraffe"]},{"s1#$%%@#":[null,0,-100,{"a2":null,"水果":"香蕉"},["富贵竹","panda","@#$$",[1000,"鼠标",null]]]},[100,[200,[300,[400,[500,[{"结果":"死机"}]]]]]],{"h1":{"h2":{"h3":{"h4":{"h5":["中国好娃娃"]}}}}}]','[{"k1":[{"s1":["a","sd","-100",[0,100,[{"s2":"rr","s3":"周杰伦"}]]]},1000,"200we",{"d1":{"t1":"2021-7-21 09:23:45.66","t2":9999}}],"k2":{"q2":{"f2":"水杯","f3":"手机","f4":"fdfs","f5":["fdf",[100,200,"re",[1000,2000,[-1.234,{"w1":"终结者"}]]]]}},"k3":[{"g1":100},{"g2":{"g3":"nice"}},10000,{"g4":{"g5":{"g6":"2323","g7":-100000}}},"good boy","giraffe"]},{"s1#$%%@#":[null,0,-100,{"a2":null,"水果":"香蕉"},["富贵竹","panda","@#$$",[1000,"鼠标",null]]]},[100,[200,[300,[400,[500,[{"结果":"死机"}]]]]]],{"h1":{"h2":{"h3":{"h4":{"h5":["中国好娃娃"]}}}}}]');
commit;

select 1 from tbl_jsonb_026 where jsonb_value(c_jsonb,'$[1]."s1#$%%@#"[0]') is null;
select jsonb_query(jsonb_set(c_jsonb,'$[1]."s1#$%%@#"[3].a2','"故事书"' returning jsonb error on error ),'$[1]."s1#$%%@#"[3].a2'  with wrapper error on error) val from tbl_jsonb_026;
select jsonb_value(c_jsonb,'$[1]."s1#$%%@#"[2]') from tbl_jsonb_026;
select NVL2(jsonb_value(c_jsonb,'$[1]."s1#$%%@#"[0]'),jsonb_query(jsonb_set(c_jsonb,'$[1]."s1#$%%@#"[3].a2','"故事书"' returning jsonb error on error ),'$[1]."s1#$%%@#"[3].a2'  with wrapper error on error),jsonb_value(c_jsonb,'$[1]."s1#$%%@#"[2]')) from tbl_jsonb_026;

select 1 from tbl_jsonb_026 where jsonb_value(c_jsonb,'$[1]."s1#$%%@#"[0]') is null;
select NVL(jsonb_value(c_jsonb,'$[1]."s1#$%%@#"[0]'),jsonb_query(jsonb_set(c_jsonb,'$[1]."s1#$%%@#"[3].a2','"故事书"' returning jsonb error on error ),'$[1]."s1#$%%@#"[3].a2'  with wrapper error on error)) from tbl_jsonb_026;
select NVL(jsonb_value(c_jsonb,'$[1]."s1#$%%@#"[0]'),100) from tbl_jsonb_026;

select 1 from tbl_jsonb_026 where json_value(c_json,'$[1]."s1#$%%@#"[0]') is null;
select NVL(json_value(c_json,'$[1]."s1#$%%@#"[0]'),100) from tbl_jsonb_026;
drop table if exists tbl_jsonb_026;
