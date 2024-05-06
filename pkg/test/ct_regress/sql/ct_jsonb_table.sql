-- The code of JSONB_TABLE is almost depended on JSON_TABLE.
-- The main process is not changed, so when someone find a bug in JSONB_TABLE, it maybe occurs in JSON_TABLE very possiblely.
SELECT * FROM JSON_TABLE('{"a":100, "b":200}', '$' COLUMNS (a  PATH '$.a' , b PATH '$.b', c EXISTS PATH '$.a'));
SELECT * FROM JSON_TABLE('{"a":100, "b":200, "c":[true, false]}', '$' COLUMNS (a  PATH '$.a' , b PATH '$.b', c PATH '$.c[*]'));
SELECT * FROM JSON_TABLE('{"list":[{"a":100, "b":200}, {"a":300, "b":400}]}', '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) order by a;
SELECT * FROM JSON_TABLE('{"list":[{"a":100, "b":200}, {"a":300, "b":400}, {"a":500, "b":600}]}', '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) order by a;
SELECT * FROM JSON_TABLE('[1, {"start":{"list":[{"a":100, "b":200}, {"a":300, "b":400}, {"a":500, "b":600}]}}]', '$[1].start.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) order by a;

drop table if exists jsonb_tbl_test;
create table jsonb_tbl_test (a jsonb, b int);
insert into jsonb_tbl_test values('{"a":100, "b":200}', 1);
insert into jsonb_tbl_test values('{"a":100, "b":200, "c":[true, false]}', 2);
insert into jsonb_tbl_test values('{"list":[{"a":100, "b":200}, {"a":300, "b":400}]}', 3);
insert into jsonb_tbl_test values('{"list":[{"a":100, "b":200}, {"a":300, "b":400}, {"a":500, "b":600}]}', 4);
insert into jsonb_tbl_test values('[1, {"start":{"list":[{"a":100, "b":200}, {"a":300, "b":400}, {"a":500, "b":600}]}}]', 5);
commit;
SELECT jbt.a, jbt.b, jbt.c FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$' COLUMNS (a  PATH '$.a' , b PATH '$.b', c EXISTS PATH '$.a')) jbt on t.b = 1;
SELECT jbt.a, jbt.b, jbt.c FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$' COLUMNS (a  PATH '$.a' , b PATH '$.b', c PATH '$.c[*]')) jbt on t.b = 2;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$.list' error on error COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on t.b = 3 order by jbt.a;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on t.b = 3 order by jbt.a;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on t.b = 4 order by jbt.a;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on (t.b = 3 or t.b = 4) order by jbt.a;
SELECT jbt.a, jbt.b FROM jsonb_tbl_test t join JSONB_TABLE(t.a, '$[1].start.list[*]' COLUMNS (a PATH '$.a' , b PATH '$.b')) jbt on t.b = 5 order by jbt.a;
drop table if exists jsonb_tbl_test;

drop table if exists test_jsonb_table;
create table test_jsonb_table (f1 varchar(100), f2 jsonb);
insert into test_jsonb_table values(1, '[{"Phone" : [{"type" : "a", "number" : "909-555-7307"}, {"type" : "b", "number" : "415-555-1234"}]}, {"Phone" : [{"type" : "c", "number" : "909-555-7307"}, {"type" : "d", "number" : "415-555-1234"}]}]');
insert into test_jsonb_table values(2, '[{"Phone" : [{"type" : "e", "number" : "909-555-7307"}, {"type" : "f", "number" : "415-555-1234"}]}, {"Phone" : [{"type" : "g", "number" : "909-555-7307"}, {"type" : "h", "number" : "415-555-1234"}]}]');
insert into test_jsonb_table values(3, '[{"Phone" : [{"type" : "3", "number" : "909-555-7307"}, {"type" : "b", "number" : "415-555-1234"}]}, {"Phone" : [{"type" : "3", "number" : "909-555-7307"}, {"type" : "d", "number" : "415-555-1234"}]}]');
insert into test_jsonb_table values(4, '[{"Phone" : [{"type" : "4", "number" : "909-555-7307"}, {"type" : "4", "number" : "415-555-1234"}]}, {"Phone" : [{"type" : "g", "number" : "909-555-7307"}, {"type" : "h", "number" : "415-555-1234"}]}]');
commit;
select a.f1,b.* from test_jsonb_table a, jsonb_table(a.f2,'$[*].Phone[*]' error on error COLUMNS (type VARChAR2(100) PATH '$.type' )) b where a.f1(+) = b.type;
select a.f1,b.* from test_jsonb_table a, jsonb_table(a.f2,'$[*].Phone[*]' error on error COLUMNS (type VARChAR2(100) PATH '$.type' )) b;
drop table if exists test_jsonb_table;
