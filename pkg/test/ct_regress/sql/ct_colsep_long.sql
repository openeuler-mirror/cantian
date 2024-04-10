--colsep
drop table if exists wg_colsep;
create table wg_colsep (f1 int, f2 int, f3 int);
insert into wg_colsep values(1,1,1);
insert into wg_colsep values(2,2,2);
insert into wg_colsep values(3,3,3);
set colsep "
set colsep '
set colsep "asdf
set colsep 'asd
select * from wg_colsep;
set colsep ','
select * from wg_colsep;
set colsep ","
select * from wg_colsep;
set colsep "|||"
select * from wg_colsep;

--long
set long 9000
