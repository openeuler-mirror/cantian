--test newpage
set pagesize 4;
drop table if exists wg_newpage;
create table wg_newpage (f1 int);
insert into wg_newpage values(1);
insert into wg_newpage values(2);
insert into wg_newpage values(3);
insert into wg_newpage values(4);
insert into wg_newpage values(5);
insert into wg_newpage values(6);
insert into wg_newpage values(7);
insert into wg_newpage values(8);
insert into wg_newpage values(9);
insert into wg_newpage values(10);
insert into wg_newpage values(11);
insert into wg_newpage values(12);
set newpage none
select * from wg_newpage;
set newpage 0
select * from wg_newpage;
set newpage 1
select * from wg_newpage;
set newpage 2
select * from wg_newpage;
