---- The following cases have been debugged and passed by pufuan, p00421579

--- The test cases for expression calculating
select -9 << 20;
select -9 << 2;
select 9 << 63;
select 5423237233838653440 << 20;
select 5423237233838653440 << 32;
select -5423237233838653440 >> 32;
select 542323723383865345324532452343440 >> 32;
select 5423237233838653440 >> 32;
select -542323723334534534534535838653440 >> 32;
select -5423237233838653440 >> 30;
select 838653440 >> 32234444444444444444444444444444444;

select 1 + (1/2 * 3) from dual;
select (1/3+2)*3 from dual;
select 12E-1-1 from dual;
select 12E-1*10 from dual;
select 12E-1*10E1 from dual;
select 12E1*10E1 from dual;
select 12E1/10E1 from dual;

select -(1 + 2) from dual;
select -(1.0 - 1.0) from dual;
select -abs(3.0 - 2  -1) from dual;
select -1 + (- (3 + 2)) from dual;
select -1 + -(- (3 + 2)) from dual;
select -1 + -(-(- (3 + 2))) from dual;

select '123123'||123 + '123'||123 from dual;
select ('123123'||123) + ('123'||123) from dual;
select * from dual where systimestamp > null;
select cast(null as timestamp) from dual;

--DTS2019022811768
select cast(0 as bigint)*cast(-1 as real) from dual;
select cast(0 as real)*cast(-1 as bigint) from dual;
select cast(-0 as real)*cast(-1 as bigint) from dual;
select cast(-0 as real)*cast(1 as bigint) from dual;
select cast(-1 as real)*cast(0 as bigint) from dual;
select cast(0 as bigint)/cast(-1 as real) from dual;  
select cast(0 as real)/cast(-1 as bigint) from dual;  
select cast(-0 as real)/cast(-1 as bigint) from dual;   


select * from dual where '' is null;

select -null from dual;
select +null from dual;

desc -q select -null from dual;
desc -q select +null from dual;
select -sysdate from dual;

select +'123123123' from dual;

select -to_dsinterval('0 0:0:0.01') from dual;
select -to_yminterval('0-1') from dual;
select -cast('010110' as raw(11)) from dual;

--issue#23788
select cast('12312313' as raw(300))||'123123' from dual;

--- bad cases
select 12E-1E*10 from dual;

--- DATETIME function and expression
select to_date('2017-08-11', 'YYYY-MM-DD'), 
       to_date('2017-08-11', 'YYYY-MM-DD')+1, 
       to_date('2017-08-11', 'YYYY-MM-DD')+1/86400, 
       to_date('2017-08-11', 'YYYY-MM-DD')-1.0/86400, 
       to_date('2017-08-11', 'YYYY-MM-DD')-1.0/8.0 
       from dual;

select to_date('2017-09-23', 'YYYY-MM-DD'), 
       to_date('2017-09-23', 'YYYY-MM-DD') + '1'/86400 
       from dual;

select to_date('2017-09-23', 'YYYY-MM-DD') || 333 from dual;
select to_date('2017-09-23', 'YYYY-MM-DD')||9999||to_date('2017-09-23', 'YYYY-MM-DD') from dual;
select to_date('2017-09-23', 'YYYY-MM-DD') + '1' from dual;
select 1+to_date('2017-09-23', 'YYYY-MM-DD') from dual;
select 1-to_date('2017-09-23', 'YYYY-MM-DD') from dual;  

-- The overflow case for int32
select 4294967294 + 4294967292, 4294967296 * 4294967296 from dual;
select 2147483633 + 999 from dual;
select 2147483647 + 1;
select 2147483647 + 2;
select 2147483648 + 1;      

-- The priority of concat operator
select 33+44||55 from dual;
select 33+(44||55) from dual;

--- The cases for operator priority
-- 60 <--- Oracle output
select 2||1+39 from dual;

-- 411 <--- Oracle and Nebula output
select 39+2||1 from dual;
-- The priority `*` and `/` is higher than `||`. This is consistent with Oracle
select 11||22||33*2 from dual;

-- The cases for concat and arithmetic operators
select (44||55)/2 from dual;
select 333/(1.1||1) from dual;

--- The case for division operator
select 3/0 from dual;
select 3/0.0 from dual;
select 123123/0.1 from dual;
select 3.0/0.0000000000010, to_char(3.0/0.0000000000010) from dual;

--- The case for string and number
select 125423523543.3 + '234', to_char(125423523543.3 + '234') from dual;
select '2222'*'3' from dual;
select '2222'/'2' from dual;
select '2222222222222222'+'2' from dual;
select '2222222222222222'||'3' from dual;
select '2222222222222222'-'3' from dual;
select 1 + '212' + 44 from dual;

--- The cases for complex expression operation with brackets
select (33+11*22)/5+11 from dual;
select (3322)/5+11 from dual;
select to_date('2017-09-23', 'YYYY-MM-DD') + (1) from dual;

select 1+2*(3+4/4/4) from dual;
select 1+2*(3+4/4/4)||2 from dual;
select (11||22||33)*2 from dual;

select (-11||22||33)*2 from dual;

--- invalid cases
select (11||-22||33)*2 from dual;


--- decimal/number and expression
select cast('1231233413.123123213E100' as decimal)||'e213213', to_char(cast('1231233413.123123213E100' as decimal))||'e213213' from dual;
select 123456789012345678901234567890||'e213213' from dual;
select .00000000000000000000001234567890123456789012345678901234567890||'e213213' from dual;
select cast('3.141596253589793232256213599323513340034588234600534524522345245277345'||'E+9' as decimal), to_char(cast('3.141596253589793232256213599323513340034588234600534524522345245277345'||'E+9' as decimal)) from dual;

--- The following bug cases have been solved
select 32233236434563456345.0/0.000000010, to_char(32233236434563456345.0/0.000000010) from dual;
select 35423645/0.000000001, to_char(35423645/0.000000001) from dual;
select 0.23435254254234/212341241341234.99999325423542354, to_char(0.23435254254234/212341241341234.99999325423542354) from dual;
select 2/3*3.00000000000095, to_char(2/3*3.00000000000095) from dual;


-- Test some corner cases for multiplication
select 4790999999999999999999999999999999999999999999999999999999999999999999999999999999999999 * 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999;
select 4789999999999999999999999999999999999999999999999999999999999999999999999999999999999999 * 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999;
select 4770999999999999999999999999999999999999999999999999999999999999999999999999999999999999 * 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999;
select 4769999999999999999999999999999999999999999999999999999999999999999999999999999999999999 * 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999;
select 999999999999999999999/1000000000000000000000;
select 70.0 / 70 ;
select 12345678901234567890 / 123;


DROP TABLE if exists REAL_TBL;
CREATE TABLE REAL_TBL (f1  real);
INSERT INTO REAL_TBL(f1) VALUES ('    0.0');
INSERT INTO REAL_TBL(f1) VALUES ('1004.30   ');
INSERT INTO REAL_TBL(f1) VALUES ('     -34.84    ');
INSERT INTO REAL_TBL(f1) VALUES ('1.2345678901234e+20');
INSERT INTO REAL_TBL(f1) VALUES ('1.2345678901234e-20');
INSERT INTO REAL_TBL(f1) VALUES (    0.0);
INSERT INTO REAL_TBL(f1) VALUES (1004.30   );
INSERT INTO REAL_TBL(f1) VALUES (     -34.84    );
INSERT INTO REAL_TBL(f1) VALUES (1.2345678901234e+20);
INSERT INTO REAL_TBL(f1) VALUES (1.2345678901234e-20);
SELECT 'TEST 1' as "ONE", * FROM REAL_TBL order by f1;

DELETE FROM REAL_TBL;
INSERT INTO REAL_TBL(f1) VALUES ('10e70');
INSERT INTO REAL_TBL(f1) VALUES ('-10e70');
INSERT INTO REAL_TBL(f1) VALUES ('10e-70');
INSERT INTO REAL_TBL(f1) VALUES ('-10e-70');
INSERT INTO REAL_TBL(f1) VALUES (10e70);
INSERT INTO REAL_TBL(f1) VALUES (-10e70);
INSERT INTO REAL_TBL(f1) VALUES (10e-70);
INSERT INTO REAL_TBL(f1) VALUES (-10e-70);
INSERT INTO REAL_TBL(f1) VALUES (10e170);
INSERT INTO REAL_TBL(f1) VALUES (-10e270);
INSERT INTO REAL_TBL(f1) VALUES (10e-170);
INSERT INTO REAL_TBL(f1) VALUES (-10e-270);
SELECT 'TEST 2', * FROM REAL_TBL order by f1;

-- bad input
DELETE FROM REAL_TBL;
INSERT INTO REAL_TBL(f1) VALUES ('');
INSERT INTO REAL_TBL(f1) VALUES ('       ');
INSERT INTO REAL_TBL(f1) VALUES ('xyz');
INSERT INTO REAL_TBL(f1) VALUES ('5.0.0');
INSERT INTO REAL_TBL(f1) VALUES ('5 . 0');
INSERT INTO REAL_TBL(f1) VALUES ('5.   0');
INSERT INTO REAL_TBL(f1) VALUES ('     - 3.0');
INSERT INTO REAL_TBL(f1) VALUES ('123            5');
SELECT 'TEST 3', * FROM REAL_TBL order by f1;

-- test for over- and underflow
DELETE FROM REAL_TBL;
INSERT INTO REAL_TBL(f1) VALUES ('10e400');
INSERT INTO REAL_TBL(f1) VALUES ('-10e400');
INSERT INTO REAL_TBL(f1) VALUES ('-10e400');
INSERT INTO REAL_TBL(f1) VALUES ('-10e400');
INSERT INTO REAL_TBL(f1) VALUES (10e400);
INSERT INTO REAL_TBL(f1) VALUES (-10e400);
INSERT INTO REAL_TBL(f1) VALUES (-10e400);
INSERT INTO REAL_TBL(f1) VALUES (-10e400);
SELECT 'TEST 4', * FROM REAL_TBL order by f1;


DELETE FROM REAL_TBL;
INSERT INTO REAL_TBL(f1) VALUES ('0.0');
INSERT INTO REAL_TBL(f1) VALUES ('-34.84');
INSERT INTO REAL_TBL(f1) VALUES ('-1004.30');
INSERT INTO REAL_TBL(f1) VALUES ('-1.2345678901234e+200');
INSERT INTO REAL_TBL(f1) VALUES ('-1.2345678901234e-200');
INSERT INTO REAL_TBL(f1) VALUES (0.0);
INSERT INTO REAL_TBL(f1) VALUES (-34.84);
INSERT INTO REAL_TBL(f1) VALUES (-1004.30);
INSERT INTO REAL_TBL(f1) VALUES (-1.2345678901234e+200);
INSERT INTO REAL_TBL(f1) VALUES (-1.2345678901234e-200);
SELECT '' AS five, * FROM REAL_TBL order by f1;

DROP TABLE if exists num_data;
CREATE TABLE num_data (id int, val number(38,10));
DROP TABLE if exists num_exp_add;
CREATE TABLE num_exp_add (id1 int, id2 int, expected number(38,10));
DROP TABLE if exists num_exp_sub;
CREATE TABLE num_exp_sub (id1 int, id2 int, expected number(38,10));
DROP TABLE if exists num_exp_div;
CREATE TABLE num_exp_div (id1 int, id2 int, expected number(38,10));
DROP TABLE if exists num_exp_mul;
CREATE TABLE num_exp_mul (id1 int, id2 int, expected number(38,10));
DROP TABLE if exists num_result;
CREATE TABLE num_result (id1 int, id2 int, result number(38,10));

INSERT INTO num_exp_add VALUES (0,0,'0');
INSERT INTO num_exp_sub VALUES (0,0,'0');
INSERT INTO num_exp_mul VALUES (0,0,'0');
INSERT INTO num_exp_div VALUES (0,0,'NaN');
INSERT INTO num_exp_add VALUES (0,1,'0');
INSERT INTO num_exp_sub VALUES (0,1,'0');
INSERT INTO num_exp_mul VALUES (0,1,'0');
INSERT INTO num_exp_div VALUES (0,1,'NaN');
INSERT INTO num_exp_add VALUES (0,2,'-34338492.215397047');
INSERT INTO num_exp_sub VALUES (0,2,'34338492.215397047');
INSERT INTO num_exp_mul VALUES (0,2,'0');
INSERT INTO num_exp_div VALUES (0,2,'0');
INSERT INTO num_exp_add VALUES (0,3,'4.31');
INSERT INTO num_exp_sub VALUES (0,3,'-4.31');
INSERT INTO num_exp_mul VALUES (0,3,'0');
INSERT INTO num_exp_div VALUES (0,3,'0');
INSERT INTO num_exp_add VALUES (0,4,'7799461.4119');
INSERT INTO num_exp_sub VALUES (0,4,'-7799461.4119');
INSERT INTO num_exp_mul VALUES (0,4,'0');
INSERT INTO num_exp_div VALUES (0,4,'0');
INSERT INTO num_exp_add VALUES (0,5,'16397.038491');
INSERT INTO num_exp_sub VALUES (0,5,'-16397.038491');
INSERT INTO num_exp_mul VALUES (0,5,'0');
INSERT INTO num_exp_div VALUES (0,5,'0');
INSERT INTO num_exp_add VALUES (0,6,'93901.57763026');
INSERT INTO num_exp_sub VALUES (0,6,'-93901.57763026');
INSERT INTO num_exp_mul VALUES (0,6,'0');
INSERT INTO num_exp_div VALUES (0,6,'0');
INSERT INTO num_exp_add VALUES (0,7,'-83028485');
INSERT INTO num_exp_sub VALUES (0,7,'83028485');
INSERT INTO num_exp_mul VALUES (0,7,'0');
INSERT INTO num_exp_div VALUES (0,7,'0');
INSERT INTO num_exp_add VALUES (0,8,'74881');
INSERT INTO num_exp_sub VALUES (0,8,'-74881');
INSERT INTO num_exp_mul VALUES (0,8,'0');
INSERT INTO num_exp_div VALUES (0,8,'0');
INSERT INTO num_exp_add VALUES (0,9,'-24926804.045047420');
INSERT INTO num_exp_sub VALUES (0,9,'24926804.045047420');
INSERT INTO num_exp_mul VALUES (0,9,'0');
INSERT INTO num_exp_div VALUES (0,9,'0');
INSERT INTO num_exp_add VALUES (1,0,'0');
INSERT INTO num_exp_sub VALUES (1,0,'0');
INSERT INTO num_exp_mul VALUES (1,0,'0');
INSERT INTO num_exp_div VALUES (1,0,'NaN');
INSERT INTO num_exp_add VALUES (1,1,'0');
INSERT INTO num_exp_sub VALUES (1,1,'0');
INSERT INTO num_exp_mul VALUES (1,1,'0');
INSERT INTO num_exp_div VALUES (1,1,'NaN');
INSERT INTO num_exp_add VALUES (1,2,'-34338492.215397047');
INSERT INTO num_exp_sub VALUES (1,2,'34338492.215397047');
INSERT INTO num_exp_mul VALUES (1,2,'0');
INSERT INTO num_exp_div VALUES (1,2,'0');
INSERT INTO num_exp_add VALUES (1,3,'4.31');
INSERT INTO num_exp_sub VALUES (1,3,'-4.31');
INSERT INTO num_exp_mul VALUES (1,3,'0');
INSERT INTO num_exp_div VALUES (1,3,'0');
INSERT INTO num_exp_add VALUES (1,4,'7799461.4119');
INSERT INTO num_exp_sub VALUES (1,4,'-7799461.4119');
INSERT INTO num_exp_mul VALUES (1,4,'0');
INSERT INTO num_exp_div VALUES (1,4,'0');
INSERT INTO num_exp_add VALUES (1,5,'16397.038491');
INSERT INTO num_exp_sub VALUES (1,5,'-16397.038491');
INSERT INTO num_exp_mul VALUES (1,5,'0');
INSERT INTO num_exp_div VALUES (1,5,'0');
INSERT INTO num_exp_add VALUES (1,6,'93901.57763026');
INSERT INTO num_exp_sub VALUES (1,6,'-93901.57763026');
INSERT INTO num_exp_mul VALUES (1,6,'0');
INSERT INTO num_exp_div VALUES (1,6,'0');
INSERT INTO num_exp_add VALUES (1,7,'-83028485');
INSERT INTO num_exp_sub VALUES (1,7,'83028485');
INSERT INTO num_exp_mul VALUES (1,7,'0');
INSERT INTO num_exp_div VALUES (1,7,'0');
INSERT INTO num_exp_add VALUES (1,8,'74881');
INSERT INTO num_exp_sub VALUES (1,8,'-74881');
INSERT INTO num_exp_mul VALUES (1,8,'0');
INSERT INTO num_exp_div VALUES (1,8,'0');
INSERT INTO num_exp_add VALUES (1,9,'-24926804.045047420');
INSERT INTO num_exp_sub VALUES (1,9,'24926804.045047420');
INSERT INTO num_exp_mul VALUES (1,9,'0');
INSERT INTO num_exp_div VALUES (1,9,'0');
INSERT INTO num_exp_add VALUES (2,0,'-34338492.215397047');
INSERT INTO num_exp_sub VALUES (2,0,'-34338492.215397047');
INSERT INTO num_exp_mul VALUES (2,0,'0');
INSERT INTO num_exp_div VALUES (2,0,'NaN');
INSERT INTO num_exp_add VALUES (2,1,'-34338492.215397047');
INSERT INTO num_exp_sub VALUES (2,1,'-34338492.215397047');
INSERT INTO num_exp_mul VALUES (2,1,'0');
INSERT INTO num_exp_div VALUES (2,1,'NaN');
INSERT INTO num_exp_add VALUES (2,2,'-68676984.430794094');
INSERT INTO num_exp_sub VALUES (2,2,'0');
INSERT INTO num_exp_mul VALUES (2,2,'1179132047626883.596862135856320209');
INSERT INTO num_exp_div VALUES (2,2,'1.00000000000000000000');
INSERT INTO num_exp_add VALUES (2,3,'-34338487.905397047');
INSERT INTO num_exp_sub VALUES (2,3,'-34338496.525397047');
INSERT INTO num_exp_mul VALUES (2,3,'-147998901.44836127257');
INSERT INTO num_exp_div VALUES (2,3,'-7967167.56737750510440835266');
INSERT INTO num_exp_add VALUES (2,4,'-26539030.803497047');
INSERT INTO num_exp_sub VALUES (2,4,'-42137953.627297047');
INSERT INTO num_exp_mul VALUES (2,4,'-267821744976817.8111137106593');
INSERT INTO num_exp_div VALUES (2,4,'-4.40267480046830116685');
INSERT INTO num_exp_add VALUES (2,5,'-34322095.176906047');
INSERT INTO num_exp_sub VALUES (2,5,'-34354889.253888047');
INSERT INTO num_exp_mul VALUES (2,5,'-563049578578.769242506736077');
INSERT INTO num_exp_div VALUES (2,5,'-2094.18866914563535496429');
INSERT INTO num_exp_add VALUES (2,6,'-34244590.637766787');
INSERT INTO num_exp_sub VALUES (2,6,'-34432393.793027307');
INSERT INTO num_exp_mul VALUES (2,6,'-3224438592470.18449811926184222');
INSERT INTO num_exp_div VALUES (2,6,'-365.68599891479766440940');
INSERT INTO num_exp_add VALUES (2,7,'-117366977.215397047');
INSERT INTO num_exp_sub VALUES (2,7,'48689992.784602953');
INSERT INTO num_exp_mul VALUES (2,7,'2851072985828710.485883795');
INSERT INTO num_exp_div VALUES (2,7,'.41357483778485235518');
INSERT INTO num_exp_add VALUES (2,8,'-34263611.215397047');
INSERT INTO num_exp_sub VALUES (2,8,'-34413373.215397047');
INSERT INTO num_exp_mul VALUES (2,8,'-2571300635581.146276407');
INSERT INTO num_exp_div VALUES (2,8,'-458.57416721727870888476');
INSERT INTO num_exp_add VALUES (2,9,'-59265296.260444467');
INSERT INTO num_exp_sub VALUES (2,9,'-9411688.170349627');
INSERT INTO num_exp_mul VALUES (2,9,'855948866655588.453741509242968740');
INSERT INTO num_exp_div VALUES (2,9,'1.37757299946438931811');
INSERT INTO num_exp_add VALUES (3,0,'4.31');
INSERT INTO num_exp_sub VALUES (3,0,'4.31');
INSERT INTO num_exp_mul VALUES (3,0,'0');
INSERT INTO num_exp_div VALUES (3,0,'NaN');
INSERT INTO num_exp_add VALUES (3,1,'4.31');
INSERT INTO num_exp_sub VALUES (3,1,'4.31');
INSERT INTO num_exp_mul VALUES (3,1,'0');
INSERT INTO num_exp_div VALUES (3,1,'NaN');
INSERT INTO num_exp_add VALUES (3,2,'-34338487.905397047');
INSERT INTO num_exp_sub VALUES (3,2,'34338496.525397047');
INSERT INTO num_exp_mul VALUES (3,2,'-147998901.44836127257');
INSERT INTO num_exp_div VALUES (3,2,'-.00000012551512084352');
INSERT INTO num_exp_add VALUES (3,3,'8.62');
INSERT INTO num_exp_sub VALUES (3,3,'0');
INSERT INTO num_exp_mul VALUES (3,3,'18.5761');
INSERT INTO num_exp_div VALUES (3,3,'1.00000000000000000000');
INSERT INTO num_exp_add VALUES (3,4,'7799465.7219');
INSERT INTO num_exp_sub VALUES (3,4,'-7799457.1019');
INSERT INTO num_exp_mul VALUES (3,4,'33615678.685289');
INSERT INTO num_exp_div VALUES (3,4,'.00000055260225961552');
INSERT INTO num_exp_add VALUES (3,5,'16401.348491');
INSERT INTO num_exp_sub VALUES (3,5,'-16392.728491');
INSERT INTO num_exp_mul VALUES (3,5,'70671.23589621');
INSERT INTO num_exp_div VALUES (3,5,'.00026285234387695504');
INSERT INTO num_exp_add VALUES (3,6,'93905.88763026');
INSERT INTO num_exp_sub VALUES (3,6,'-93897.26763026');
INSERT INTO num_exp_mul VALUES (3,6,'404715.7995864206');
INSERT INTO num_exp_div VALUES (3,6,'.00004589912234457595');
INSERT INTO num_exp_add VALUES (3,7,'-83028480.69');
INSERT INTO num_exp_sub VALUES (3,7,'83028489.31');
INSERT INTO num_exp_mul VALUES (3,7,'-357852770.35');
INSERT INTO num_exp_div VALUES (3,7,'-.00000005190989574240');
INSERT INTO num_exp_add VALUES (3,8,'74885.31');
INSERT INTO num_exp_sub VALUES (3,8,'-74876.69');
INSERT INTO num_exp_mul VALUES (3,8,'322737.11');
INSERT INTO num_exp_div VALUES (3,8,'.00005755799201399553');
INSERT INTO num_exp_add VALUES (3,9,'-24926799.735047420');
INSERT INTO num_exp_sub VALUES (3,9,'24926808.355047420');
INSERT INTO num_exp_mul VALUES (3,9,'-107434525.43415438020');
INSERT INTO num_exp_div VALUES (3,9,'-.00000017290624149854');
INSERT INTO num_exp_add VALUES (4,0,'7799461.4119');
INSERT INTO num_exp_sub VALUES (4,0,'7799461.4119');
INSERT INTO num_exp_mul VALUES (4,0,'0');
INSERT INTO num_exp_div VALUES (4,0,'NaN');
INSERT INTO num_exp_add VALUES (4,1,'7799461.4119');
INSERT INTO num_exp_sub VALUES (4,1,'7799461.4119');
INSERT INTO num_exp_mul VALUES (4,1,'0');
INSERT INTO num_exp_div VALUES (4,1,'NaN');
INSERT INTO num_exp_add VALUES (4,2,'-26539030.803497047');
INSERT INTO num_exp_sub VALUES (4,2,'42137953.627297047');
INSERT INTO num_exp_mul VALUES (4,2,'-267821744976817.8111137106593');
INSERT INTO num_exp_div VALUES (4,2,'-.22713465002993920385');
INSERT INTO num_exp_add VALUES (4,3,'7799465.7219');
INSERT INTO num_exp_sub VALUES (4,3,'7799457.1019');
INSERT INTO num_exp_mul VALUES (4,3,'33615678.685289');
INSERT INTO num_exp_div VALUES (4,3,'1809619.81714617169373549883');
INSERT INTO num_exp_add VALUES (4,4,'15598922.8238');
INSERT INTO num_exp_sub VALUES (4,4,'0');
INSERT INTO num_exp_mul VALUES (4,4,'60831598315717.14146161');
INSERT INTO num_exp_div VALUES (4,4,'1.00000000000000000000');
INSERT INTO num_exp_add VALUES (4,5,'7815858.450391');
INSERT INTO num_exp_sub VALUES (4,5,'7783064.373409');
INSERT INTO num_exp_mul VALUES (4,5,'127888068979.9935054429');
INSERT INTO num_exp_div VALUES (4,5,'475.66281046305802686061');
INSERT INTO num_exp_add VALUES (4,6,'7893362.98953026');
INSERT INTO num_exp_sub VALUES (4,6,'7705559.83426974');
INSERT INTO num_exp_mul VALUES (4,6,'732381731243.745115764094');
INSERT INTO num_exp_div VALUES (4,6,'83.05996138436129499606');
INSERT INTO num_exp_add VALUES (4,7,'-75229023.5881');
INSERT INTO num_exp_sub VALUES (4,7,'90827946.4119');
INSERT INTO num_exp_mul VALUES (4,7,'-647577464846017.9715');
INSERT INTO num_exp_div VALUES (4,7,'-.09393717604145131637');
INSERT INTO num_exp_add VALUES (4,8,'7874342.4119');
INSERT INTO num_exp_sub VALUES (4,8,'7724580.4119');
INSERT INTO num_exp_mul VALUES (4,8,'584031469984.4839');
INSERT INTO num_exp_div VALUES (4,8,'104.15808298366741897143');
INSERT INTO num_exp_add VALUES (4,9,'-17127342.633147420');
INSERT INTO num_exp_sub VALUES (4,9,'32726265.456947420');
INSERT INTO num_exp_mul VALUES (4,9,'-194415646271340.1815956522980');
INSERT INTO num_exp_div VALUES (4,9,'-.31289456112403769409');
INSERT INTO num_exp_add VALUES (5,0,'16397.038491');
INSERT INTO num_exp_sub VALUES (5,0,'16397.038491');
INSERT INTO num_exp_mul VALUES (5,0,'0');
INSERT INTO num_exp_div VALUES (5,0,'NaN');
INSERT INTO num_exp_add VALUES (5,1,'16397.038491');
INSERT INTO num_exp_sub VALUES (5,1,'16397.038491');
INSERT INTO num_exp_mul VALUES (5,1,'0');
INSERT INTO num_exp_div VALUES (5,1,'NaN');
INSERT INTO num_exp_add VALUES (5,2,'-34322095.176906047');
INSERT INTO num_exp_sub VALUES (5,2,'34354889.253888047');
INSERT INTO num_exp_mul VALUES (5,2,'-563049578578.769242506736077');
INSERT INTO num_exp_div VALUES (5,2,'-.00047751189505192446');
INSERT INTO num_exp_add VALUES (5,3,'16401.348491');
INSERT INTO num_exp_sub VALUES (5,3,'16392.728491');
INSERT INTO num_exp_mul VALUES (5,3,'70671.23589621');
INSERT INTO num_exp_div VALUES (5,3,'3804.41728329466357308584');
INSERT INTO num_exp_add VALUES (5,4,'7815858.450391');
INSERT INTO num_exp_sub VALUES (5,4,'-7783064.373409');
INSERT INTO num_exp_mul VALUES (5,4,'127888068979.9935054429');
INSERT INTO num_exp_div VALUES (5,4,'.00210232958726897192');
INSERT INTO num_exp_add VALUES (5,5,'32794.076982');
INSERT INTO num_exp_sub VALUES (5,5,'0');
INSERT INTO num_exp_mul VALUES (5,5,'268862871.275335557081');
INSERT INTO num_exp_div VALUES (5,5,'1.00000000000000000000');
INSERT INTO num_exp_add VALUES (5,6,'110298.61612126');
INSERT INTO num_exp_sub VALUES (5,6,'-77504.53913926');
INSERT INTO num_exp_mul VALUES (5,6,'1539707782.76899778633766');
INSERT INTO num_exp_div VALUES (5,6,'.17461941433576102689');
INSERT INTO num_exp_add VALUES (5,7,'-83012087.961509');
INSERT INTO num_exp_sub VALUES (5,7,'83044882.038491');
INSERT INTO num_exp_mul VALUES (5,7,'-1361421264394.416135');
INSERT INTO num_exp_div VALUES (5,7,'-.00019748690453643710');
INSERT INTO num_exp_add VALUES (5,8,'91278.038491');
INSERT INTO num_exp_sub VALUES (5,8,'-58483.961509');
INSERT INTO num_exp_mul VALUES (5,8,'1227826639.244571');
INSERT INTO num_exp_div VALUES (5,8,'.21897461960978085228');
INSERT INTO num_exp_add VALUES (5,9,'-24910407.006556420');
INSERT INTO num_exp_sub VALUES (5,9,'24943201.083538420');
INSERT INTO num_exp_mul VALUES (5,9,'-408725765384.257043660243220');
INSERT INTO num_exp_div VALUES (5,9,'-.00065780749354660427');
INSERT INTO num_exp_add VALUES (6,0,'93901.57763026');
INSERT INTO num_exp_sub VALUES (6,0,'93901.57763026');
INSERT INTO num_exp_mul VALUES (6,0,'0');
INSERT INTO num_exp_div VALUES (6,0,'NaN');
INSERT INTO num_exp_add VALUES (6,1,'93901.57763026');
INSERT INTO num_exp_sub VALUES (6,1,'93901.57763026');
INSERT INTO num_exp_mul VALUES (6,1,'0');
INSERT INTO num_exp_div VALUES (6,1,'NaN');
INSERT INTO num_exp_add VALUES (6,2,'-34244590.637766787');
INSERT INTO num_exp_sub VALUES (6,2,'34432393.793027307');
INSERT INTO num_exp_mul VALUES (6,2,'-3224438592470.18449811926184222');
INSERT INTO num_exp_div VALUES (6,2,'-.00273458651128995823');
INSERT INTO num_exp_add VALUES (6,3,'93905.88763026');
INSERT INTO num_exp_sub VALUES (6,3,'93897.26763026');
INSERT INTO num_exp_mul VALUES (6,3,'404715.7995864206');
INSERT INTO num_exp_div VALUES (6,3,'21786.90896293735498839907');
INSERT INTO num_exp_add VALUES (6,4,'7893362.98953026');
INSERT INTO num_exp_sub VALUES (6,4,'-7705559.83426974');
INSERT INTO num_exp_mul VALUES (6,4,'732381731243.745115764094');
INSERT INTO num_exp_div VALUES (6,4,'.01203949512295682469');
INSERT INTO num_exp_add VALUES (6,5,'110298.61612126');
INSERT INTO num_exp_sub VALUES (6,5,'77504.53913926');
INSERT INTO num_exp_mul VALUES (6,5,'1539707782.76899778633766');
INSERT INTO num_exp_div VALUES (6,5,'5.72674008674192359679');
INSERT INTO num_exp_add VALUES (6,6,'187803.15526052');
INSERT INTO num_exp_sub VALUES (6,6,'0');
INSERT INTO num_exp_mul VALUES (6,6,'8817506281.4517452372676676');
INSERT INTO num_exp_div VALUES (6,6,'1.00000000000000000000');
INSERT INTO num_exp_add VALUES (6,7,'-82934583.42236974');
INSERT INTO num_exp_sub VALUES (6,7,'83122386.57763026');
INSERT INTO num_exp_mul VALUES (6,7,'-7796505729750.37795610');
INSERT INTO num_exp_div VALUES (6,7,'-.00113095617281538980');
INSERT INTO num_exp_add VALUES (6,8,'168782.57763026');
INSERT INTO num_exp_sub VALUES (6,8,'19020.57763026');
INSERT INTO num_exp_mul VALUES (6,8,'7031444034.53149906');
INSERT INTO num_exp_div VALUES (6,8,'1.25401073209839612184');
INSERT INTO num_exp_add VALUES (6,9,'-24832902.467417160');
INSERT INTO num_exp_sub VALUES (6,9,'25020705.622677680');
INSERT INTO num_exp_mul VALUES (6,9,'-2340666225110.29929521292692920');
INSERT INTO num_exp_div VALUES (6,9,'-.00376709254265256789');
INSERT INTO num_exp_add VALUES (7,0,'-83028485');
INSERT INTO num_exp_sub VALUES (7,0,'-83028485');
INSERT INTO num_exp_mul VALUES (7,0,'0');
INSERT INTO num_exp_div VALUES (7,0,'NaN');
INSERT INTO num_exp_add VALUES (7,1,'-83028485');
INSERT INTO num_exp_sub VALUES (7,1,'-83028485');
INSERT INTO num_exp_mul VALUES (7,1,'0');
INSERT INTO num_exp_div VALUES (7,1,'NaN');
INSERT INTO num_exp_add VALUES (7,2,'-117366977.215397047');
INSERT INTO num_exp_sub VALUES (7,2,'-48689992.784602953');
INSERT INTO num_exp_mul VALUES (7,2,'2851072985828710.485883795');
INSERT INTO num_exp_div VALUES (7,2,'2.41794207151503385700');
INSERT INTO num_exp_add VALUES (7,3,'-83028480.69');
INSERT INTO num_exp_sub VALUES (7,3,'-83028489.31');
INSERT INTO num_exp_mul VALUES (7,3,'-357852770.35');
INSERT INTO num_exp_div VALUES (7,3,'-19264149.65197215777262180974');
INSERT INTO num_exp_add VALUES (7,4,'-75229023.5881');
INSERT INTO num_exp_sub VALUES (7,4,'-90827946.4119');
INSERT INTO num_exp_mul VALUES (7,4,'-647577464846017.9715');
INSERT INTO num_exp_div VALUES (7,4,'-10.64541262725136247686');
INSERT INTO num_exp_add VALUES (7,5,'-83012087.961509');
INSERT INTO num_exp_sub VALUES (7,5,'-83044882.038491');
INSERT INTO num_exp_mul VALUES (7,5,'-1361421264394.416135');
INSERT INTO num_exp_div VALUES (7,5,'-5063.62688881730941836574');
INSERT INTO num_exp_add VALUES (7,6,'-82934583.42236974');
INSERT INTO num_exp_sub VALUES (7,6,'-83122386.57763026');
INSERT INTO num_exp_mul VALUES (7,6,'-7796505729750.37795610');
INSERT INTO num_exp_div VALUES (7,6,'-884.20756174009028770294');
INSERT INTO num_exp_add VALUES (7,7,'-166056970');
INSERT INTO num_exp_sub VALUES (7,7,'0');
INSERT INTO num_exp_mul VALUES (7,7,'6893729321395225');
INSERT INTO num_exp_div VALUES (7,7,'1.00000000000000000000');
INSERT INTO num_exp_add VALUES (7,8,'-82953604');
INSERT INTO num_exp_sub VALUES (7,8,'-83103366');
INSERT INTO num_exp_mul VALUES (7,8,'-6217255985285');
INSERT INTO num_exp_div VALUES (7,8,'-1108.80577182462841041118');
INSERT INTO num_exp_add VALUES (7,9,'-107955289.045047420');
INSERT INTO num_exp_sub VALUES (7,9,'-58101680.954952580');
INSERT INTO num_exp_mul VALUES (7,9,'2069634775752159.035758700');
INSERT INTO num_exp_div VALUES (7,9,'3.33089171198810413382');
INSERT INTO num_exp_add VALUES (8,0,'74881');
INSERT INTO num_exp_sub VALUES (8,0,'74881');
INSERT INTO num_exp_mul VALUES (8,0,'0');
INSERT INTO num_exp_div VALUES (8,0,'NaN');
INSERT INTO num_exp_add VALUES (8,1,'74881');
INSERT INTO num_exp_sub VALUES (8,1,'74881');
INSERT INTO num_exp_mul VALUES (8,1,'0');
INSERT INTO num_exp_div VALUES (8,1,'NaN');
INSERT INTO num_exp_add VALUES (8,2,'-34263611.215397047');
INSERT INTO num_exp_sub VALUES (8,2,'34413373.215397047');
INSERT INTO num_exp_mul VALUES (8,2,'-2571300635581.146276407');
INSERT INTO num_exp_div VALUES (8,2,'-.00218067233500788615');
INSERT INTO num_exp_add VALUES (8,3,'74885.31');
INSERT INTO num_exp_sub VALUES (8,3,'74876.69');
INSERT INTO num_exp_mul VALUES (8,3,'322737.11');
INSERT INTO num_exp_div VALUES (8,3,'17373.78190255220417633410');
INSERT INTO num_exp_add VALUES (8,4,'7874342.4119');
INSERT INTO num_exp_sub VALUES (8,4,'-7724580.4119');
INSERT INTO num_exp_mul VALUES (8,4,'584031469984.4839');
INSERT INTO num_exp_div VALUES (8,4,'.00960079113741758956');
INSERT INTO num_exp_add VALUES (8,5,'91278.038491');
INSERT INTO num_exp_sub VALUES (8,5,'58483.961509');
INSERT INTO num_exp_mul VALUES (8,5,'1227826639.244571');
INSERT INTO num_exp_div VALUES (8,5,'4.56673929509287019456');
INSERT INTO num_exp_add VALUES (8,6,'168782.57763026');
INSERT INTO num_exp_sub VALUES (8,6,'-19020.57763026');
INSERT INTO num_exp_mul VALUES (8,6,'7031444034.53149906');
INSERT INTO num_exp_div VALUES (8,6,'.79744134113322314424');
INSERT INTO num_exp_add VALUES (8,7,'-82953604');
INSERT INTO num_exp_sub VALUES (8,7,'83103366');
INSERT INTO num_exp_mul VALUES (8,7,'-6217255985285');
INSERT INTO num_exp_div VALUES (8,7,'-.00090187120721280172');
INSERT INTO num_exp_add VALUES (8,8,'149762');
INSERT INTO num_exp_sub VALUES (8,8,'0');
INSERT INTO num_exp_mul VALUES (8,8,'5607164161');
INSERT INTO num_exp_div VALUES (8,8,'1.00000000000000000000');
INSERT INTO num_exp_add VALUES (8,9,'-24851923.045047420');
INSERT INTO num_exp_sub VALUES (8,9,'25001685.045047420');
INSERT INTO num_exp_mul VALUES (8,9,'-1866544013697.195857020');
INSERT INTO num_exp_div VALUES (8,9,'-.00300403532938582735');
INSERT INTO num_exp_add VALUES (9,0,'-24926804.045047420');
INSERT INTO num_exp_sub VALUES (9,0,'-24926804.045047420');
INSERT INTO num_exp_mul VALUES (9,0,'0');
INSERT INTO num_exp_div VALUES (9,0,'NaN');
INSERT INTO num_exp_add VALUES (9,1,'-24926804.045047420');
INSERT INTO num_exp_sub VALUES (9,1,'-24926804.045047420');
INSERT INTO num_exp_mul VALUES (9,1,'0');
INSERT INTO num_exp_div VALUES (9,1,'NaN');
INSERT INTO num_exp_add VALUES (9,2,'-59265296.260444467');
INSERT INTO num_exp_sub VALUES (9,2,'9411688.170349627');
INSERT INTO num_exp_mul VALUES (9,2,'855948866655588.453741509242968740');
INSERT INTO num_exp_div VALUES (9,2,'.72591434384152961526');
INSERT INTO num_exp_add VALUES (9,3,'-24926799.735047420');
INSERT INTO num_exp_sub VALUES (9,3,'-24926808.355047420');
INSERT INTO num_exp_mul VALUES (9,3,'-107434525.43415438020');
INSERT INTO num_exp_div VALUES (9,3,'-5783481.21694835730858468677');
INSERT INTO num_exp_add VALUES (9,4,'-17127342.633147420');
INSERT INTO num_exp_sub VALUES (9,4,'-32726265.456947420');
INSERT INTO num_exp_mul VALUES (9,4,'-194415646271340.1815956522980');
INSERT INTO num_exp_div VALUES (9,4,'-3.19596478892958416484');
INSERT INTO num_exp_add VALUES (9,5,'-24910407.006556420');
INSERT INTO num_exp_sub VALUES (9,5,'-24943201.083538420');
INSERT INTO num_exp_mul VALUES (9,5,'-408725765384.257043660243220');
INSERT INTO num_exp_div VALUES (9,5,'-1520.20159364322004505807');
INSERT INTO num_exp_add VALUES (9,6,'-24832902.467417160');
INSERT INTO num_exp_sub VALUES (9,6,'-25020705.622677680');
INSERT INTO num_exp_mul VALUES (9,6,'-2340666225110.29929521292692920');
INSERT INTO num_exp_div VALUES (9,6,'-265.45671195426965751280');
INSERT INTO num_exp_add VALUES (9,7,'-107955289.045047420');
INSERT INTO num_exp_sub VALUES (9,7,'58101680.954952580');
INSERT INTO num_exp_mul VALUES (9,7,'2069634775752159.035758700');
INSERT INTO num_exp_div VALUES (9,7,'.30021990699995814689');
INSERT INTO num_exp_add VALUES (9,8,'-24851923.045047420');
INSERT INTO num_exp_sub VALUES (9,8,'-25001685.045047420');
INSERT INTO num_exp_mul VALUES (9,8,'-1866544013697.195857020');
INSERT INTO num_exp_div VALUES (9,8,'-332.88556569820675471748');
INSERT INTO num_exp_add VALUES (9,9,'-49853608.090094840');
INSERT INTO num_exp_sub VALUES (9,9,'0');
INSERT INTO num_exp_mul VALUES (9,9,'621345559900192.420120630048656400');
INSERT INTO num_exp_div VALUES (9,9,'1.00000000000000000000');

INSERT INTO num_data VALUES (0, '0');
INSERT INTO num_data VALUES (1, '0');
INSERT INTO num_data VALUES (2, '-34338492.215397047');
INSERT INTO num_data VALUES (3, '4.31');
INSERT INTO num_data VALUES (4, '7799461.4119');
INSERT INTO num_data VALUES (5, '16397.038491');
INSERT INTO num_data VALUES (6, '93901.57763026');
INSERT INTO num_data VALUES (7, '-83028485');
INSERT INTO num_data VALUES (8, '74881');
INSERT INTO num_data VALUES (9, '-24926804.045047420');


DROP INDEX if exists num_exp_add_idx ON num_exp_add;
CREATE UNIQUE INDEX num_exp_add_idx ON num_exp_add (id1, id2);
DROP INDEX if exists num_exp_sub_idx ON num_exp_sub;
CREATE UNIQUE INDEX num_exp_sub_idx ON num_exp_sub (id1, id2);
DROP INDEX if exists num_exp_div_idx ON num_exp_div;
CREATE UNIQUE INDEX num_exp_div_idx ON num_exp_div (id1, id2);
DROP INDEX if exists num_exp_mul_idx ON num_exp_mul;
CREATE UNIQUE INDEX num_exp_mul_idx ON num_exp_mul (id1, id2);

DELETE FROM num_result;
INSERT INTO num_result SELECT t1.id, t2.id, t1.val + t2.val
    FROM num_data t1, num_data t2;
SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM num_result t1, num_exp_add t2 
    WHERE t1.id1 = t2.id1 AND t1.id2 = t2.id2 order by t1.id1, t1.id2;

DELETE FROM num_result;
INSERT INTO num_result SELECT t1.id, t2.id, t1.val - t2.val
    FROM num_data t1, num_data t2;
SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM num_result t1, num_exp_sub t2
    WHERE t1.id1 = t2.id1 
    AND t1.id2 = t2.id2 
    AND t1.result != t2.expected order by t1.id1, t1.id2;

-- ******************************
-- * Multiply check
-- ******************************
DELETE FROM num_result;
INSERT INTO num_result SELECT t1.id, t2.id, t1.val * t2.val
    FROM num_data t1, num_data t2;
SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM num_result t1, num_exp_mul t2
    WHERE t1.id1 = t2.id1 
    AND t1.id2 = t2.id2 
    AND t1.result != t2.expected order by t1.id1, t1.id2;

DELETE FROM num_result;
INSERT INTO num_result SELECT t1.id, t2.id, t1.val / t2.val
    FROM num_data t1, num_data t2
    WHERE t2.val != '0.0';
	
SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM num_result t1, num_exp_div t2
    WHERE t1.id1 = t2.id1 
    AND t1.id2 = t2.id2 
    AND t1.result != t2.expected order by t1.id1, t1.id2;


SELECT t1.id1, t1.id2, t1.result, t2.expected
    FROM num_result t1, num_exp_div t2
    WHERE t1.id1 = t2.id1 
    AND t1.id2 = t2.id2 
    order by t1.id1, t1.id2;	

drop table if exists expr_abc;
create table expr_abc(c int);
insert into expr_abc values(123.333::int);
select c::char    from expr_abc;
select c::char(2)    from expr_abc;
select c::char(3)    from expr_abc;
select c::char(5)    from expr_abc;
select c::varchar from expr_abc;
select c::decimal from expr_abc;
select c::decimal(3, -1) from expr_abc;
select c::bigint  from expr_abc;
select c::date    from expr_abc;
select c::blob    from expr_abc;
select c::real    from expr_abc;
select c::timestamp  from expr_abc;
insert into expr_abc values(100);
insert into expr_abc values(200);
SELECT 10 * c::numeric / 3::numeric FROM expr_abc;
SELECT max(10 * c::numeric / 3::numeric) FROM expr_abc WHERE c < 150;

select 0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001;
select 0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001;
select '0.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001'::double;

select 12.34-'123' from dual;
drop table if exists employees;
create table employees (
	employee_id integer,
	manager_id integer,
	first_name varchar2(10) not null,
	last_name varchar2(10) not null,
	title varchar2(20),
	salary number(10),
  	clobemp      CLOB,
  	intemp       NUMBER(10),
  	longemp      NUMBER(24),
  	numberemp    NUMBER(10,2),
  	blobemp      BLOB,
  	dateemp      DATE,
  	timestampemp TIMESTAMP(6),
	constraint employees_pk primary key (employee_id)
);
insert into employees(employee_id,first_name,last_name,title,intemp) values(1,'aaa','bbb','1234',1234);
insert into employees(employee_id,first_name,last_name,title,numberemp) values(2,'aaa','bbb','1234',12.34);
select intemp, title, intemp-title from employees where employee_id=1;
select numberemp, title, numberemp-title from employees where employee_id=2;

drop table if exists PFA_UNARY_TBL;
create table PFA_UNARY_TBL(xx int, yy bigint, dd double, de decimal, cc char(100));
insert into PFA_UNARY_TBL values(10, 10, 10, 10, '10');
insert into PFA_UNARY_TBL values(-2, -2, -2, -2, '-2');
select -xx, -yy, -dd, -de, -cc from PFA_UNARY_TBL order by xx;

select sum(xx), sum(yy), sum(dd), sum(de), sum(cc) from PFA_UNARY_TBL;
select -sum(xx), -sum(yy), -sum(dd), -sum(de), -sum(cc) from PFA_UNARY_TBL;

select case when 1 = 0 then null else 1.231 end from dual;
select case when 1 = 1 then null else 1.231 end from dual;
select case when 1 = 1 then null || null else 2.123 end from dual;
select case when 1 = 0 then null || null else 2.123 end from dual;
select case when 1 = 0 then null - null else 2.123 end from dual;
select case when 1 = 0 then null - systimestamp else 2.123 end from dual;
select case when 1 = 0 then systimestamp - null else 2.123 end from dual;
select case when 1 = 0 then sysdate - sysdate else 2.123 end from dual;

drop table if exists EMPLOYEES;
CREATE TABLE EMPLOYEES
(EMPLOYEE_ID NUMBER(6,0), 
 FIRST_NAME  VARCHAR2(20), 
 LAST_NAME   VARCHAR2(25) CONSTRAINT EMP_LAST_NAME_NN NOT NULL, 
 SALARY NUMBER(8,2)
);

insert into employees values(1,'li','lilei', 2000);
insert into employees values(2,'li','hanmm', 5000);
insert into employees values(3,'li','jack', 5000);
insert into employees values(4,'li','lusi', 1000);

SELECT AVG((CASE WHEN (e.salary > 2000) THEN (e.salary) ELSE (2000) END)) Average_Salary FROM employees e;
SELECT AVG((CASE WHEN (e.salary > 2000 AND e.salary < 6000) THEN (e.salary) ELSE (2000) END)) Average_Salary FROM employees e;
SELECT AVG((CASE WHEN (e.salary > 2000 or e.salary < 1000) THEN (e.salary) ELSE (2000) END)) Average_Salary FROM employees e;

SELECT AVG(CASE WHEN (e.salary > 4000) THEN (e.salary + 200)
WHEN (e.salary > 1999) THEN (e.salary + 100)
WHEN (e.salary > 999) THEN (e.salary + 50)
END) Average_Salary FROM employees e;

SELECT CASE WHEN (e.salary > 4000) THEN (e.salary) END as NULL_COLUMN FROM employees e;
drop table employees;

drop table if exists customer;
CREATE TABLE customer
(CUSTOMER_ID NUMBER(6,0), 
 CUST_FIRST_NAME  VARCHAR2(20) NOT NULL, 
 CUST_LAST_NAME   VARCHAR2(20) NOT NULL, 
 CREDIT_LIMIT INTEGER
);
insert into customer values (1, 'li', 'adjani', 100); 
insert into customer values (2, 'li', 'alexander', 2000);
insert into customer values (3, 'li', 'altman', 5000);

SELECT cust_last_name,
CASE (credit_limit) WHEN (100) THEN ('Low')
WHEN (5000) THEN ('High')
ELSE ('Medium') END AS credit
FROM customer
ORDER BY cust_last_name, credit;

insert into customer values (4, 'li', 'jack', 1990);
SELECT cust_last_name,
CASE (credit_limit) WHEN (100) THEN ('Low')
WHEN (5000) THEN ('High')
WHEN (2000) THEN ('Medium') END AS credit
FROM customer
ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case (CREDIT_LIMIT) when (100) then (110) else (case (CREDIT_LIMIT) when (1990) then (2000) when (2000) then (2010) else (5010) end) end ) as nest_case_result from customer ORDER BY CUSTOMER_ID;
select (CUSTOMER_ID + case when (CREDIT_LIMIT < 1000) then (110) else (case when (CREDIT_LIMIT < 2000) then (2000) when (CREDIT_LIMIT < 5000) then (2010) else  (5010) end) end ) as nest_case_result from customer ORDER BY CUSTOMER_ID;
select (CUSTOMER_ID + case when (CREDIT_LIMIT < 1000) then (110) else (case (CREDIT_LIMIT) when (1990) then (2000) when (2000) then (2010) else (5010) end) end ) as nest_case_result from customer ORDER BY CUSTOMER_ID;
select (CUSTOMER_ID + case (CREDIT_LIMIT) when (100) then (110) else (case when (CREDIT_LIMIT < 2000) then (2000) when (CREDIT_LIMIT < 5000) then (2010) else (5010) end) end ) as nest_case_result from customer ORDER BY CUSTOMER_ID;

select (CUSTOMER_ID + case credit THEN 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN WHEN 1990 then 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN THEN 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN WHEN 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 WHEN WHEN) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 WHEN ELSE) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 WHEN END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 ELSE WHEN) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 ELSE ELSE) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 ELSE END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 END ELSE) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 END WHEN) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case credit WHEN 1990 THEN 2000 END END) from customer ORDER BY cust_last_name, credit;

select (CUSTOMER_ID + case THEN 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN WHEN credit > 1990 then 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN THEN 2000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN WHEN credit > 4000 END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 WHEN WHEN) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 WHEN ELSE) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 WHEN END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 ELSE WHEN) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 ELSE ELSE) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 ELSE END) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 END ELSE) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 END WHEN) from customer ORDER BY cust_last_name, credit;
select (CUSTOMER_ID + case WHEN credit > 1990 THEN 2000 END END) from customer ORDER BY cust_last_name, credit;
drop table customer;

CREATE TABLE customer
(CUSTOMER_ID NUMBER(6,0), 
 CUST_FIRST_NAME  VARCHAR2(20) default case 1 when 1 then 'ABC' end , 
 CREDIT_LIMIT INTEGER
);
drop table customer;
-- the text for to_char
select to_char(to_timestamp('2014-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF'), 'YYYY-MM-DD"T"HH24:MI:SS') from dual;
select to_char(to_timestamp('2014-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF'), 'YYYY-MM-DD"T""T"HH24:MI:SS') from dual;
select to_char(to_timestamp('2014-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF'), 'YYYY-MM-DD"X123123123123123123123X"HH24:MI:SS') from dual;
select to_char(to_timestamp('2014-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF'), 'YYYY-MM-DD"-- I LOVE CHINA --"HH24:MI:SS') from dual;
select to_char(to_timestamp('2014-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF'), 'YYYY-MM-DD"select * from dual"HH24:MI:SS') from dual;
select to_char(to_timestamp('2018-06-07 x 11:40:30', 'YYYY-MM-DD"    x "HH24:MI:SS'), 'YYYY-MM-DD HH24:MI:SS.FF') from dual;
select to_char(to_timestamp('2018-06-07 x 11:40:30', 'YYYY-MM-DD"    x "HH24:MI:SS'), 'YYYY-MM-DD "   x " HH24:MI:SS.FF') from dual;

-- the format text for to_timestamp
select to_timestamp('""2014-04-04 04:04:04.040404', '""YYYY-MM-DD HH24:MI:SS.FF') from dual;
select to_timestamp('2014-04-04 04:04:04.040404', '""YYYY-MM-DD HH24:MI:SS.FF') from dual;
select to_timestamp('00002014-04-04 04:04:04.040404', '"0000"YYYY-MM-DD HH24:MI:SS.FF') from dual;
select to_timestamp('20182014-04-04 04:04:04.040404', '"2018"YYYY-MM-DD HH24:MI:SS.FF') from dual;
select to_timestamp('20182014-04-04 04:04:04.040404', 'YYYY"2014"-MM-DD HH24:MI:SS.FF') from dual;
select to_timestamp('YYYY2018-04-04 04:04:04.040404', '"YYYY"YYYY-MM-DD HH24:MI:SS.FF') from dual;
select to_timestamp('2018-06-0711:40:30', 'YYYY-MM-DD""HH24:MI:SS') from dual;
select to_timestamp('2018 - 06-0711:40:30', 'YYYY-MM-DD""HH24:MI:SS') from dual;
 
select 1 from dual where to_timestamp('YYYY2018-04-04 04:04:04.040404', '"YYYY"YYYY-MM-DD HH24:MI:SS.FF') = to_timestamp('2018-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF');
select 1 from dual where to_timestamp('mm2018-04-04 04:04:04.040404', '"MM"YYYY-MM-DD HH24:MI:SS.FF') = to_timestamp('2018-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF');
select 1 from dual where to_timestamp('mm2018-04-04 04:04:04.040404ff', '"MM"YYYY-MM-DD HH24:MI:SS.FF"FF"') = to_timestamp('2018-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF');

-- The space is allowed when parsing a datetime text
select to_timestamp('2018 - 06-0711:40:30', 'YYYY-MM-DDHH24:MI:SS') from dual;

select 1 from dual where to_timestamp('2014-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF') < current_timestamp(3 + 1);
select 1 from dual where to_timestamp('2014-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF') < current_timestamp();
select 1 from dual where to_timestamp('2000-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF') < current_timestamp(2);
select 1 from dual where to_timestamp('2000-04-04 04:04:04.040404', 'YYYY-MM-DD HH24:MI:SS.FF') < current_timestamp(6);

--DTS2018071200658
drop table if exists test_groupby;
create table test_groupby(a int, b int, c int);
insert into test_groupby values(1,2,3);
insert into test_groupby values(2,2,2);
insert into test_groupby values(2,2,2);
insert into test_groupby values(3,2,2);
select * from test_groupby;
select a,b,case when c > 0 then 1 else 0 end as d from test_groupby group by a,b,c order by 1,2,3;
drop table test_groupby;


create view ma5600tv8_PORT_DUMP_VIEW 
 as select 'Port' as Type, b.Name as NE_ID,CONCAT(b.Name,'-',SUBSTR(a.Name,1,instr(a.Name,'/') -1)) as SHELF_ID,a.ID2 as Slot,a.ID4 as Port_Name, c.Alias as Description, 
case((select count(*) 
      from ma5600tv8_pvc_SrvFlowTrafNameVw d
      where isDefaultName <>  1  and  (a.ID1 = d.DstResID1 and a.ID2 = d.DstResID2 and a.ID4 = d.DstResID3 and a.ID0 = d.DevID))) when 0 then 'DOWN' else 'UP' end as Status
from bms_gdm_ObjectTab a left join bms_res_ptp c on (a.ID0 = c.ID0 and a.ID1 = c.ID1 and a.ID2 = c.ID2 and a.ID3 = c.ID3 and a.ID4 = c.ID4),bms_gdm_DeviceTab b 
where a.ID0 = b.ID and a.MainType = 6 and b.Type = 41;

drop table if exists tbl_Qos_Behavior;
create table tbl_Qos_Behavior 
(
   id INT  DEFAULT  -1 not null,
   iDevID INT DEFAULT  -1 not null  ,
   strName VARCHAR(64)   DEFAULT  '--' not null,
   iDefType INT  DEFAULT  -1 not null,
   iPermitVal INT   DEFAULT  -1 not null,
   strActFilt VARCHAR(16)   DEFAULT  '--' not null,
   strCarCirVal VARCHAR(50)   DEFAULT  '--' not null,
   strCarPirVal VARCHAR(50) not null  DEFAULT  '--',
   strCarCbsVal VARCHAR(50) not null  DEFAULT  '--',
   strCarPbsVal VARCHAR(50) not null  DEFAULT  '--',
   iCarGreenAct INT not null  DEFAULT  -1,
   iGreenActClsVal INT not null  DEFAULT  -1,
   iGreenActClsColVal INT not null  DEFAULT  -1,
   iGreenActionRmkDscpVal INT not null  DEFAULT  -1,
   iGreenActionRmkMplsVal INT not null  DEFAULT  -1,
   iGreenActionRmkIpPrecVal INT not null  DEFAULT  -1,
   iCarYellowAct INT not null  DEFAULT  -1,
   iYellowActClsVal INT not null  DEFAULT  -1,
   iYellowActClsColVal INT not null  DEFAULT  -1,
   iYellowActionRmkDscpVal INT not null  DEFAULT  -1,
   iYellowActionRmkMplsVal INT not null  DEFAULT  -1,
   iYellowActionRmkIpPrecVal INT not null  DEFAULT  -1,
   iCarRedAct INT not null  DEFAULT  -1,
   iRedActClsVal INT not null  DEFAULT  -1,
   iRedActClsColVal INT not null  DEFAULT  -1,
   iRedActionRmkDscpVal INT not null  DEFAULT  -1,
   iRedActionRmkMplsVal INT not null  DEFAULT  -1,
   iRedActionRmkIpPrecVal INT not null  DEFAULT  -1,
   iCarSummary INT not null  DEFAULT  -1,
   iRmkIpPreVal INT not null  DEFAULT  -1,
   iRmk8021pVal INT not null  DEFAULT  -1,
   iRmkDscpVal INT not null  DEFAULT  -1,
   iRmkMplsExpVal INT not null  DEFAULT  -1,
   iRmkProtocol INT not null  DEFAULT  -1,
   iRmkLocalPrecedenceVal INT not null  DEFAULT  -1,
   strRmkDestMac VARCHAR(50) not null  DEFAULT  '--',
   strNhpIp VARCHAR(50) not null  DEFAULT  '--',
   strNhpIf VARCHAR(50) not null  DEFAULT  '--',
   iVlanID INT not null  DEFAULT  -1,
   strMultiNhpIp1 VARCHAR(50) not null  DEFAULT  '--',
   strMultiNhpIf1 VARCHAR(50) not null  DEFAULT  '--',
   strMultiNhpIp2 VARCHAR(50) not null  DEFAULT  '--',
   strMultiNhpIf2 VARCHAR(50) not null  DEFAULT  '--',
   strMultiNhpIp3 VARCHAR(50) not null  DEFAULT  '--',
   strMultiNhpIf3 VARCHAR(50) not null  DEFAULT  '--',
   strMultiNhpIp4 VARCHAR(50) not null  DEFAULT  '--',
   strMultiNhpIf4 VARCHAR(50) not null  DEFAULT  '--',
   strLspDesIp VARCHAR(50) not null  DEFAULT  '--',
   strLspNhpIp VARCHAR(50) not null  DEFAULT  '--',
   strLspIf VARCHAR(50) not null  DEFAULT  '--',
   iLspSecondary INT not null  DEFAULT  -1,
   strRdcSI VARCHAR(50) not null  DEFAULT  '--',
   iRdcCp INT not null  DEFAULT  -1,
   iUrpfType INT not null  DEFAULT  -1,
   iUrpfDefault INT not null  DEFAULT  -1,
   iObsportIndex INT not null  DEFAULT  -1,
   iPortMirrEnable INT not null  DEFAULT  -1,
   iServClsVal INT not null  DEFAULT  -1,
   iServClsColVal INT not null  DEFAULT  -1,
   iLoadBalance INT not null  DEFAULT  -1,
   iDenyPacLenType INT not null  DEFAULT  -1,
   iDenyPacLenVal INT not null  DEFAULT  -1,
   iDenyMaxPacLenval INT not null  DEFAULT  -1,
   iTrafficStatistic INT not null  DEFAULT  -1,
   iRandomDiscard INT not null  DEFAULT  -1,
   iTrafStaSummary INT not null  DEFAULT  -1,
   iDropPreHigh INT not null  DEFAULT  -1,
   iDpi INT not null  DEFAULT  -1,
   iHitCount INT not null  DEFAULT  -1,
   iMainType INT not null  DEFAULT  -1,
   iSubType INT not null  DEFAULT  -1,
   strCirThreshold VARCHAR(50) not null  DEFAULT  '--',
   strPirThreshold VARCHAR(50) not null  DEFAULT  '--',
   iCarShare INT not null  DEFAULT  -1,
   iAggregation INT not null  DEFAULT  -1,
   iGreenActionRmk8021pVal INT not null  DEFAULT  -1,
   iYellowActionRmk8021pVal INT not null  DEFAULT  -1,
   iRedActionRmk8021pVal INT not null  DEFAULT  -1,
   strVPNGroup VARCHAR(64) not null  DEFAULT  '--',
   strCir VARCHAR(128) not null  DEFAULT  '--',
   strPir VARCHAR(128) not null  DEFAULT  '--',
   strFlowQueue VARCHAR(128) not null  DEFAULT  '--',
   strFlowMapping VARCHAR(128) not null  DEFAULT  '--',
   strUserGroup VARCHAR(128) not null  DEFAULT  '--',
   strSvcTmp VARCHAR(128) not null  DEFAULT  '--',
   ProfileMD5 VARCHAR(64) not null  DEFAULT  '--',
   strRemoteMirrorIns VARCHAR(31) not null  DEFAULT  '--',
   strRemoteMirrorCir VARCHAR(10) not null  DEFAULT  '--',
   strVSIName VARCHAR(31) not null  DEFAULT  '--',
   iColorAware INT not null  DEFAULT  -1,
   strVRFName VARCHAR(31) not null  DEFAULT  '--' 
);
drop index if exists index_Qos_Behavior on tbl_Qos_Behavior;
create unique index index_Qos_Behavior 
on tbl_Qos_Behavior
(id, 
iDevID, 
strName);
drop table if exists tbl_R_Qos_Pf_BehaviorInfo;
create table tbl_R_Qos_Pf_BehaviorInfo 
(
   ProfileName VARCHAR(255) not null,
   ProfileAlias VARCHAR(100),
   LocalKey INT   AUTO_INCREMENT UNIQUE,
   ProfileType INT not null  DEFAULT  -1,
   iFirewall INT not null  DEFAULT  -1,
   ProfileMD5 VARCHAR(32) not null  DEFAULT  '--',
   CONSTRAINT PK_TBL_R_QOS_PF_BEHAVIORINFO PRIMARY KEY(ProfileName)   
);

drop view if exists tbl_R_Qos_Pf_BehaviorInfoNE;
 create view tbl_R_Qos_Pf_BehaviorInfoNE
(DevID, ProfileName, ProfileMD5, iSame)
as 
select LP.iDevID, LP.strName, LP.ProfileMD5,
case GP.ProfileMD5 when LP.ProfileMD5 then 1 else 2 end as iSame
from tbl_R_Qos_Pf_BehaviorInfo GP, (select iDevID, strName, ProfileMD5
   from tbl_Qos_Behavior)  LP
where GP.ProfileName = LP.strName; 

drop view if exists view_R_Qos_Pf_BehaviorInfo;
 create view view_R_Qos_Pf_BehaviorInfo
(ProfileName, ProfileAlias, LocalKey, ProfileType, iFirewall, ProfileMD5, iSame)
as
select GP.ProfileName, GP.ProfileAlias, GP.LocalKey, GP.ProfileType, GP.iFirewall, GP.ProfileMD5,
case when count(DISTINCT GP.ProfileMD5) > 1 then 2 
when count(DISTINCT GP.ProfileMD5) = 1 then case GP.ProfileMD5 when max(GP.ProfileMD5) then 1 else 2 end
when count(DISTINCT GP.ProfileMD5) = 0 then 1 end as iSame
from tbl_R_Qos_Pf_BehaviorInfo GP left join tbl_R_Qos_Pf_BehaviorInfoNE LP
on GP.ProfileName = LP.ProfileName
group by GP.ProfileName,GP.ProfileAlias,GP.LocalKey,GP.ProfileType,GP.iFirewall, 
GP.ProfileMD5; 

drop index index_Qos_Behavior on tbl_Qos_Behavior;
drop view  tbl_R_Qos_Pf_BehaviorInfoNE;
drop view  view_R_Qos_Pf_BehaviorInfo;
drop table tbl_Qos_Behavior;
drop table tbl_R_Qos_Pf_BehaviorInfo;

select convert((case(cast(1 as int) & 2) when 0 then 1 else 2 end) / 2, int);
select convert((case(cast(1 as int) & 1) when (cast(1 as int) & 1) then (case (1) when (1) then (1) else (0) end) else (cast (3 as int) & 3) end) / 2, int);

drop table if exists tTENE;
create table tTENE 
(
   PID INT,
   cAutoSync TINYINT ,
   cBuildTime INT,
   cCodeSet TINYINT ,
   cConfigState TINYINT ,
   cCreater VARCHAR(512),
   cEnableIntelligence TINYINT ,
   cID INT not null,
   cLastDBCHGSEQ DECIMAL(20,0),
   cLastSyncTime DECIMAL(20,0),
   cLocationName VARCHAR(512),
   cMemo VARCHAR(512),
   cNEFlags INT,
   cNEID DECIMAL(20,0),
   cNEMac VARCHAR(512),
   cNE_ATTRIB_TimeDivision INT,
   cName VARCHAR(512),
   cNamingRuleType INT,
   cOwner VARCHAR(512),
   cPatchVerList VARCHAR(512),
   cPfmMonEndTime15m INT,
   cPfmMonEndTime24h INT,
   cPfmMonNeverStop15m TINYINT ,
   cPfmMonNeverStop24h TINYINT ,
   cPfmMonStartTime15m INT,
   cPfmMonStartTime24h INT,
   cPfmMonitor15m TINYINT ,
   cPfmMonitor24h TINYINT ,
   cPhyID DECIMAL(20,0),
   cPreConfig TINYINT ,
   cRackType INT,
   cSCBMode TINYINT ,
   cShelfType INT,
   cSyncNumber DECIMAL(20,0),
   cSyncState DECIMAL(20,0),
   cType DECIMAL(10,0),
   cUserLabel VARCHAR(512),
   cVRCBVer VARCHAR(512),
   cVersion DECIMAL(20,0),
   PRIMARY KEY  
(cID)   
);
drop index if exists idx_TENE_DevID on tTENE;
create unique index idx_TENE_DevID 
on tTENE
(cNEID);
drop index if exists idx_TENE_PhyID on tTENE;
create index idx_TENE_PhyID 
on tTENE
(cPhyID);

SELECT 
cNEID, 
cType,
cShelfType,
CASE WHEN tTENE.cVRCBVer is NULL or tTENE.cVRCBVer = '/' or tTENE.cVRCBVer = '--' or (tTENE.cVRCBVer not like '%V%')
THEN(CONCAT(CONVERT(mod(tTENE.cVersion/(256*256*256),256),CHAR(3)),'.',CONVERT(mod(tTENE.cVersion/(256*256),256),CHAR(3)),'.',CONVERT(mod(tTENE.cVersion/256,256),CHAR(3)),'.',CONVERT(mod(cast(tTENE.cVersion as  INTEGER),256),CHAR(3))))
ELSE tTENE.cVRCBVer END AS strOsVersion FROM tTENE group by cType,cNEID,cShelfType,cVRCBVer,cVersion;


drop table if exists tTENASubrack;
create table tTENASubrack 
(
   Flag VARCHAR(512),
   PID INT,
   cID INT not null,
   cServiceType DECIMAL(20,0),
   cServiceTypeCount INT,
   cSubrackFIC VARCHAR(512),
   cSubrackID DECIMAL(10,0),
   cSubrackName VARCHAR(512),
   cSubrackType DECIMAL(20,0),
   cXCCapacity DECIMAL(20,0),
   cXCCapacityCount INT 
);
create index IndextTENASubrack 
on tTENASubrack
(PID);

SELECT
tTENE.cType,
  tTENE.cNEID,
  cast(tTENASubrack.cSubrackType as  INTEGER) AS cShelfType,
  CAST(CASE WHEN tTENE.cVRCBVer is NULL or tTENE.cVRCBVer = '/' or tTENE.cVRCBVer = '--' or (tTENE.cVRCBVer not like '%V%')
THEN(CONCAT(CAST(mod(cast(tTENE.cVersion/(256*256*256) as  INTEGER),256) AS CHAR(3)),'.',CAST(mod(cast(tTENE.cVersion/(256*256) as  INTEGER),256) AS CHAR(3)),'.',CAST(mod(cast(tTENE.cVersion/256 as  INTEGER),256) AS CHAR(3)),
   '.',CAST(mod(cast(tTENE.cVersion as  INTEGER),256) AS CHAR(3))))
ELSE tTENE.cVRCBVer END AS CHAR(128)) AS strOsVersion
FROM tTENASubrack,tTENE;

drop index idx_TENE_DevID on tTENE;
drop index idx_TENE_PhyID on tTENE;
drop table tTENE;
drop index IndextTENASubrack on tTENASubrack;
drop table tTENASubrack;

--begin:DTS2018072601365 
drop table if exists zsharding_tbl1;
create table zsharding_tbl1(c_id int, c_char char(55), c_varchar varchar(55));
insert into zsharding_tbl1 values(1,'Fluffy','Fluffy');
select C_ID,c_varchar from zsharding_tbl1 where regexp_like(c_varchar,'ffy****') order by 1;

drop table if exists zsharding_tbl12;
create table zsharding_tbl12(c_id int, c_clob clob, c_date date);
insert into zsharding_tbl12 values(1,'Fluffy',TO_DATE('2018-06-28 13:14:15', 'YYYY-MM-DD HH24:MI:SS'));
select regexp_substr(c_date,'18') from zsharding_tbl12 order by 1;
--end:DTS2018072601365 

-- regexp error code should not overwrite sql parser error.
drop table if exists nls_error_t;
create table nls_error_t(c1 int, c2 int);
select 
    c1, 
    REGEXP_COUNT(CAST('K(%`$!Qdnsr0Lzw;<Vv[:$GEbL8s60BcxiUjlXhP*7u:216??l' AS VARCHAR(100)), CAST('|f;/sc{g~HQg=fMO?VW;=?h,^$zhoLU+5XAi:1Z2U6It{CEA*L' AS VARCHAR(100))),
    c3
from nls_error_t;

create or replace function GetBigintFromHex (
    v_HexNum in varchar2  )
return number 
is
    v_IntNum number(19,0) ;
    v_Pos number(10, 0) ;
    v_j number(10, 0) ;
begin
    v_IntNum := 0;
    v_Pos := 0;
    v_j :=  length(v_HexNum) - 2;
    while v_Pos < v_j
    loop 
        begin
            v_IntNum := v_IntNum +  power(16, v_Pos) * (case ( ( ( right( substr(v_HexNum, 3, v_j - v_Pos), 1)) )) when '0' then 0 when '1' then 1 when '2' then 2 when '3' then 3 when '4' then 4 when '5' then 5 when '6' then 6 when '7' then 7 when '8' then 8 when '9' then 9 when 'a' then 10 when 'b' then 11 when 'c' then 12 when 'd' then 13 when 'e' then 14 when 'f' then 15 when 'A' then 10 when 'B' then 11 when 'C' then 12 when 'D' then 13 when 'E' then 14 when 'F' then 15 end);
            v_Pos := v_Pos + 1;
        end;
    end loop;

    return v_IntNum;
end;
/

select GetBigintFromHex('0xFF');
drop function GetBigintFromHex;