drop table if exists t_withas1;
drop table if exists t_withas2;

create table t_withas1(f_int1 int, f_int2 number(10,2), f_int3 int);
create table t_withas2(f_int1 int, f_int2 number(10,2), f_int3 int);
insert into t_withas1(f_int1, f_int2) values(1, 11);
insert into t_withas2(f_int1, f_int2) values(2, 22);

-- oracle not support, zenith support
insert into t_withas2(f_int1, f_int2) (with t_tmp1 as (select f_int1, f_int2 from t_withas1) select f_int1, f_int2 from t_tmp1);
insert into t_withas2(f_int1, f_int2) ( with t_tmp1 as (select f_int1, f_int2 from t_withas1) select f_int1, f_int2 from t_tmp1 );
(with t_tmp1 as (select * from t_withas1)select * from t_tmp1);
select f_int1, f_int2 from t_withas1 where f_int1=(((with t_tmp1 as (select * from t_withas1) select f_int1 from t_tmp1))) order by f_int1, f_int2;
select f_int1, f_int2 from t_withas2 where f_int1 in (with t_tmp1 as (select f_int1 from t_withas2) select f_int1 from t_tmp1) order by f_int1, f_int2;
insert into t_withas2 (with cr as (select * from t_withas2) select * from cr);
insert into t_withas2 (with cr as (select * from t_withas2) select * from cr union select * from cr);
select * from t_withas2 order by f_int1 desc;

CREATE TABLE "HOUSEHOLD_DEMOGRAPHICS"
(
"HD_DEMO_SK" BINARY_INTEGER NOT NULL,
"HD_INCOME_BAND_SK" BINARY_INTEGER,
"HD_BUY_POTENTIAL" CHAR(15 BYTE),
"HD_DEP_COUNT" BINARY_INTEGER,
"HD_VEHICLE_COUNT" BINARY_INTEGER
);
insert into household_demographics values (1,2,0,0,null);
insert into household_demographics values (1,2,0,null,0);
with tmp1 as (select hd_demo_sk, hd_income_band_sk, hd_dep_count, hd_vehicle_count from household_demographics order by 1,2,3,4) select hd_demo_sk, hd_income_band_sk, hd_dep_count from (select hd_demo_sk, hd_income_band_sk, hd_dep_count from tmp1 where (hd_demo_sk||hd_dep_count)= (select hd_demo_sk||hd_vehicle_count from tmp1 order by 1 limit 1));
DROP TABLE "HOUSEHOLD_DEMOGRAPHICS";

--DTS2019062511066: transform with as clause
drop table if exists store_returns;
create table store_returns
(
    sr_returned_date_sk       integer                       ,
    sr_return_time_sk         integer                       ,
    sr_item_sk                integer               not null,
    sr_customer_sk            integer                       ,
    sr_cdemo_sk               integer                       ,
    sr_hdemo_sk               integer                       ,
    sr_addr_sk                integer                       ,
    sr_store_sk               integer                       ,
    sr_reason_sk              integer                       ,
    sr_ticket_number          bigint               not null,
    sr_return_quantity        integer                       ,
    sr_return_amt             decimal(7,2)                  ,
    sr_return_tax             decimal(7,2)                  ,
    sr_return_amt_inc_tax     decimal(7,2)                  ,
    sr_fee                    decimal(7,2)                  ,
    sr_return_ship_cost       decimal(7,2)                  ,
    sr_refunded_cash          decimal(7,2)                  ,
    sr_reversed_charge        decimal(7,2)                  ,
    sr_store_credit           decimal(7,2)                  ,
    sr_net_loss               decimal(7,2)
 )
partition by range(sr_returned_date_sk)
(
        partition p1 values less than (2451179) ,
        partition p2 values less than (2451544) ,
        partition p3 values less than (2451910) ,
        partition p4 values less than (2452275) ,
        partition p5 values less than (2452640) ,
        partition p6 values less than (2453005) ,
        partition p7 values less than (maxvalue)
);
create index store_returns_index on store_returns(sr_item_sk, sr_ticket_number) local;

drop table if exists web_page;
create table web_page
(
    wp_web_page_sk            integer               not null,
    wp_web_page_id            char(16)              not null,
    wp_rec_start_date         date                          ,
    wp_rec_end_date           date                          ,
    wp_creation_date_sk       integer                       ,
    wp_access_date_sk         integer                       ,
    wp_autogen_flag           char(1)                       ,
    wp_customer_sk            integer                       ,
    wp_url                    varchar(100)                  ,
    wp_type                   char(50)                      ,
    wp_char_count             integer                       ,
    wp_link_count             integer                       ,
    wp_image_count            integer                       ,
    wp_max_ad_count           integer
 )
partition by range(wp_rec_start_date)
(
        partition p1 values less than('1990-01-01'),
        partition p2 values less than('1995-01-01'),
        partition p3 values less than('2000-01-01'),
        partition p4 values less than('2005-01-01'),
        partition p5 values less than('2010-01-01'),
        partition p6 values less than('2015-01-01'),
        partition p7 values less than(maxvalue)
);
create index web_page_index on web_page (wp_web_page_sk) local;

drop table if exists store;
create table store
(
    s_store_sk                integer               not null,
    s_store_id                char(16)              not null,
    s_rec_start_date          date                          ,
    s_rec_end_date            date                          ,
    s_closed_date_sk          integer                       ,
    s_store_name              varchar(50)                   ,
    s_number_employees        integer                       ,
    s_floor_space             integer                       ,
    s_hours                   char(20)                      ,
    s_manager                 varchar(40)                   ,
    s_market_id               integer                       ,
    s_geography_class         varchar(100)                  ,
    s_market_desc             varchar(100)                  ,
    s_market_manager          varchar(40)                   ,
    s_division_id             integer                       ,
    s_division_name           varchar(50)                   ,
    s_company_id              integer                       ,
    s_company_name            varchar(50)                   ,
    s_street_number           varchar(10)                   ,
    s_street_name             varchar(60)                   ,
    s_street_type             char(15)                      ,
    s_suite_number            char(10)                      ,
    s_city                    varchar(60)                   ,
    s_county                  varchar(30)                   ,
    s_state                   char(2)                       ,
    s_zip                     char(10)                      ,
    s_country                 varchar(20)                   ,
    s_gmt_offset              decimal(5,2)                  ,
    s_tax_precentage          decimal(5,2)
);
create index ds_store_index on store (s_store_sk);

drop table if exists web_site;
create table web_site
(
    web_site_sk               integer               not null,
    web_site_id               char(16)              not null,
    web_rec_start_date        date                          ,
    web_rec_end_date          date                          ,
    web_name                  varchar(50)                   ,
    web_open_date_sk          integer                       ,
    web_close_date_sk         integer                       ,
    web_class                 varchar(50)                   ,
    web_manager               varchar(40)                   ,
    web_mkt_id                integer                       ,
    web_mkt_class             varchar(50)                   ,
    web_mkt_desc              varchar(100)                  ,
    web_market_manager        varchar(40)                   ,
    web_company_id            integer                       ,
    web_company_name          char(50)                      ,
    web_street_number         char(10)                      ,
    web_street_name           varchar(60)                   ,
    web_street_type           char(15)                      ,
    web_suite_number          char(10)                      ,
    web_city                  varchar(60)                   ,
    web_county                varchar(30)                   ,
    web_state                 char(2)                       ,
    web_zip                   char(10)                      ,
    web_country               varchar(20)                   ,
    web_gmt_offset            decimal(5,2)                  ,
    web_tax_percentage        decimal(5,2)
 )
 partition by range(web_rec_start_date)
(
        partition p1 values less than('1990-01-01'),
        partition p2 values less than('1995-01-01'),
        partition p3 values less than('2000-01-01'),
        partition p4 values less than('2005-01-01'),
        partition p5 values less than('2010-01-01'),
        partition p6 values less than('2015-01-01'),
        partition p7 values less than(maxvalue)
);
create index web_site_index on web_site (web_site_sk) local;

drop table if exists customer;
create table customer
(
    c_customer_sk             integer               not null,
    c_customer_id             char(16)              not null,
    c_current_cdemo_sk        integer                       ,
    c_current_hdemo_sk        integer                       ,
    c_current_addr_sk         integer                       ,
    c_first_shipto_date_sk    integer                       ,
    c_first_sales_date_sk     integer                       ,
    c_salutation              char(10)                      ,
    c_first_name              char(20)                      ,
    c_last_name               char(30)                      ,
    c_preferred_cust_flag     char(1)                       ,
    c_birth_day               integer                       ,
    c_birth_month             integer                       ,
    c_birth_year              integer                       ,
    c_birth_country           varchar(20)                   ,
    c_login                   char(13)                      ,
    c_email_address           char(50)                      ,
    c_last_review_date        char(10)
);
create index customer_index on customer(c_customer_sk);

drop table store_returns;
drop table web_page;
drop table store;
drop table web_site;
drop table customer;

--DTS2019082710521
DROP TABLE if exists "DES_BASE_OBJENTITYREL_T" ;
DROP TABLE if exists "DES_SITE_PHYSICAL_REL_T" ;
DROP TABLE if exists "ESUR_DECO_JOB_SUBSIDIARY_T";
DROP TABLE if exists "ESUR_SURVEY_JOB_T";

CREATE TABLE "DES_BASE_OBJENTITYREL_T"
(
  "PHYSICAL_ID" NUMBER NOT NULL,
  "COUNTRY_CODE" VARCHAR(32 BYTE) NOT NULL,
  "PROVINCE_CODE" VARCHAR(32 BYTE),
  "OBJECT_CODE" VARCHAR(64 BYTE) NOT NULL,
  "PARENT_OBJECT_CODE" VARCHAR(32 BYTE),
  "PHYSICAL_SITE_NUMBER" VARCHAR(64 BYTE) NOT NULL,
  "PRIMARY_FIELD" VARCHAR(4000 BYTE) NOT NULL,
  "MODEL_ID" NUMBER,
  "DELETE_FLAG" CHAR(1 BYTE),
  "CREATED_BY" NUMBER,
  "CREATION_DATE" DATE,
  "LAST_UPDATED_BY" NUMBER,
  "LAST_UPDATE_DATE" DATE,
  "IS_SCATTERED" VARCHAR(1 BYTE),
  "ENTITY_STATUS" VARCHAR(10 BYTE),
  "IS_TEMP" VARCHAR(1 BYTE),
  "PROJECT_CODE" VARCHAR(40 BYTE),
  "SOURCE" VARCHAR(32 BYTE),
  "NODE_NUMBER" VARCHAR(32 BYTE),
  "IS_HISTORY" CHAR(1 BYTE),
  "IS_MODIFY" CHAR(1 BYTE),
  "IS_ORIGINAL_STATUS" NUMBER,
  "CONFIRM_RESULT" NUMBER,
  "CONFIRM_REMARK" VARCHAR(4000 BYTE),
  "OPERATOR_NAME" VARCHAR(500 BYTE),
  "IS_TO_DELETE" NUMBER,
  "IS_WSD" CHAR(1 BYTE),
  "ENTITY_ID" VARCHAR(64 BYTE),
  "PARENT_ENTITY_ID" VARCHAR(64 BYTE)
);
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322480211,'NC',null,'60002','50001','NSTP1J9XHA','Board',6689211,'0',999999999998949,'2019-08-02 10:28:11',999999999998949,'2019-08-13 14:19:17','0','1',null,'5555551S','eSurvey TSS','210010441981211','0','0',0,null,null,null,null,null,'70844766211','70844761211');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322482211,'NC',null,'70003','60002','NSTP1J9XHA','Board(Board)_Port001',null,'0',999999999998949,'2019-08-02 10:28:12',999999999998949,'2019-08-13 14:19:17','0','1',null,'5555551S','eSurvey TSS','210010441981211','0','0',0,null,null,null,null,null,'70844771211','70844766211');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322486211,'NC',null,'50001','-31415926','NSTP1J9XHA','BBU Subrack',2305000,'0',999999999998949,'2019-08-02 10:28:14',999999999998949,'2019-08-13 14:19:17','1','1',null,'5555551S','eSurvey TSS','210010441981211','0','0',0,null,null,null,null,null,'70844761211','-31415926');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322777211,'NC',null,'50001','-31415926','NSTP1J9XHA','BBU Subrack',2305000,'0',435259918449113,'2019-08-03 16:30:53',435259918449113,'2019-08-03 16:30:53','1','1',null,null,'eSurvey TSS','210010441981211','1','0',0,null,null,null,null,null,'70844761211','25142322776211');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322787211,'NC',null,'50001','-31415926','NSTP1J9XHA','BBU Subrack',2305000,'0',435259918449113,'2019-08-03 16:35:16',435259918449113,'2019-08-03 16:35:16','1','1',null,null,'eSurvey TSS','210010441981211','1','0',0,null,null,null,null,null,'70844761211','25142322786211');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322814211,'NC',null,'70006','30010','NSTP1JCP85','AAU(AAU001)_Port001',null,'0',999999999998949,'2019-08-03 16:39:55',999999999998949,'2019-08-05 14:06:52','0','2',null,'5555551S','eSurvey TSS','210010444264211','0','0',0,null,null,null,null,null,'80776744211','80776743211');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322819211,'NC',null,'70006','30010','NSTP1JCP85','AAU(AAU002)_Port001',null,'0',999999999998949,'2019-08-03 16:39:55',999999999998949,'2019-08-05 14:06:52','0','2',null,'5555551S','eSurvey TSS','210010444264211','0','0',0,null,null,null,null,null,'80776753211','80776752211');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322821211,'NC',null,'70006','30010','NSTP1JCP85','AAU(AAU)_Port001',null,'0',999999999998949,'2019-08-03 16:39:55',999999999998949,'2019-08-05 14:06:52','0','2',null,'5555551S','eSurvey TSS','210010444264211','0','0',0,null,null,null,null,null,'80776716211','80776711211');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322807211,'NC',null,'70003','60002','NSTP1JCP85','Board(Board)_Port2(RM71073308211)',71142211,'0',999999999998949,'2019-08-03 16:39:58',999999999998949,'2019-08-05 14:06:53','0','3',null,'5555551S','eSurvey TSS','210010444264211','0','0',0,null,null,null,null,null,'71073308211','71073304211');
INSERT INTO "DES_BASE_OBJENTITYREL_T" ("PHYSICAL_ID","COUNTRY_CODE","PROVINCE_CODE","OBJECT_CODE","PARENT_OBJECT_CODE","PHYSICAL_SITE_NUMBER","PRIMARY_FIELD","MODEL_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","IS_SCATTERED","ENTITY_STATUS","IS_TEMP","PROJECT_CODE","SOURCE","NODE_NUMBER","IS_HISTORY","IS_MODIFY","IS_ORIGINAL_STATUS","CONFIRM_RESULT","CONFIRM_REMARK","OPERATOR_NAME","IS_TO_DELETE","IS_WSD","ENTITY_ID","PARENT_ENTITY_ID") values
  (25142322822211,'NC',null,'70003','60002','NSTP1JCP85','Board(Board)_Port1(RM71073307211)',71141211,'0',999999999998949,'2019-08-03 16:39:58',999999999998949,'2019-08-05 14:06:53','0','3',null,'5555551S','eSurvey TSS','210010444264211','0','0',0,null,null,null,null,null,'71073307211','71073304211');

CREATE TABLE "DES_SITE_PHYSICAL_REL_T"
(
  "ID" NUMBER NOT NULL,
  "PROJECT_CODE" VARCHAR(200 BYTE) NOT NULL,
  "PHYSICAL_SITE_NUMBER" VARCHAR(12 BYTE) NOT NULL,
  "CUSTOMER_SITE_NUMBER" VARCHAR(12 BYTE) NOT NULL,
  "DELETE_FLAG" CHAR(1 BYTE) NOT NULL,
  "CREATED_BY" NUMBER,
  "CREATION_DATE" DATE NOT NULL,
  "LAST_UPDATED_BY" NUMBER,
  "LAST_UPDATE_DATE" DATE NOT NULL,
  "NODE_NUMBER" VARCHAR(32 BYTE)
);
INSERT INTO "DES_SITE_PHYSICAL_REL_T" ("ID","PROJECT_CODE","PHYSICAL_SITE_NUMBER","CUSTOMER_SITE_NUMBER","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","NODE_NUMBER") values
  (6761329211,'1807091S','NSTP09V34G','NSTC0EDKRX','0',0,'2019-01-07 19:45:26',0,'2019-01-19 19:18:46','210010055600211');
INSERT INTO "DES_SITE_PHYSICAL_REL_T" ("ID","PROJECT_CODE","PHYSICAL_SITE_NUMBER","CUSTOMER_SITE_NUMBER","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","NODE_NUMBER") values
  (6782182211,'1807091S','NSTP1JQE58','NSTC1HHP8G','0',0,'2019-07-30 17:26:37',0,'2019-07-30 17:26:37','210010742547211');
INSERT INTO "DES_SITE_PHYSICAL_REL_T" ("ID","PROJECT_CODE","PHYSICAL_SITE_NUMBER","CUSTOMER_SITE_NUMBER","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","NODE_NUMBER") values
  (6782354211,'1807091S','NSTP1JQE59','NSTC1HJ3FW','0',0,'2019-08-05 10:55:06',0,'2019-08-05 14:53:03','210010744305211');
INSERT INTO "DES_SITE_PHYSICAL_REL_T" ("ID","PROJECT_CODE","PHYSICAL_SITE_NUMBER","CUSTOMER_SITE_NUMBER","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","NODE_NUMBER") values
  (6782168211,'5590161','NSTP1JQLU1','NSTC1HHP83','0',0,'2019-07-30 10:22:06',0,'2019-07-30 10:22:25','210010742417211');
INSERT INTO "DES_SITE_PHYSICAL_REL_T" ("ID","PROJECT_CODE","PHYSICAL_SITE_NUMBER","CUSTOMER_SITE_NUMBER","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","NODE_NUMBER") values
  (6782282211,'5590161','NSTP1JQLU2','NSTC1HHP84','0',0,'2019-08-02 15:57:06',0,'2019-08-02 15:57:32','210010742416211');
INSERT INTO "DES_SITE_PHYSICAL_REL_T" ("ID","PROJECT_CODE","PHYSICAL_SITE_NUMBER","CUSTOMER_SITE_NUMBER","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","NODE_NUMBER") values
  (6782419211,'5590161','NSTP1JQLU3','NSTC1HHP85','0',0,'2019-08-05 17:34:38',0,'2019-08-05 17:34:38','210010742415211');
INSERT INTO "DES_SITE_PHYSICAL_REL_T" ("ID","PROJECT_CODE","PHYSICAL_SITE_NUMBER","CUSTOMER_SITE_NUMBER","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","NODE_NUMBER") values
  (6782173211,'5590161','NSTP1JQLU7','NSTC1HHP89','0',0,'2019-07-30 14:58:18',0,'2019-07-30 14:58:29','210010742526211');
INSERT INTO "DES_SITE_PHYSICAL_REL_T" ("ID","PROJECT_CODE","PHYSICAL_SITE_NUMBER","CUSTOMER_SITE_NUMBER","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","NODE_NUMBER") values
  (6782183211,'1807091S','NSTP1JQLUA','NSTC1HHP8H','0',0,'2019-07-30 17:26:41',0,'2019-07-30 17:26:41','210010742546211');


CREATE TABLE "ESUR_DECO_JOB_SUBSIDIARY_T"
(
  "ID" NUMBER NOT NULL,
  "PHYSICAL_SITE_NUMBER" VARCHAR(64 BYTE) NOT NULL,
  "CUSTOM_SITE_NUMBER" VARCHAR(64 BYTE) NOT NULL,
  "PROJECT_NUMBER" VARCHAR(200 BYTE),
  "ENTITY_ID" VARCHAR(64 BYTE),
  "ENTITY_STATUS" VARCHAR(10 BYTE),
  "WORK_TYPE" VARCHAR(2 BYTE),
  "NODE_NUMBER" VARCHAR(32 BYTE),
  "ATTRIBUTE_CODE" VARCHAR(64 BYTE),
  "SYS_SOURCE" VARCHAR(64 BYTE),
  "JOB_ID" NUMBER,
  "DELETE_FLAG" VARCHAR(1 BYTE) NOT NULL,
  "CREATED_BY" NUMBER NOT NULL,
  "CREATION_DATE" DATE NOT NULL,
  "LAST_UPDATED_BY" NUMBER NOT NULL,
  "LAST_UPDATE_DATE" DATE NOT NULL
);
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18002211,'NSTP0CDX9R','NSTC0CDV1C',null,'937307229211','1','0','NSTC0CDV1C','SDB00005287','2',1016932211,'0',715926521613826,'2019-08-01 16:04:31',715926521613826,'2019-08-01 16:04:31');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18003211,'NSTP0CDX9R','NSTC0CDV1C',null,'937307229211','1','0','NSTC0CDV1C','SDB00005287','2',1016933211,'0',715926521613826,'2019-08-01 16:05:27',715926521613826,'2019-08-01 16:05:27');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18004211,'NSTP0CDX9R','NSTC0CDV1C',null,'937307229211','1','0','NSTC0CDV1C','SDB00005287','2',1016934211,'0',715926521613826,'2019-08-01 16:16:09',715926521613826,'2019-08-01 16:16:09');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18005211,'NSTP0CDX9R','NSTC0CDV1C',null,'937307229211','1','0','NSTC0CDV1C','SDB00005287','2',1016935211,'0',715926521613826,'2019-08-01 16:16:30',715926521613826,'2019-08-01 16:16:30');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18006211,'NSTP09F303','NSTC09F15R',null,'937307980211','1','0','NSTC09F15R','SDB00005287','2',1016936211,'0',715926302421665,'2019-08-02 09:40:06',715926302421665,'2019-08-02 09:40:06');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18007211,'NSTP09F303','NSTC09F15R',null,'937307980211','1','0','NSTC09F15R','SDB00005287','2',1016937211,'0',715926302421665,'2019-08-02 09:40:44',715926302421665,'2019-08-02 09:40:44');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18008211,'NSTP101JU8','NSTC101M39',null,'937308387211','1','0','NSTC101M39','SDB00005287','2',1016938211,'0',715926521613826,'2019-08-02 18:27:12',715926521613826,'2019-08-02 18:27:12');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18009211,'NSTP0CWAD4','NSTC0CW1FR',null,'937311985211','1','0','NSTC0CW1FR','ITEM17303000','2',1016939211,'0',655783474775805,'2019-08-07 08:57:26',655783474775805,'2019-08-07 08:57:26');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18010211,'NSTP0CWAD4','NSTC0CW1FR',null,'937311985211','1','0','NSTC0CW1FR','ITEM17303000','2',1016940211,'0',655783474775805,'2019-08-07 08:58:42',655783474775805,'2019-08-07 08:58:42');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18011211,'NSTP0CWAD4','NSTC0CW1FR',null,'937311985211','1','0','NSTC0CW1FR','ITEM17303000','2',1016941211,'0',655783474775805,'2019-08-07 08:58:48',655783474775805,'2019-08-07 08:58:48');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18012211,'NSTP0CWAD4','NSTC0CW1FR',null,'937311985211','1','0','NSTC0CW1FR','ITEM17303000','2',1016942211,'0',655783474775805,'2019-08-07 08:59:01',655783474775805,'2019-08-07 08:59:01');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18013211,'NSTP0CWAD4','NSTC0CW1FR',null,'937311985211','1','0','NSTC0CW1FR','ITEM17303000','2',1016943211,'0',655783474775805,'2019-08-07 09:02:55',655783474775805,'2019-08-07 09:02:55');
INSERT INTO "ESUR_DECO_JOB_SUBSIDIARY_T" ("ID","PHYSICAL_SITE_NUMBER","CUSTOM_SITE_NUMBER","PROJECT_NUMBER","ENTITY_ID","ENTITY_STATUS","WORK_TYPE","NODE_NUMBER","ATTRIBUTE_CODE","SYS_SOURCE","JOB_ID","DELETE_FLAG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE") values
  (18014211,'NSTP0CWAD4','NSTC0CW1FR',null,'937311965211','1','0','NSTC0CW1FR','ITEM17303000','2',1016944211,'0',655783474775805,'2019-08-07 10:17:47',655783474775805,'2019-08-07 10:17:47');


CREATE TABLE "ESUR_SURVEY_JOB_T"
(
  "ID" NUMBER NOT NULL,
  "JOB_ID" NUMBER NOT NULL,
  "JOB_TYPE" VARCHAR(64 BYTE),
  "JOB_PARA" CLOB,
  "JOB_STATE" NUMBER,
  "START_DATE" DATE,
  "FINISH_DATE" DATE,
  "RESULT_MSG" VARCHAR(1024 BYTE),
  "CREATED_BY" NUMBER NOT NULL,
  "CREATION_DATE" DATE NOT NULL,
  "LAST_UPDATED_BY" NUMBER NOT NULL ,
  "LAST_UPDATE_DATE" DATE NOT NULL,
  "DOCKING_SYS_ID" VARCHAR(1024 BYTE)
);
INSERT INTO "ESUR_SURVEY_JOB_T" ("ID","JOB_ID","JOB_TYPE","JOB_PARA","JOB_STATE","START_DATE","FINISH_DATE","RESULT_MSG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","DOCKING_SYS_ID") values
  (1016932211,1016932211,'ConvertPanorama','<?xml version="1.0" encoding="UTF-8"?>
<root>
    <para>
        <customSiteId>LOPAL</customSiteId>
        <physicSiteNumber>NSTP0CDX9R</physicSiteNumber>
        <isScattered>0</isScattered>
        <attrCode>SDB00005287</attrCode>
        <customSiteNumber>NSTC0CDV1C</customSiteNumber>
        <entityStatus>1</entityStatus>
        <nodeNumber>NSTC0CDV1C</nodeNumber>
        <workType>0</workType>
        <entityId>937307229211</entityId>
        <pickerSysType>2</pickerSysType>
    </para>
    <extr></extr>
</root>',3,null,null,'fail;0022',715926521613826,'2019-08-01 16:04:30',-1,'2019-08-01 16:04:34',null);
INSERT INTO "ESUR_SURVEY_JOB_T" ("ID","JOB_ID","JOB_TYPE","JOB_PARA","JOB_STATE","START_DATE","FINISH_DATE","RESULT_MSG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","DOCKING_SYS_ID") values
  (1016933211,1016933211,'ConvertPanorama','<?xml version="1.0" encoding="UTF-8"?>
<root>
    <para>
        <customSiteId>LOPAL</customSiteId>
        <physicSiteNumber>NSTP0CDX9R</physicSiteNumber>
        <isScattered>0</isScattered>
        <attrCode>SDB00005287</attrCode>
        <customSiteNumber>NSTC0CDV1C</customSiteNumber>
        <entityStatus>1</entityStatus>
        <nodeNumber>NSTC0CDV1C</nodeNumber>
        <workType>0</workType>
        <entityId>937307229211</entityId>
        <pickerSysType>2</pickerSysType>
    </para>
    <extr></extr>
</root>',3,null,null,'fail;0022',715926521613826,'2019-08-01 16:05:27',-1,'2019-08-01 16:05:30',null);
INSERT INTO "ESUR_SURVEY_JOB_T" ("ID","JOB_ID","JOB_TYPE","JOB_PARA","JOB_STATE","START_DATE","FINISH_DATE","RESULT_MSG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","DOCKING_SYS_ID") values
  (1016934211,1016934211,'ConvertPanorama','<?xml version="1.0" encoding="UTF-8"?>
<root>
    <para>
        <customSiteId>LOPAL</customSiteId>
        <physicSiteNumber>NSTP0CDX9R</physicSiteNumber>
        <isScattered>0</isScattered>
        <attrCode>SDB00005287</attrCode>
        <customSiteNumber>NSTC0CDV1C</customSiteNumber>
        <entityStatus>1</entityStatus>
        <nodeNumber>NSTC0CDV1C</nodeNumber>
        <workType>0</workType>
        <entityId>937307229211</entityId>
        <pickerSysType>2</pickerSysType>
    </para>
    <extr></extr>
</root>',3,null,null,'fail;0022',715926521613826,'2019-08-01 16:16:09',-1,'2019-08-01 16:16:12',null);
INSERT INTO "ESUR_SURVEY_JOB_T" ("ID","JOB_ID","JOB_TYPE","JOB_PARA","JOB_STATE","START_DATE","FINISH_DATE","RESULT_MSG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","DOCKING_SYS_ID") values
  (1016935211,1016935211,'ConvertPanorama','<?xml version="1.0" encoding="UTF-8"?>
<root>
    <para>
        <customSiteId>LOPAL</customSiteId>
        <physicSiteNumber>NSTP0CDX9R</physicSiteNumber>
        <isScattered>0</isScattered>
        <attrCode>SDB00005287</attrCode>
        <customSiteNumber>NSTC0CDV1C</customSiteNumber>
        <entityStatus>1</entityStatus>
        <nodeNumber>NSTC0CDV1C</nodeNumber>
        <workType>0</workType>
        <entityId>937307229211</entityId>
        <pickerSysType>2</pickerSysType>
    </para>
    <extr></extr>
</root>',3,null,null,'fail;0022',715926521613826,'2019-08-01 16:16:30',-1,'2019-08-01 16:16:33',null);
INSERT INTO "ESUR_SURVEY_JOB_T" ("ID","JOB_ID","JOB_TYPE","JOB_PARA","JOB_STATE","START_DATE","FINISH_DATE","RESULT_MSG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","DOCKING_SYS_ID") values
  (1016936211,1016936211,'ConvertPanorama','<?xml version="1.0" encoding="UTF-8"?>
<root>
    <para>
        <customSiteId>TI0062</customSiteId>
        <physicSiteNumber>NSTP09F303</physicSiteNumber>
        <isScattered>0</isScattered>
        <attrCode>SDB00005287</attrCode>
        <customSiteNumber>NSTC09F15R</customSiteNumber>
        <entityStatus>1</entityStatus>
        <nodeNumber>NSTC09F15R</nodeNumber>
        <workType>0</workType>
        <entityId>937307980211</entityId>
        <pickerSysType>2</pickerSysType>
    </para>
    <extr></extr>
</root>',3,null,null,'fail;0022',715926302421665,'2019-08-02 09:40:06',-1,'2019-08-02 09:40:09',null);
INSERT INTO "ESUR_SURVEY_JOB_T" ("ID","JOB_ID","JOB_TYPE","JOB_PARA","JOB_STATE","START_DATE","FINISH_DATE","RESULT_MSG","CREATED_BY","CREATION_DATE","LAST_UPDATED_BY","LAST_UPDATE_DATE","DOCKING_SYS_ID") values
  (1016937211,1016937211,'ConvertPanorama','<?xml version="1.0" encoding="UTF-8"?>
<root>
    <para>
        <customSiteId>TI0062</customSiteId>
        <physicSiteNumber>NSTP09F303</physicSiteNumber>
        <isScattered>0</isScattered>
        <attrCode>SDB00005287</attrCode>
        <customSiteNumber>NSTC09F15R</customSiteNumber>
        <entityStatus>1</entityStatus>
        <nodeNumber>NSTC09F15R</nodeNumber>
        <workType>0</workType>
        <entityId>937307980211</entityId>
        <pickerSysType>2</pickerSysType>
    </para>
    <extr></extr>
</root>',3,null,null,'fail;0022',715926302421665,'2019-08-02 09:40:44',-1,'2019-08-02 09:40:47',null);

DROP TABLE "DES_BASE_OBJENTITYREL_T" ;
DROP TABLE "DES_SITE_PHYSICAL_REL_T" ;
DROP TABLE "ESUR_DECO_JOB_SUBSIDIARY_T";
DROP TABLE "ESUR_SURVEY_JOB_T";

drop table if exists t_dql_base_001;
create table t_dql_base_001(id int not null,c_int int,c_vchar varchar(20) not null,c_clob clob not null,c_blob blob not null,c_date date,constraint t_dql_base_001_con primary key(c_vchar));
insert into t_dql_base_001 values(1,100,'abc123',lpad('123abc',50,'abc'),lpad('11100011',50,'1100'),to_timestamp(to_char('1800-01-01 10:51:47'),'yyyy-mm-dd hh24:mi:ss'));
select distinct count((with tmpt as (select id from t_dql_base_001) select * from tmpt where t1.id=id)) over(partition by (with tmpt as (select id from t_dql_base_001) select * from tmpt where t1.id=id)) c from t_dql_base_001 t1;
select distinct count((with tmpt as (select id from t_dql_base_001) select * from tmpt where t1.id=id)) over(partition by (with tmpt as (select id from tmpt) select * from tmpt where t1.id=id)) c from t_dql_base_001 t1;


-- DTS20201226076I4MP1G00
drop table if exists withas_free_page_t;
create table withas_free_page_t(id number(8), c_str varchar(5));
insert into withas_free_page_t values(1, 'M');
insert into withas_free_page_t values(2, 'M');
insert into withas_free_page_t values(3, 'F');
insert into withas_free_page_t values(4, 'F');
commit;

with jennifer_1 as (
    select 
        ref_0.id as c0, 
        ref_0.c_str as c1
    from withas_free_page_t as ref_0
)

select
    corr(0,2.0) as c0,
    ref_1.c0 as c1
from
    (jennifer_1 as ref_1) right outer join 
    (jennifer_1 as ref_2)
    on (regexp_like(ref_1.c1,'.*'))
group by
    cube(
        ref_2.c0, ref_2.c0, cast('2020-12-21 20:55:54' as timestamp with local time zone), ref_1.c1,
        cast('c288ef3a9deaeca4' as binary(100)), ref_2.c0, ref_2.c0, null, false, null, cast('688015 0:44:6' as interval day to second(6))
    ),
    ref_2.c0, ref_1.c0, ref_1.c1;

drop table withas_free_page_t;

--DTS2020042010859
drop table if exists FILECURRENT_0422;
drop table if exists FILEATTRIBUTE_0422;
drop table if exists sharp_0422;
CREATE TABLE FILECURRENT_0422 (
	ID BINARY_INTEGER NOT NULL,
	SN BINARY_INTEGER,
	OID VARCHAR(50),
	NAME VARCHAR(100),
	PATH VARCHAR(200),
	TYPE BINARY_INTEGER,
	STATUS BINARY_INTEGER,
	FLAG BINARY_INTEGER,
	CREATEUSER VARCHAR(20),
	CREATETIME VARCHAR(20),
	UPDATEUSER VARCHAR(20),
	UPDATETIME VARCHAR(20),
	REMARK VARCHAR(100),
	CID BINARY_INTEGER,
	CREATETYPE BINARY_INTEGER,
	OPSTATUS BINARY_INTEGER,
	FROMFILEID BINARY_INTEGER,
	FILESOURCE BINARY_INTEGER,
	TDCNAME VARCHAR(1000),
	CONSTRAINT PK_FILECURRENT_DTS2020042010859 PRIMARY KEY (ID)
);
CREATE TABLE FILEATTRIBUTE_0422 (
	ID BINARY_INTEGER NOT NULL,
	FTYPE BINARY_INTEGER,
	FID BINARY_INTEGER,
	FSN BINARY_INTEGER,
	ATYPE BINARY_INTEGER,
	AID VARCHAR(20),
	CONSTRAINT PK_FILEATTRIBUTE_DTS2020042010859 PRIMARY KEY (ID)
);
CREATE TABLE sharp_0422 (
	ID BINARY_INTEGER NOT NULL,
	NAME VARCHAR(100),
	CREATEUSER VARCHAR(20),
	CREATETIME VARCHAR(20),
	UPDATEUSER VARCHAR(20),
	UPDATETIME VARCHAR(20),
	VERNAME VARCHAR(100),
	REMARK VARCHAR(500),
	STATUS BINARY_INTEGER,
	SHARPBASICID BINARY_INTEGER,
	ALIASNAME VARCHAR(200),
	CONSTRAINT PK_SHARP_DTS2020042010859 PRIMARY KEY (ID)
);
CREATE OR REPLACE FUNCTION newsort_DTS2020042010859
(
   name in varchar2
)
RETURN VARCHAR2
as
results varchar2(8000 char);
colum_name_v1 varchar2(8000 char);
colum_name_v2 varchar2(8000 char);
begin
	if instr(name,'_')>0 and instr(name,'-')=0 then
	colum_name_v2:=replace(name,'_','|');
	
	elsif instr(name,'-')>0 and instr(name,'_')=0 then
	colum_name_v2:=replace(name,'-','|');
	
	elsif instr(name,'-')>0 and instr(name,'_')=0 then
	colum_name_v1:=replace(name,'-','|');
	colum_name_v2:=replace(colum_name_v1,'_','|');
	
	else colum_name_v2:=name;
	end if;
	
	results:=colum_name_v2;
	return results;
end;
/

WITH ret AS(SELECT a.id , c.name AS sharpName FROM FILECURRENT_0422 a  INNER JOIN FILEATTRIBUTE_0422 b ON a.id = b.fid  AND a.sn = b.fsn AND b.ftype = 1 AND b.atype = 6 INNER JOIN sharp_0422 c ON isnumeric(b.aid) and b.aid = c.id and c.status <> 9 INNER JOIN ( 
SELECT 4158772 AS fileid  from dual UNION SELECT 4158774 from dual UNION SELECT 4158776 from dual UNION SELECT 4158778 from dual UNION SELECT 4158780 from dual UNION SELECT 4158782 from dual UNION SELECT 4158784 from dual UNION SELECT 4158784 from dual 
UNION SELECT 4158786 from dual UNION SELECT 4158788 from dual UNION SELECT 4158790 from dual UNION SELECT 4158792 from dual UNION SELECT 4158792 from dual UNION SELECT 4158794 from dual UNION SELECT 4158796 from dual UNION SELECT 4158798 from dual 
UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158800 from dual UNION SELECT 4158802 from dual UNION SELECT 4158804 from dual UNION SELECT 4158807 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158811 from dual UNION SELECT 4158813 from dual UNION SELECT 4158813 from dual UNION SELECT 4158815 from dual UNION SELECT 4158815 from dual 
UNION SELECT 4158817 from dual UNION SELECT 4158819 from dual UNION SELECT 4158821 from dual UNION SELECT 4158822 from dual UNION SELECT 4158823 from dual UNION SELECT 4158824 from dual UNION SELECT 4158825 from dual UNION SELECT 4158826 from dual 
UNION SELECT 4158827 from dual UNION SELECT 4158828 from dual UNION SELECT 4158829 from dual UNION SELECT 4158830 from dual UNION SELECT 4158831 from dual UNION SELECT 4158832 from dual UNION SELECT 4158833 from dual UNION SELECT 4158834 from dual 
UNION SELECT 4158835 from dual UNION SELECT 4158836 from dual UNION SELECT 4158837 from dual UNION SELECT 4158838 from dual UNION SELECT 4158839 from dual UNION SELECT 4158840 from dual UNION SELECT 4158841 from dual UNION SELECT 4158842 from dual 
UNION SELECT 4158843 from dual UNION SELECT 4158844 from dual UNION SELECT 4158845 from dual UNION SELECT 4158847 from dual UNION SELECT 4158848 from dual UNION SELECT 4158850 from dual UNION SELECT 4158851 from dual UNION SELECT 4158852 from dual 
UNION SELECT 4158853 from dual UNION SELECT 4158854 from dual UNION SELECT 4158855 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158857 from dual 
UNION SELECT 4158858 from dual UNION SELECT 4158859 from dual UNION SELECT 4158860 from dual UNION SELECT 4158861 from dual UNION SELECT 4158862 from dual UNION SELECT 4158863 from dual UNION SELECT 4158864 from dual UNION SELECT 4158865 from dual 
uNION SELECT 4158866 from dual UNION SELECT 4158867 from dual UNION SELECT 4158868 from dual UNION SELECT 4158869 from dual UNION SELECT 4158870 from dual UNION SELECT 4158871 from dual UNION SELECT 4158872 from dual UNION SELECT 4158873 from dual 
UNION SELECT 4158874 from dual UNION SELECT 4158875 from dual UNION SELECT 4158876 from dual UNION SELECT 4158877 from dual UNION SELECT 4158878 from dual UNION SELECT 4158879 from dual UNION SELECT 4158880 from dual UNION SELECT 4158881 from dual 
UNION SELECT 4158882 from dual UNION SELECT 4158883 from dual UNION SELECT 4158884 from dual UNION SELECT 4158885 from dual UNION SELECT 4158886 from dual UNION SELECT 4158887 from dual UNION SELECT 4158888 from dual UNION SELECT 4158889 from dual 
UNION SELECT 4158890 from dual UNION SELECT 4158891 from dual UNION SELECT 4158892 from dual UNION SELECT 4158893 from dual UNION SELECT 4158894 from dual UNION SELECT 4158895 from dual UNION SELECT 4158896 from dual UNION SELECT 4158897 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158997 from dual UNION SELECT 4158998 from dual UNION SELECT 4158999 from dual UNION SELECT 4159000 from dual 
UNION SELECT 4159001 from dual UNION SELECT 4159002 from dual UNION SELECT 4159003 from dual UNION SELECT 4159004 from dual UNION SELECT 4159005 from dual UNION SELECT 4159006 from dual UNION SELECT 4159007 from dual UNION SELECT 4159008 from dual 
UNION SELECT 4159009 from dual UNION SELECT 4159010 from dual UNION SELECT 4159012 from dual UNION SELECT 4159013 from dual UNION SELECT 4159013 from dual UNION SELECT 4159013 from dual UNION SELECT 4159014 from dual UNION SELECT 4159015 from dual 
UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual 
UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159017 from dual UNION SELECT 4159018 from dual UNION SELECT 4159019 from dual UNION SELECT 4159020 from dual UNION SELECT 4159021 from dual UNION SELECT 4159022 from dual 
UNION SELECT 4159023 from dual UNION SELECT 4159024 from dual UNION SELECT 4159025 from dual UNION SELECT 4159026 from dual UNION SELECT 4159027 from dual UNION SELECT 4159028 from dual UNION SELECT 4159029 from dual UNION SELECT 4159030 from dual 
UNION SELECT 4159031 from dual UNION SELECT 4159032 from dual UNION SELECT 4159033 from dual UNION SELECT 4159034 from dual UNION SELECT 4159035 from dual UNION SELECT 4159036 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual 
UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual 
UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159039 from dual UNION SELECT 4159039 from dual UNION SELECT 4159040 from dual 
UNION SELECT 4159041 from dual UNION SELECT 4159042 from dual UNION SELECT 4159043 from dual UNION SELECT 4159044 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual 
UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual 
UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual 
UNION SELECT 4159046 from dual UNION SELECT 4159047 from dual UNION SELECT 4159048 from dual UNION SELECT 4159049 from dual UNION SELECT 4159050 from dual UNION SELECT 4159051 from dual UNION SELECT 4159052 from dual UNION SELECT 4159053 from dual 
UNION SELECT 4159054 from dual UNION SELECT 4159055 from dual UNION SELECT 4159056 from dual UNION SELECT 4159057 from dual UNION SELECT 4159058 from dual UNION SELECT 4159059 from dual UNION SELECT 4159060 from dual UNION SELECT 4159061 from dual 
UNION SELECT 4159062 from dual UNION SELECT 4159063 from dual UNION SELECT 4159064 from dual UNION SELECT 4159065 from dual UNION SELECT 4159066 from dual UNION SELECT 4159067 from dual UNION SELECT 4159068 from dual UNION SELECT 4159069 from dual 
UNION SELECT 4159070 from dual UNION SELECT 4159071 from dual UNION SELECT 4159072 from dual UNION SELECT 4159073 from dual UNION SELECT 4159074 from dual UNION SELECT 4159074 from dual UNION SELECT 4159075 from dual UNION SELECT 4159076 from dual 
UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual 
UNION SELECT 4159076 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual 
UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual 
UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159078 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual 
UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual 
UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159080 from dual UNION SELECT 4159081 from dual UNION SELECT 4159082 from dual 
UNION SELECT 4159083 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159085 from dual UNION SELECT 4159086 from dual UNION SELECT 4159087 from dual 
UNION SELECT 4159088 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159090 from dual UNION SELECT 4159091 from dual UNION SELECT 4159092 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159094 from dual UNION SELECT 4159095 from dual UNION SELECT 4159096 from dual UNION SELECT 4159097 from dual 
UNION SELECT 4159098 from dual UNION SELECT 4159099 from dual UNION SELECT 4159100 from dual UNION SELECT 4159101 from dual UNION SELECT 4159102 from dual UNION SELECT 4159103 from dual UNION SELECT 4159104 from dual UNION SELECT 4159105 from dual 
UNION SELECT 4159106 from dual UNION SELECT 4159107 from dual UNION SELECT 4159108 from dual UNION SELECT 4159109 from dual UNION SELECT 4159110 from dual UNION SELECT 4159111 from dual UNION SELECT 4159112 from dual UNION SELECT 4159112 from dual 
UNION SELECT 4159113 from dual UNION SELECT 4159114 from dual UNION SELECT 4159115 from dual UNION SELECT 4159116 from dual UNION SELECT 4159117 from dual UNION SELECT 4159118 from dual UNION SELECT 4159119 from dual UNION SELECT 4159120 from dual 
UNION SELECT 4159121 from dual UNION SELECT 4159122 from dual UNION SELECT 4159123 from dual UNION SELECT 4159124 from dual UNION SELECT 4159125 from dual UNION SELECT 4159126 from dual UNION SELECT 4159127 from dual UNION SELECT 4159127 from dual 
UNION SELECT 4159128 from dual UNION SELECT 4159129 from dual UNION SELECT 4159130 from dual UNION SELECT 4159131 from dual UNION SELECT 4159132 from dual UNION SELECT 4159133 from dual UNION SELECT 4159134 from dual UNION SELECT 4159135 from dual 
UNION SELECT 4159136 from dual UNION SELECT 4159137 from dual UNION SELECT 4159138 from dual UNION SELECT 4159139 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual 
UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual 
UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159141 from dual UNION SELECT 4159142 from dual UNION SELECT 4159143 from dual UNION SELECT 4159144 from dual UNION SELECT 4159145 from dual UNION SELECT 4159146 from dual 
UNION SELECT 4159147 from dual UNION SELECT 4159148 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual 
UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual 
UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159150 from dual 
UNION SELECT 4159151 from dual UNION SELECT 4159152 from dual UNION SELECT 4159153 from dual UNION SELECT 4159154 from dual UNION SELECT 4159155 from dual UNION SELECT 4159155 from dual UNION SELECT 4159156 from dual UNION SELECT 4159157 from dual 
UNION SELECT 4159158 from dual UNION SELECT 4159159 from dual UNION SELECT 4159160 from dual UNION SELECT 4159161 from dual UNION SELECT 4159162 from dual UNION SELECT 4159163 from dual UNION SELECT 4159164 from dual UNION SELECT 4159165 from dual 
UNION SELECT 4159166 from dual UNION SELECT 4159167 from dual UNION SELECT 4159167 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual 
UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159169 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159278 from dual UNION SELECT 4159279 from dual UNION SELECT 4159280 from dual UNION SELECT 4159281 from dual UNION SELECT 4159282 from dual 
UNION SELECT 4159283 from dual UNION SELECT 4159284 from dual UNION SELECT 4159285 from dual UNION SELECT 4159286 from dual UNION SELECT 4159287 from dual UNION SELECT 4159288 from dual UNION SELECT 4159289 from dual UNION SELECT 4159290 from dual 
UNION SELECT 4159291 from dual UNION SELECT 4159292 from dual UNION SELECT 4159293 from dual UNION SELECT 4159294 from dual UNION SELECT 4159295 from dual UNION SELECT 4159296 from dual UNION SELECT 4159297 from dual UNION SELECT 4159298 from dual 
UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual 
UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159299 from dual UNION SELECT 4159300 from dual 
UNION SELECT 4159301 from dual UNION SELECT 4159302 from dual UNION SELECT 4159303 from dual UNION SELECT 4159304 from dual UNION SELECT 4159305 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual 
UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159307 from dual UNION SELECT 4159308 from dual 
UNION SELECT 4159309 from dual UNION SELECT 4159310 from dual UNION SELECT 4159311 from dual UNION SELECT 4159312 from dual UNION SELECT 4159313 from dual UNION SELECT 4159314 from dual UNION SELECT 4159315 from dual UNION SELECT 4159316 from dual 
UNION SELECT 4159317 from dual UNION SELECT 4159318 from dual UNION SELECT 4159319 from dual UNION SELECT 4159320 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual 
UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159322 from dual UNION SELECT 4159323 from dual UNION SELECT 4159324 from dual UNION SELECT 4159325 from dual UNION SELECT 4159326 from dual 
UNION SELECT 4159327 from dual UNION SELECT 4159328 from dual UNION SELECT 4159329 from dual UNION SELECT 4159330 from dual UNION SELECT 4159330 from dual UNION SELECT 4159330 from dual UNION SELECT 4159331 from dual UNION SELECT 4159332 from dual 
UNION SELECT 4159333 from dual UNION SELECT 4159334 from dual UNION SELECT 4159334 from dual UNION SELECT 4159335 from dual UNION SELECT 4159336 from dual UNION SELECT 4159337 from dual UNION SELECT 4159338 from dual UNION SELECT 4159339 from dual 
UNION SELECT 4159340 from dual UNION SELECT 4159341 from dual UNION SELECT 4159342 from dual UNION SELECT 4159343 from dual UNION SELECT 4159344 from dual UNION SELECT 4159345 from dual UNION SELECT 4159346 from dual UNION SELECT 4159347 from dual 
UNION SELECT 4159348 from dual UNION SELECT 4159349 from dual UNION SELECT 4159350 from dual UNION SELECT 4159351 from dual UNION SELECT 4159352 from dual UNION SELECT 4159353 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual 
UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual 
UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159355 from dual UNION SELECT 4159356 from dual UNION SELECT 4159357 from dual UNION SELECT 4159358 from dual UNION SELECT 4159359 from dual 
UNION SELECT 4159360 from dual UNION SELECT 4159361 from dual UNION SELECT 4159362 from dual UNION SELECT 4159391 from dual UNION SELECT 4159392 from dual UNION SELECT 4159392 from dual UNION SELECT 4159393 from dual UNION SELECT 4159394 from dual 
UNION SELECT 4159395 from dual UNION SELECT 4159396 from dual UNION SELECT 4159396 from dual UNION SELECT 4159397 from dual UNION SELECT 4159398 from dual UNION SELECT 4159399 from dual UNION SELECT 4159400 from dual UNION SELECT 4159401 from dual 
UNION SELECT 4159402 from dual UNION SELECT 4159403 from dual UNION SELECT 4159404 from dual UNION SELECT 4159405 from dual UNION SELECT 4159406 from dual UNION SELECT 4159407 from dual UNION SELECT 4159408 from dual UNION SELECT 4159409 from dual 
UNION SELECT 4159410 from dual UNION SELECT 4159411 from dual UNION SELECT 4159412 from dual UNION SELECT 4159413 from dual UNION SELECT 4159414 from dual UNION SELECT 4159415 from dual UNION SELECT 4159416 from dual UNION SELECT 4159417 from dual 
UNION SELECT 4159418 from dual UNION SELECT 4159419 from dual UNION SELECT 4159420 from dual UNION SELECT 4159421 from dual UNION SELECT 4159422 from dual UNION SELECT 4159423 from dual UNION SELECT 4159424 from dual UNION SELECT 4159425 from dual 
UNION SELECT 4159426 from dual UNION SELECT 4159427 from dual UNION SELECT 4159428 from dual UNION SELECT 4159429 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual 
UNION SELECT 4159430 from dual UNION SELECT 4159431 from dual UNION SELECT 4159432 from dual UNION SELECT 4159433 from dual UNION SELECT 4159434 from dual UNION SELECT 4159435 from dual UNION SELECT 4159436 from dual UNION SELECT 4159437 from dual 
UNION SELECT 4159437 from dual UNION SELECT 4159437 from dual UNION SELECT 4159438 from dual UNION SELECT 4159439 from dual UNION SELECT 4159440 from dual UNION SELECT 4159440 from dual UNION SELECT 4159440 from dual UNION SELECT 4159441 from dual 
UNION SELECT 4159442 from dual UNION SELECT 4159443 from dual UNION SELECT 4159444 from dual UNION SELECT 4159445 from dual UNION SELECT 4159446 from dual UNION SELECT 4159447 from dual UNION SELECT 4159448 from dual UNION SELECT 4159449 from dual 
UNION SELECT 4159450 from dual UNION SELECT 4159451 from dual UNION SELECT 4159452 from dual UNION SELECT 4159453 from dual UNION SELECT 4159454 from dual UNION SELECT 4159455 from dual UNION SELECT 4159456 from dual UNION SELECT 4159456 from dual 
UNION SELECT 4159457 from dual UNION SELECT 4159458 from dual UNION SELECT 4159459 from dual UNION SELECT 4159460 from dual UNION SELECT 4159461 from dual UNION SELECT 4159462 from dual UNION SELECT 4159463 from dual UNION SELECT 4159464 from dual 
UNION SELECT 4159465 from dual UNION SELECT 4159466 from dual UNION SELECT 4159467 from dual UNION SELECT 4159468 from dual UNION SELECT 4159469 from dual UNION SELECT 4159470 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159472 from dual UNION SELECT 4159473 from dual UNION SELECT 4159474 from dual UNION SELECT 4159475 from dual UNION SELECT 4159476 from dual UNION SELECT 4159476 from dual UNION SELECT 4159477 from dual UNION SELECT 4159478 from dual 
UNION SELECT 4159479 from dual UNION SELECT 4159480 from dual UNION SELECT 4159481 from dual UNION SELECT 4159482 from dual UNION SELECT 4159483 from dual UNION SELECT 4159484 from dual UNION SELECT 4159485 from dual UNION SELECT 4159486 from dual 
UNION SELECT 4159487 from dual UNION SELECT 4159488 from dual UNION SELECT 4159489 from dual UNION SELECT 4159490 from dual UNION SELECT 4159491 from dual UNION SELECT 4159492 from dual UNION SELECT 4159492 from dual UNION SELECT 4159493 from dual 
UNION SELECT 4159494 from dual UNION SELECT 4159495 from dual UNION SELECT 4159496 from dual UNION SELECT 4159497 from dual UNION SELECT 4159498 from dual UNION SELECT 4159499 from dual UNION SELECT 4159500 from dual UNION SELECT 4159501 from dual 
UNION SELECT 4159502 from dual UNION SELECT 4159503 from dual UNION SELECT 4159504 from dual UNION SELECT 4159505 from dual UNION SELECT 4159506 from dual UNION SELECT 4159507 from dual UNION SELECT 4159508 from dual UNION SELECT 4159509 from dual 
UNION SELECT 4159510 from dual UNION SELECT 4159511 from dual UNION SELECT 4159512 from dual UNION SELECT 4159513 from dual UNION SELECT 4159514 from dual UNION SELECT 4159515 from dual UNION SELECT 4159516 from dual UNION SELECT 4159517 from dual 
UNION SELECT 4159518 from dual UNION SELECT 4159519 from dual UNION SELECT 4159520 from dual UNION SELECT 4159521 from dual UNION SELECT 4159522 from dual UNION SELECT 4159523 from dual UNION SELECT 4159524 from dual UNION SELECT 4159525 from dual 
UNION SELECT 4159526 from dual UNION SELECT 4159527 from dual UNION SELECT 4159528 from dual UNION SELECT 4159529 from dual UNION SELECT 4159530 from dual UNION SELECT 4159530 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual 
UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual 
UNION SELECT 4158786 from dual UNION SELECT 4158788 from dual UNION SELECT 4158790 from dual UNION SELECT 4158792 from dual UNION SELECT 4158792 from dual UNION SELECT 4158794 from dual UNION SELECT 4158796 from dual UNION SELECT 4158798 from dual 
UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158800 from dual UNION SELECT 4158802 from dual UNION SELECT 4158804 from dual UNION SELECT 4158807 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158811 from dual UNION SELECT 4158813 from dual UNION SELECT 4158813 from dual UNION SELECT 4158815 from dual UNION SELECT 4158815 from dual 
UNION SELECT 4158817 from dual UNION SELECT 4158819 from dual UNION SELECT 4158821 from dual UNION SELECT 4158822 from dual UNION SELECT 4158823 from dual UNION SELECT 4158824 from dual UNION SELECT 4158825 from dual UNION SELECT 4158826 from dual 
UNION SELECT 4158827 from dual UNION SELECT 4158828 from dual UNION SELECT 4158829 from dual UNION SELECT 4158830 from dual UNION SELECT 4158831 from dual UNION SELECT 4158832 from dual UNION SELECT 4158833 from dual UNION SELECT 4158834 from dual 
UNION SELECT 4158835 from dual UNION SELECT 4158836 from dual UNION SELECT 4158837 from dual UNION SELECT 4158838 from dual UNION SELECT 4158839 from dual UNION SELECT 4158840 from dual UNION SELECT 4158841 from dual UNION SELECT 4158842 from dual 
UNION SELECT 4158843 from dual UNION SELECT 4158844 from dual UNION SELECT 4158845 from dual UNION SELECT 4158847 from dual UNION SELECT 4158848 from dual UNION SELECT 4158850 from dual UNION SELECT 4158851 from dual UNION SELECT 4158852 from dual 
UNION SELECT 4158853 from dual UNION SELECT 4158854 from dual UNION SELECT 4158855 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158857 from dual 
UNION SELECT 4158858 from dual UNION SELECT 4158859 from dual UNION SELECT 4158860 from dual UNION SELECT 4158861 from dual UNION SELECT 4158862 from dual UNION SELECT 4158863 from dual UNION SELECT 4158864 from dual UNION SELECT 4158865 from dual 
uNION SELECT 4158866 from dual UNION SELECT 4158867 from dual UNION SELECT 4158868 from dual UNION SELECT 4158869 from dual UNION SELECT 4158870 from dual UNION SELECT 4158871 from dual UNION SELECT 4158872 from dual UNION SELECT 4158873 from dual 
UNION SELECT 4158874 from dual UNION SELECT 4158875 from dual UNION SELECT 4158876 from dual UNION SELECT 4158877 from dual UNION SELECT 4158878 from dual UNION SELECT 4158879 from dual UNION SELECT 4158880 from dual UNION SELECT 4158881 from dual 
UNION SELECT 4158882 from dual UNION SELECT 4158883 from dual UNION SELECT 4158884 from dual UNION SELECT 4158885 from dual UNION SELECT 4158886 from dual UNION SELECT 4158887 from dual UNION SELECT 4158888 from dual UNION SELECT 4158889 from dual 
UNION SELECT 4158890 from dual UNION SELECT 4158891 from dual UNION SELECT 4158892 from dual UNION SELECT 4158893 from dual UNION SELECT 4158894 from dual UNION SELECT 4158895 from dual UNION SELECT 4158896 from dual UNION SELECT 4158897 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158997 from dual UNION SELECT 4158998 from dual UNION SELECT 4158999 from dual UNION SELECT 4159000 from dual 
UNION SELECT 4159001 from dual UNION SELECT 4159002 from dual UNION SELECT 4159003 from dual UNION SELECT 4159004 from dual UNION SELECT 4159005 from dual UNION SELECT 4159006 from dual UNION SELECT 4159007 from dual UNION SELECT 4159008 from dual 
UNION SELECT 4159009 from dual UNION SELECT 4159010 from dual UNION SELECT 4159012 from dual UNION SELECT 4159013 from dual UNION SELECT 4159013 from dual UNION SELECT 4159013 from dual UNION SELECT 4159014 from dual UNION SELECT 4159015 from dual 
UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual 
UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159017 from dual UNION SELECT 4159018 from dual UNION SELECT 4159019 from dual UNION SELECT 4159020 from dual UNION SELECT 4159021 from dual UNION SELECT 4159022 from dual 
UNION SELECT 4159023 from dual UNION SELECT 4159024 from dual UNION SELECT 4159025 from dual UNION SELECT 4159026 from dual UNION SELECT 4159027 from dual UNION SELECT 4159028 from dual UNION SELECT 4159029 from dual UNION SELECT 4159030 from dual 
UNION SELECT 4159031 from dual UNION SELECT 4159032 from dual UNION SELECT 4159033 from dual UNION SELECT 4159034 from dual UNION SELECT 4159035 from dual UNION SELECT 4159036 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual 
UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual 
UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159039 from dual UNION SELECT 4159039 from dual UNION SELECT 4159040 from dual 
UNION SELECT 4159041 from dual UNION SELECT 4159042 from dual UNION SELECT 4159043 from dual UNION SELECT 4159044 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual 
UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual 
UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual 
UNION SELECT 4159046 from dual UNION SELECT 4159047 from dual UNION SELECT 4159048 from dual UNION SELECT 4159049 from dual UNION SELECT 4159050 from dual UNION SELECT 4159051 from dual UNION SELECT 4159052 from dual UNION SELECT 4159053 from dual 
UNION SELECT 4159054 from dual UNION SELECT 4159055 from dual UNION SELECT 4159056 from dual UNION SELECT 4159057 from dual UNION SELECT 4159058 from dual UNION SELECT 4159059 from dual UNION SELECT 4159060 from dual UNION SELECT 4159061 from dual 
UNION SELECT 4159062 from dual UNION SELECT 4159063 from dual UNION SELECT 4159064 from dual UNION SELECT 4159065 from dual UNION SELECT 4159066 from dual UNION SELECT 4159067 from dual UNION SELECT 4159068 from dual UNION SELECT 4159069 from dual 
UNION SELECT 4159070 from dual UNION SELECT 4159071 from dual UNION SELECT 4159072 from dual UNION SELECT 4159073 from dual UNION SELECT 4159074 from dual UNION SELECT 4159074 from dual UNION SELECT 4159075 from dual UNION SELECT 4159076 from dual 
UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual 
UNION SELECT 4159076 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual 
UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual 
UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159078 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual 
UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual 
UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159080 from dual UNION SELECT 4159081 from dual UNION SELECT 4159082 from dual 
UNION SELECT 4159083 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159085 from dual UNION SELECT 4159086 from dual UNION SELECT 4159087 from dual 
UNION SELECT 4159088 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159090 from dual UNION SELECT 4159091 from dual UNION SELECT 4159092 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159094 from dual UNION SELECT 4159095 from dual UNION SELECT 4159096 from dual UNION SELECT 4159097 from dual 
UNION SELECT 4159098 from dual UNION SELECT 4159099 from dual UNION SELECT 4159100 from dual UNION SELECT 4159101 from dual UNION SELECT 4159102 from dual UNION SELECT 4159103 from dual UNION SELECT 4159104 from dual UNION SELECT 4159105 from dual 
UNION SELECT 4159106 from dual UNION SELECT 4159107 from dual UNION SELECT 4159108 from dual UNION SELECT 4159109 from dual UNION SELECT 4159110 from dual UNION SELECT 4159111 from dual UNION SELECT 4159112 from dual UNION SELECT 4159112 from dual 
UNION SELECT 4159113 from dual UNION SELECT 4159114 from dual UNION SELECT 4159115 from dual UNION SELECT 4159116 from dual UNION SELECT 4159117 from dual UNION SELECT 4159118 from dual UNION SELECT 4159119 from dual UNION SELECT 4159120 from dual 
UNION SELECT 4159121 from dual UNION SELECT 4159122 from dual UNION SELECT 4159123 from dual UNION SELECT 4159124 from dual UNION SELECT 4159125 from dual UNION SELECT 4159126 from dual UNION SELECT 4159127 from dual UNION SELECT 4159127 from dual 
UNION SELECT 4159128 from dual UNION SELECT 4159129 from dual UNION SELECT 4159130 from dual UNION SELECT 4159131 from dual UNION SELECT 4159132 from dual UNION SELECT 4159133 from dual UNION SELECT 4159134 from dual UNION SELECT 4159135 from dual 
UNION SELECT 4159136 from dual UNION SELECT 4159137 from dual UNION SELECT 4159138 from dual UNION SELECT 4159139 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual 
UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual 
UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159141 from dual UNION SELECT 4159142 from dual UNION SELECT 4159143 from dual UNION SELECT 4159144 from dual UNION SELECT 4159145 from dual UNION SELECT 4159146 from dual 
UNION SELECT 4159147 from dual UNION SELECT 4159148 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual 
UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual 
UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159150 from dual 
UNION SELECT 4159151 from dual UNION SELECT 4159152 from dual UNION SELECT 4159153 from dual UNION SELECT 4159154 from dual UNION SELECT 4159155 from dual UNION SELECT 4159155 from dual UNION SELECT 4159156 from dual UNION SELECT 4159157 from dual 
UNION SELECT 4159158 from dual UNION SELECT 4159159 from dual UNION SELECT 4159160 from dual UNION SELECT 4159161 from dual UNION SELECT 4159162 from dual UNION SELECT 4159163 from dual UNION SELECT 4159164 from dual UNION SELECT 4159165 from dual 
UNION SELECT 4159166 from dual UNION SELECT 4159167 from dual UNION SELECT 4159167 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual 
UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159169 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159278 from dual UNION SELECT 4159279 from dual UNION SELECT 4159280 from dual UNION SELECT 4159281 from dual UNION SELECT 4159282 from dual 
UNION SELECT 4159283 from dual UNION SELECT 4159284 from dual UNION SELECT 4159285 from dual UNION SELECT 4159286 from dual UNION SELECT 4159287 from dual UNION SELECT 4159288 from dual UNION SELECT 4159289 from dual UNION SELECT 4159290 from dual 
UNION SELECT 4159291 from dual UNION SELECT 4159292 from dual UNION SELECT 4159293 from dual UNION SELECT 4159294 from dual UNION SELECT 4159295 from dual UNION SELECT 4159296 from dual UNION SELECT 4159297 from dual UNION SELECT 4159298 from dual 
UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual 
UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159299 from dual UNION SELECT 4159300 from dual 
UNION SELECT 4159301 from dual UNION SELECT 4159302 from dual UNION SELECT 4159303 from dual UNION SELECT 4159304 from dual UNION SELECT 4159305 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual 
UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159307 from dual UNION SELECT 4159308 from dual 
UNION SELECT 4159309 from dual UNION SELECT 4159310 from dual UNION SELECT 4159311 from dual UNION SELECT 4159312 from dual UNION SELECT 4159313 from dual UNION SELECT 4159314 from dual UNION SELECT 4159315 from dual UNION SELECT 4159316 from dual 
UNION SELECT 4159317 from dual UNION SELECT 4159318 from dual UNION SELECT 4159319 from dual UNION SELECT 4159320 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual 
UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159322 from dual UNION SELECT 4159323 from dual UNION SELECT 4159324 from dual UNION SELECT 4159325 from dual UNION SELECT 4159326 from dual 
UNION SELECT 4159327 from dual UNION SELECT 4159328 from dual UNION SELECT 4159329 from dual UNION SELECT 4159330 from dual UNION SELECT 4159330 from dual UNION SELECT 4159330 from dual UNION SELECT 4159331 from dual UNION SELECT 4159332 from dual 
UNION SELECT 4159333 from dual UNION SELECT 4159334 from dual UNION SELECT 4159334 from dual UNION SELECT 4159335 from dual UNION SELECT 4159336 from dual UNION SELECT 4159337 from dual UNION SELECT 4159338 from dual UNION SELECT 4159339 from dual 
UNION SELECT 4159340 from dual UNION SELECT 4159341 from dual UNION SELECT 4159342 from dual UNION SELECT 4159343 from dual UNION SELECT 4159344 from dual UNION SELECT 4159345 from dual UNION SELECT 4159346 from dual UNION SELECT 4159347 from dual 
UNION SELECT 4159348 from dual UNION SELECT 4159349 from dual UNION SELECT 4159350 from dual UNION SELECT 4159351 from dual UNION SELECT 4159352 from dual UNION SELECT 4159353 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual 
UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual 
UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159355 from dual UNION SELECT 4159356 from dual UNION SELECT 4159357 from dual UNION SELECT 4159358 from dual UNION SELECT 4159359 from dual 
UNION SELECT 4159360 from dual UNION SELECT 4159361 from dual UNION SELECT 4159362 from dual UNION SELECT 4159391 from dual UNION SELECT 4159392 from dual UNION SELECT 4159392 from dual UNION SELECT 4159393 from dual UNION SELECT 4159394 from dual 
UNION SELECT 4159395 from dual UNION SELECT 4159396 from dual UNION SELECT 4159396 from dual UNION SELECT 4159397 from dual UNION SELECT 4159398 from dual UNION SELECT 4159399 from dual UNION SELECT 4159400 from dual UNION SELECT 4159401 from dual 
UNION SELECT 4159402 from dual UNION SELECT 4159403 from dual UNION SELECT 4159404 from dual UNION SELECT 4159405 from dual UNION SELECT 4159406 from dual UNION SELECT 4159407 from dual UNION SELECT 4159408 from dual UNION SELECT 4159409 from dual 
UNION SELECT 4159410 from dual UNION SELECT 4159411 from dual UNION SELECT 4159412 from dual UNION SELECT 4159413 from dual UNION SELECT 4159414 from dual UNION SELECT 4159415 from dual UNION SELECT 4159416 from dual UNION SELECT 4159417 from dual 
UNION SELECT 4159418 from dual UNION SELECT 4159419 from dual UNION SELECT 4159420 from dual UNION SELECT 4159421 from dual UNION SELECT 4159422 from dual UNION SELECT 4159423 from dual UNION SELECT 4159424 from dual UNION SELECT 4159425 from dual 
UNION SELECT 4159426 from dual UNION SELECT 4159427 from dual UNION SELECT 4159428 from dual UNION SELECT 4159429 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual 
UNION SELECT 4159430 from dual UNION SELECT 4159431 from dual UNION SELECT 4159432 from dual UNION SELECT 4159433 from dual UNION SELECT 4159434 from dual UNION SELECT 4159435 from dual UNION SELECT 4159436 from dual UNION SELECT 4159437 from dual 
UNION SELECT 4159437 from dual UNION SELECT 4159437 from dual UNION SELECT 4159438 from dual UNION SELECT 4159439 from dual UNION SELECT 4159440 from dual UNION SELECT 4159440 from dual UNION SELECT 4159440 from dual UNION SELECT 4159441 from dual 
UNION SELECT 4159442 from dual UNION SELECT 4159443 from dual UNION SELECT 4159444 from dual UNION SELECT 4159445 from dual UNION SELECT 4159446 from dual UNION SELECT 4159447 from dual UNION SELECT 4159448 from dual UNION SELECT 4159449 from dual 
UNION SELECT 4159450 from dual UNION SELECT 4159451 from dual UNION SELECT 4159452 from dual UNION SELECT 4159453 from dual UNION SELECT 4159454 from dual UNION SELECT 4159455 from dual UNION SELECT 4159456 from dual UNION SELECT 4159456 from dual 
UNION SELECT 4159457 from dual UNION SELECT 4159458 from dual UNION SELECT 4159459 from dual UNION SELECT 4159460 from dual UNION SELECT 4159461 from dual UNION SELECT 4159462 from dual UNION SELECT 4159463 from dual UNION SELECT 4159464 from dual 
UNION SELECT 4159465 from dual UNION SELECT 4159466 from dual UNION SELECT 4159467 from dual UNION SELECT 4159468 from dual UNION SELECT 4159469 from dual UNION SELECT 4159470 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159472 from dual UNION SELECT 4159473 from dual UNION SELECT 4159474 from dual UNION SELECT 4159475 from dual UNION SELECT 4159476 from dual UNION SELECT 4159476 from dual UNION SELECT 4159477 from dual UNION SELECT 4159478 from dual 
UNION SELECT 4159479 from dual UNION SELECT 4159480 from dual UNION SELECT 4159481 from dual UNION SELECT 4159482 from dual UNION SELECT 4159483 from dual UNION SELECT 4159484 from dual UNION SELECT 4159485 from dual UNION SELECT 4159486 from dual 
UNION SELECT 4159487 from dual UNION SELECT 4159488 from dual UNION SELECT 4159489 from dual UNION SELECT 4159490 from dual UNION SELECT 4159491 from dual UNION SELECT 4159492 from dual UNION SELECT 4159492 from dual UNION SELECT 4159493 from dual 
UNION SELECT 4159494 from dual UNION SELECT 4159495 from dual UNION SELECT 4159496 from dual UNION SELECT 4159497 from dual UNION SELECT 4159498 from dual UNION SELECT 4159499 from dual UNION SELECT 4159500 from dual UNION SELECT 4159501 from dual 
UNION SELECT 4159502 from dual UNION SELECT 4159503 from dual UNION SELECT 4159504 from dual UNION SELECT 4159505 from dual UNION SELECT 4159506 from dual UNION SELECT 4159507 from dual UNION SELECT 4159508 from dual UNION SELECT 4159509 from dual 
UNION SELECT 4159510 from dual UNION SELECT 4159511 from dual UNION SELECT 4159512 from dual UNION SELECT 4159513 from dual UNION SELECT 4159514 from dual UNION SELECT 4159515 from dual UNION SELECT 4159516 from dual UNION SELECT 4159517 from dual 
UNION SELECT 4159518 from dual UNION SELECT 4159519 from dual UNION SELECT 4159520 from dual UNION SELECT 4159521 from dual UNION SELECT 4159522 from dual UNION SELECT 4159523 from dual UNION SELECT 4159524 from dual UNION SELECT 4159525 from dual 
UNION SELECT 4159526 from dual UNION SELECT 4159527 from dual UNION SELECT 4159528 from dual UNION SELECT 4159529 from dual UNION SELECT 4159530 from dual UNION SELECT 4159530 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual 
UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual 
UNION SELECT 4158786 from dual UNION SELECT 4158788 from dual UNION SELECT 4158790 from dual UNION SELECT 4158792 from dual UNION SELECT 4158792 from dual UNION SELECT 4158794 from dual UNION SELECT 4158796 from dual UNION SELECT 4158798 from dual 
UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158798 from dual UNION SELECT 4158800 from dual UNION SELECT 4158802 from dual UNION SELECT 4158804 from dual UNION SELECT 4158807 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual 
UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158809 from dual UNION SELECT 4158811 from dual UNION SELECT 4158813 from dual UNION SELECT 4158813 from dual UNION SELECT 4158815 from dual UNION SELECT 4158815 from dual 
UNION SELECT 4158817 from dual UNION SELECT 4158819 from dual UNION SELECT 4158821 from dual UNION SELECT 4158822 from dual UNION SELECT 4158823 from dual UNION SELECT 4158824 from dual UNION SELECT 4158825 from dual UNION SELECT 4158826 from dual 
UNION SELECT 4158827 from dual UNION SELECT 4158828 from dual UNION SELECT 4158829 from dual UNION SELECT 4158830 from dual UNION SELECT 4158831 from dual UNION SELECT 4158832 from dual UNION SELECT 4158833 from dual UNION SELECT 4158834 from dual 
UNION SELECT 4158835 from dual UNION SELECT 4158836 from dual UNION SELECT 4158837 from dual UNION SELECT 4158838 from dual UNION SELECT 4158839 from dual UNION SELECT 4158840 from dual UNION SELECT 4158841 from dual UNION SELECT 4158842 from dual 
UNION SELECT 4158843 from dual UNION SELECT 4158844 from dual UNION SELECT 4158845 from dual UNION SELECT 4158847 from dual UNION SELECT 4158848 from dual UNION SELECT 4158850 from dual UNION SELECT 4158851 from dual UNION SELECT 4158852 from dual 
UNION SELECT 4158853 from dual UNION SELECT 4158854 from dual UNION SELECT 4158855 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158856 from dual UNION SELECT 4158857 from dual 
UNION SELECT 4158858 from dual UNION SELECT 4158859 from dual UNION SELECT 4158860 from dual UNION SELECT 4158861 from dual UNION SELECT 4158862 from dual UNION SELECT 4158863 from dual UNION SELECT 4158864 from dual UNION SELECT 4158865 from dual 
uNION SELECT 4158866 from dual UNION SELECT 4158867 from dual UNION SELECT 4158868 from dual UNION SELECT 4158869 from dual UNION SELECT 4158870 from dual UNION SELECT 4158871 from dual UNION SELECT 4158872 from dual UNION SELECT 4158873 from dual 
UNION SELECT 4158874 from dual UNION SELECT 4158875 from dual UNION SELECT 4158876 from dual UNION SELECT 4158877 from dual UNION SELECT 4158878 from dual UNION SELECT 4158879 from dual UNION SELECT 4158880 from dual UNION SELECT 4158881 from dual 
UNION SELECT 4158882 from dual UNION SELECT 4158883 from dual UNION SELECT 4158884 from dual UNION SELECT 4158885 from dual UNION SELECT 4158886 from dual UNION SELECT 4158887 from dual UNION SELECT 4158888 from dual UNION SELECT 4158889 from dual 
UNION SELECT 4158890 from dual UNION SELECT 4158891 from dual UNION SELECT 4158892 from dual UNION SELECT 4158893 from dual UNION SELECT 4158894 from dual UNION SELECT 4158895 from dual UNION SELECT 4158896 from dual UNION SELECT 4158897 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual 
UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158898 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual 
UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158996 from dual UNION SELECT 4158997 from dual UNION SELECT 4158998 from dual UNION SELECT 4158999 from dual UNION SELECT 4159000 from dual 
UNION SELECT 4159001 from dual UNION SELECT 4159002 from dual UNION SELECT 4159003 from dual UNION SELECT 4159004 from dual UNION SELECT 4159005 from dual UNION SELECT 4159006 from dual UNION SELECT 4159007 from dual UNION SELECT 4159008 from dual 
UNION SELECT 4159009 from dual UNION SELECT 4159010 from dual UNION SELECT 4159012 from dual UNION SELECT 4159013 from dual UNION SELECT 4159013 from dual UNION SELECT 4159013 from dual UNION SELECT 4159014 from dual UNION SELECT 4159015 from dual 
UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual 
UNION SELECT 4159016 from dual UNION SELECT 4159016 from dual UNION SELECT 4159017 from dual UNION SELECT 4159018 from dual UNION SELECT 4159019 from dual UNION SELECT 4159020 from dual UNION SELECT 4159021 from dual UNION SELECT 4159022 from dual 
UNION SELECT 4159023 from dual UNION SELECT 4159024 from dual UNION SELECT 4159025 from dual UNION SELECT 4159026 from dual UNION SELECT 4159027 from dual UNION SELECT 4159028 from dual UNION SELECT 4159029 from dual UNION SELECT 4159030 from dual 
UNION SELECT 4159031 from dual UNION SELECT 4159032 from dual UNION SELECT 4159033 from dual UNION SELECT 4159034 from dual UNION SELECT 4159035 from dual UNION SELECT 4159036 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual 
UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159037 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual 
UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159038 from dual UNION SELECT 4159039 from dual UNION SELECT 4159039 from dual UNION SELECT 4159040 from dual 
UNION SELECT 4159041 from dual UNION SELECT 4159042 from dual UNION SELECT 4159043 from dual UNION SELECT 4159044 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual 
UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159045 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual 
UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual UNION SELECT 4159046 from dual 
UNION SELECT 4159046 from dual UNION SELECT 4159047 from dual UNION SELECT 4159048 from dual UNION SELECT 4159049 from dual UNION SELECT 4159050 from dual UNION SELECT 4159051 from dual UNION SELECT 4159052 from dual UNION SELECT 4159053 from dual 
UNION SELECT 4159054 from dual UNION SELECT 4159055 from dual UNION SELECT 4159056 from dual UNION SELECT 4159057 from dual UNION SELECT 4159058 from dual UNION SELECT 4159059 from dual UNION SELECT 4159060 from dual UNION SELECT 4159061 from dual 
UNION SELECT 4159062 from dual UNION SELECT 4159063 from dual UNION SELECT 4159064 from dual UNION SELECT 4159065 from dual UNION SELECT 4159066 from dual UNION SELECT 4159067 from dual UNION SELECT 4159068 from dual UNION SELECT 4159069 from dual 
UNION SELECT 4159070 from dual UNION SELECT 4159071 from dual UNION SELECT 4159072 from dual UNION SELECT 4159073 from dual UNION SELECT 4159074 from dual UNION SELECT 4159074 from dual UNION SELECT 4159075 from dual UNION SELECT 4159076 from dual 
UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual UNION SELECT 4159076 from dual 
UNION SELECT 4159076 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual 
UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual 
UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159077 from dual UNION SELECT 4159078 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual 
UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual 
UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159079 from dual UNION SELECT 4159080 from dual UNION SELECT 4159081 from dual UNION SELECT 4159082 from dual 
UNION SELECT 4159083 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159084 from dual UNION SELECT 4159085 from dual UNION SELECT 4159086 from dual UNION SELECT 4159087 from dual 
UNION SELECT 4159088 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159089 from dual UNION SELECT 4159090 from dual UNION SELECT 4159091 from dual UNION SELECT 4159092 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual 
UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159093 from dual UNION SELECT 4159094 from dual UNION SELECT 4159095 from dual UNION SELECT 4159096 from dual UNION SELECT 4159097 from dual 
UNION SELECT 4159098 from dual UNION SELECT 4159099 from dual UNION SELECT 4159100 from dual UNION SELECT 4159101 from dual UNION SELECT 4159102 from dual UNION SELECT 4159103 from dual UNION SELECT 4159104 from dual UNION SELECT 4159105 from dual 
UNION SELECT 4159106 from dual UNION SELECT 4159107 from dual UNION SELECT 4159108 from dual UNION SELECT 4159109 from dual UNION SELECT 4159110 from dual UNION SELECT 4159111 from dual UNION SELECT 4159112 from dual UNION SELECT 4159112 from dual 
UNION SELECT 4159113 from dual UNION SELECT 4159114 from dual UNION SELECT 4159115 from dual UNION SELECT 4159116 from dual UNION SELECT 4159117 from dual UNION SELECT 4159118 from dual UNION SELECT 4159119 from dual UNION SELECT 4159120 from dual 
UNION SELECT 4159121 from dual UNION SELECT 4159122 from dual UNION SELECT 4159123 from dual UNION SELECT 4159124 from dual UNION SELECT 4159125 from dual UNION SELECT 4159126 from dual UNION SELECT 4159127 from dual UNION SELECT 4159127 from dual 
UNION SELECT 4159128 from dual UNION SELECT 4159129 from dual UNION SELECT 4159130 from dual UNION SELECT 4159131 from dual UNION SELECT 4159132 from dual UNION SELECT 4159133 from dual UNION SELECT 4159134 from dual UNION SELECT 4159135 from dual 
UNION SELECT 4159136 from dual UNION SELECT 4159137 from dual UNION SELECT 4159138 from dual UNION SELECT 4159139 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual 
UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual 
UNION SELECT 4159140 from dual UNION SELECT 4159140 from dual UNION SELECT 4159141 from dual UNION SELECT 4159142 from dual UNION SELECT 4159143 from dual UNION SELECT 4159144 from dual UNION SELECT 4159145 from dual UNION SELECT 4159146 from dual 
UNION SELECT 4159147 from dual UNION SELECT 4159148 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual 
UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual 
UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159149 from dual UNION SELECT 4159150 from dual 
UNION SELECT 4159151 from dual UNION SELECT 4159152 from dual UNION SELECT 4159153 from dual UNION SELECT 4159154 from dual UNION SELECT 4159155 from dual UNION SELECT 4159155 from dual UNION SELECT 4159156 from dual UNION SELECT 4159157 from dual 
UNION SELECT 4159158 from dual UNION SELECT 4159159 from dual UNION SELECT 4159160 from dual UNION SELECT 4159161 from dual UNION SELECT 4159162 from dual UNION SELECT 4159163 from dual UNION SELECT 4159164 from dual UNION SELECT 4159165 from dual 
UNION SELECT 4159166 from dual UNION SELECT 4159167 from dual UNION SELECT 4159167 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual 
UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159168 from dual UNION SELECT 4159169 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual 
UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159170 from dual UNION SELECT 4159278 from dual UNION SELECT 4159279 from dual UNION SELECT 4159280 from dual UNION SELECT 4159281 from dual UNION SELECT 4159282 from dual 
UNION SELECT 4159283 from dual UNION SELECT 4159284 from dual UNION SELECT 4159285 from dual UNION SELECT 4159286 from dual UNION SELECT 4159287 from dual UNION SELECT 4159288 from dual UNION SELECT 4159289 from dual UNION SELECT 4159290 from dual 
UNION SELECT 4159291 from dual UNION SELECT 4159292 from dual UNION SELECT 4159293 from dual UNION SELECT 4159294 from dual UNION SELECT 4159295 from dual UNION SELECT 4159296 from dual UNION SELECT 4159297 from dual UNION SELECT 4159298 from dual 
UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual 
UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159298 from dual UNION SELECT 4159299 from dual UNION SELECT 4159300 from dual 
UNION SELECT 4159301 from dual UNION SELECT 4159302 from dual UNION SELECT 4159303 from dual UNION SELECT 4159304 from dual UNION SELECT 4159305 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual 
UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159306 from dual UNION SELECT 4159307 from dual UNION SELECT 4159308 from dual 
UNION SELECT 4159309 from dual UNION SELECT 4159310 from dual UNION SELECT 4159311 from dual UNION SELECT 4159312 from dual UNION SELECT 4159313 from dual UNION SELECT 4159314 from dual UNION SELECT 4159315 from dual UNION SELECT 4159316 from dual 
UNION SELECT 4159317 from dual UNION SELECT 4159318 from dual UNION SELECT 4159319 from dual UNION SELECT 4159320 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual 
UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159321 from dual UNION SELECT 4159322 from dual UNION SELECT 4159323 from dual UNION SELECT 4159324 from dual UNION SELECT 4159325 from dual UNION SELECT 4159326 from dual 
UNION SELECT 4159327 from dual UNION SELECT 4159328 from dual UNION SELECT 4159329 from dual UNION SELECT 4159330 from dual UNION SELECT 4159330 from dual UNION SELECT 4159330 from dual UNION SELECT 4159331 from dual UNION SELECT 4159332 from dual 
UNION SELECT 4159333 from dual UNION SELECT 4159334 from dual UNION SELECT 4159334 from dual UNION SELECT 4159335 from dual UNION SELECT 4159336 from dual UNION SELECT 4159337 from dual UNION SELECT 4159338 from dual UNION SELECT 4159339 from dual 
UNION SELECT 4159340 from dual UNION SELECT 4159341 from dual UNION SELECT 4159342 from dual UNION SELECT 4159343 from dual UNION SELECT 4159344 from dual UNION SELECT 4159345 from dual UNION SELECT 4159346 from dual UNION SELECT 4159347 from dual 
UNION SELECT 4159348 from dual UNION SELECT 4159349 from dual UNION SELECT 4159350 from dual UNION SELECT 4159351 from dual UNION SELECT 4159352 from dual UNION SELECT 4159353 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual 
UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual 
UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159354 from dual UNION SELECT 4159355 from dual UNION SELECT 4159356 from dual UNION SELECT 4159357 from dual UNION SELECT 4159358 from dual UNION SELECT 4159359 from dual 
UNION SELECT 4159360 from dual UNION SELECT 4159361 from dual UNION SELECT 4159362 from dual UNION SELECT 4159391 from dual UNION SELECT 4159392 from dual UNION SELECT 4159392 from dual UNION SELECT 4159393 from dual UNION SELECT 4159394 from dual 
UNION SELECT 4159395 from dual UNION SELECT 4159396 from dual UNION SELECT 4159396 from dual UNION SELECT 4159397 from dual UNION SELECT 4159398 from dual UNION SELECT 4159399 from dual UNION SELECT 4159400 from dual UNION SELECT 4159401 from dual 
UNION SELECT 4159402 from dual UNION SELECT 4159403 from dual UNION SELECT 4159404 from dual UNION SELECT 4159405 from dual UNION SELECT 4159406 from dual UNION SELECT 4159407 from dual UNION SELECT 4159408 from dual UNION SELECT 4159409 from dual 
UNION SELECT 4159410 from dual UNION SELECT 4159411 from dual UNION SELECT 4159412 from dual UNION SELECT 4159413 from dual UNION SELECT 4159414 from dual UNION SELECT 4159415 from dual UNION SELECT 4159416 from dual UNION SELECT 4159417 from dual 
UNION SELECT 4159418 from dual UNION SELECT 4159419 from dual UNION SELECT 4159420 from dual UNION SELECT 4159421 from dual UNION SELECT 4159422 from dual UNION SELECT 4159423 from dual UNION SELECT 4159424 from dual UNION SELECT 4159425 from dual 
UNION SELECT 4159426 from dual UNION SELECT 4159427 from dual UNION SELECT 4159428 from dual UNION SELECT 4159429 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual UNION SELECT 4159430 from dual 
UNION SELECT 4159430 from dual UNION SELECT 4159431 from dual UNION SELECT 4159432 from dual UNION SELECT 4159433 from dual UNION SELECT 4159434 from dual UNION SELECT 4159435 from dual UNION SELECT 4159436 from dual UNION SELECT 4159437 from dual 
UNION SELECT 4159437 from dual UNION SELECT 4159437 from dual UNION SELECT 4159438 from dual UNION SELECT 4159439 from dual UNION SELECT 4159440 from dual UNION SELECT 4159440 from dual UNION SELECT 4159440 from dual UNION SELECT 4159441 from dual 
UNION SELECT 4159442 from dual UNION SELECT 4159443 from dual UNION SELECT 4159444 from dual UNION SELECT 4159445 from dual UNION SELECT 4159446 from dual UNION SELECT 4159447 from dual UNION SELECT 4159448 from dual UNION SELECT 4159449 from dual 
UNION SELECT 4159450 from dual UNION SELECT 4159451 from dual UNION SELECT 4159452 from dual UNION SELECT 4159453 from dual UNION SELECT 4159454 from dual UNION SELECT 4159455 from dual UNION SELECT 4159456 from dual UNION SELECT 4159456 from dual 
UNION SELECT 4159457 from dual UNION SELECT 4159458 from dual UNION SELECT 4159459 from dual UNION SELECT 4159460 from dual UNION SELECT 4159461 from dual UNION SELECT 4159462 from dual UNION SELECT 4159463 from dual UNION SELECT 4159464 from dual 
UNION SELECT 4159465 from dual UNION SELECT 4159466 from dual UNION SELECT 4159467 from dual UNION SELECT 4159468 from dual UNION SELECT 4159469 from dual UNION SELECT 4159470 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual UNION SELECT 4159471 from dual 
UNION SELECT 4159472 from dual UNION SELECT 4159473 from dual UNION SELECT 4159474 from dual UNION SELECT 4159475 from dual UNION SELECT 4159476 from dual UNION SELECT 4159476 from dual UNION SELECT 4159477 from dual UNION SELECT 4159478 from dual 
UNION SELECT 4159479 from dual UNION SELECT 4159480 from dual UNION SELECT 4159481 from dual UNION SELECT 4159482 from dual UNION SELECT 4159483 from dual UNION SELECT 4159484 from dual UNION SELECT 4159485 from dual UNION SELECT 4159486 from dual 
UNION SELECT 4159487 from dual UNION SELECT 4159488 from dual UNION SELECT 4159489 from dual UNION SELECT 4159490 from dual UNION SELECT 4159491 from dual UNION SELECT 4159492 from dual UNION SELECT 4159492 from dual UNION SELECT 4159493 from dual 
UNION SELECT 4159494 from dual UNION SELECT 4159495 from dual UNION SELECT 4159496 from dual UNION SELECT 4159497 from dual UNION SELECT 4159498 from dual UNION SELECT 4159499 from dual UNION SELECT 4159500 from dual UNION SELECT 4159501 from dual 
UNION SELECT 4159502 from dual UNION SELECT 4159503 from dual UNION SELECT 4159504 from dual UNION SELECT 4159505 from dual UNION SELECT 4159506 from dual UNION SELECT 4159507 from dual UNION SELECT 4159508 from dual UNION SELECT 4159509 from dual 
UNION SELECT 4159510 from dual UNION SELECT 4159511 from dual UNION SELECT 4159512 from dual UNION SELECT 4159513 from dual UNION SELECT 4159514 from dual UNION SELECT 4159515 from dual UNION SELECT 4159516 from dual UNION SELECT 4159517 from dual 
UNION SELECT 4159518 from dual UNION SELECT 4159519 from dual UNION SELECT 4159520 from dual UNION SELECT 4159521 from dual UNION SELECT 4159522 from dual UNION SELECT 4159523 from dual UNION SELECT 4159524 from dual UNION SELECT 4159525 from dual 
UNION SELECT 4159526 from dual UNION SELECT 4159527 from dual UNION SELECT 4159528 from dual UNION SELECT 4159529 from dual UNION SELECT 4159530 from dual UNION SELECT 4159530 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual 
UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual UNION SELECT 4159531 from dual 
UNION SELECT 4159531 from dual ) d ON a.id = d.fileid order by newsort_DTS2020042010859(c.name)) SELECT DISTINCT id, group_concat(sharpName) AS sharpNames FROM ret GROUP BY id;
drop table FILECURRENT_0422;
drop table FILEATTRIBUTE_0422;
drop table sharp_0422;
set termout off
set feedback off
alter system set cbo = on;
@@core_adjust_plan_id.sql
alter system set cbo = off;
set termout on
set feedback on