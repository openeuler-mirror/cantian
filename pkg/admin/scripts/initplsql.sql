--01
declare
  sys_procs_cnt int;
  sys_trig_cnt int;
begin
  select count(*) into sys_procs_cnt from SYS.SYS_PROCS where TYPE = 'T';
  select count(*) into sys_trig_cnt from SYS.SYS_TRIGGERS;
  if sys_procs_cnt > 0 and sys_trig_cnt = 0 then
    execute immediate 'ALTER DATABASE UPGRADE PROCEDURE';
  end if;
end;
/

CREATE TABLE IF NOT EXISTS SYS_STATS_LOG
(
  START_TIME     DATE NOT NULL,  --the begin time to collect statistics information
  END_TIME       DATE,   --the end time of collect stat information
  OWNER          VARCHAR(64) NOT NULL, -- table owner
  TABLE_NAME     VARCHAR(64) NOT NULL, 
  PART_NAME      VARCHAR(64),
  OBJ_SIZE       BIGINT NOT NULL,  --segment size of object
  PERCENT        NUMBER(8,5) NOT NULL,  --sampling information ratio
  STATUS         VARCHAR(10) NOT NULL, --BEGIN, FINISHED, ERROR
  ERR_CODE       INT,          --if error, otherwise to be null
  ERR_MSG        VARCHAR(2000) --if error, otherwise to be null
)
PARTITION BY RANGE (START_TIME) INTERVAL(NUMTODSINTERVAL(1,'DAY'))
(PARTITION HISTORY_BASE VALUES LESS THAN(TO_DATE('2020-10-20 0:0:0'))) TABLESPACE SYSAUX
/
CREATE INDEX IF NOT EXISTS SYS_STATS_LOG_IDX ON SYS_STATS_LOG(OWNER, TABLE_NAME, PART_NAME) LOCAL
/

CREATE OR REPLACE PROCEDURE UPDATE_KMC_MASTERKEY() is 
BEGIN
    execute immediate 'alter database update masterkey';
END;
/

CREATE OR REPLACE FUNCTION UPDATE_JOB_RETURN_EXISTS(WHAT_LIKE VARCHAR) RETURN BOOLEAN
IS
 JOBNO NUMBER;
 EXITS_FLAG BOOLEAN := FALSE;
 EXECUTE_DATE DATE;
BEGIN
 FOR ITEM IN (SELECT JOB,BROKEN,THIS_DATE,NEXT_DATE,WHAT,INTERVAL# FROM SYS_JOBS WHERE WHAT like WHAT_LIKE) LOOP
    EXITS_FLAG := TRUE;
    DBE_TASK.CANCEL(ITEM.JOB);
    EXECUTE IMMEDIATE 'SELECT '||ITEM.INTERVAL#||' FROM SYS_DUMMY' INTO EXECUTE_DATE;
    DBE_TASK.SUBMIT(JOBNO,ITEM.WHAT, EXECUTE_DATE, ITEM.INTERVAL#);
    IF (ITEM.BROKEN) THEN
        DBE_TASK.SUSPEND(JOBNO,TRUE);
    END IF;
 END LOOP;
RETURN EXITS_FLAG;
END;
/

DECLARE
 JOBNO NUMBER;
BEGIN
 IF (UPDATE_JOB_RETURN_EXISTS('UPDATE_KMC_MASTERKEY(%);') = FALSE) THEN
    DBE_TASK.SUBMIT(JOBNO,'UPDATE_KMC_MASTERKEY();', TRUNC(SYSDATE+50) + 1/24, 'TRUNC(sysdate+50) +1/24');
    DBE_TASK.SUSPEND(JOBNO,TRUE);
 END IF;
 COMMIT;
END;
/

CREATE OR  REPLACE PROCEDURE GATHER_DB_STATS(
    estimate_percent NUMBER  DEFAULT 10,
    force            BOOLEAN DEFAULT TRUE,
    max_minutes      INTEGER  DEFAULT 360,
    method_opt       VARCHAR DEFAULT 'FOR ALL COLUMNS'
) 
--force false: don't gather when cbo is disable
--max_minutes: default 6 hours
IS
    cbo_enable   VARCHAR(3);
    start_time   DATE;
    curr_time    DATE;
    is_finish    boolean;
    snapshot_too_old  EXCEPTION;                    -- declare exception
    v_table      VARCHAR(130);
    PRAGMA EXCEPTION_INIT (snapshot_too_old, 715);  -- assign error code to exception
BEGIN    
    IF max_minutes < 1 OR max_minutes > 1440 THEN
        THROW_EXCEPTION(-20000, 'max_minutes should between [1, 1440]');
    END IF;    

    --check cbo flag
    IF force = FALSE THEN
        SELECT VALUE INTO cbo_enable FROM SYS.DV_PARAMETERS WHERE NAME='CBO';
        IF UPPER(cbo_enable) = 'OFF' THEN
            RETURN;
        END IF;
    END IF;
    
    start_time := SYSDATE;
    
    --only gather new heap table
    LOOP
        is_finish := false;
        
        BEGIN

        FOR ITEM IN (SELECT OWNER, TABLE_NAME FROM ADM_TABLES WHERE TABLE_TYPE in ('HEAP', 'NOLOGGING') AND LAST_ANALYZED is NULL) 
        LOOP
            curr_time := SYSDATE;
            IF curr_time > (start_time + max_minutes/1440) THEN
                RETURN;
            END IF;
            
            BEGIN
                v_table := '"'||ITEM.TABLE_NAME||'"';
                DBE_STATS.COLLECT_TABLE_STATS(ITEM.OWNER, v_table, null, estimate_percent, TRUE, method_opt);
            EXCEPTION
                WHEN OTHERS THEN
                  NULL;
            END;
        END LOOP;
        
        is_finish := true;
        
        EXCEPTION
          WHEN snapshot_too_old THEN                         -- handle exception
            NULL;
        END;
        
        IF is_finish = true THEN
            EXIT; 
        END IF;
    END LOOP;
    
    --only gather heap table
    LOOP
        is_finish := false;
        
        BEGIN
        FOR ITEM IN (SELECT OWNER, TABLE_NAME,LAST_ANALYZED FROM ADM_TABLES WHERE TABLE_TYPE in ('HEAP', 'NOLOGGING') AND 
                    LAST_ANALYZED < start_time ORDER BY LAST_ANALYZED) 
        LOOP
            curr_time := SYSDATE;
            IF curr_time > (start_time + max_minutes/1440) THEN
                RETURN;
            END IF;
            
            BEGIN
                v_table := '"'||ITEM.TABLE_NAME||'"';
                DBE_STATS.COLLECT_TABLE_STATS(ITEM.OWNER, v_table, null, estimate_percent, TRUE, method_opt);
            EXCEPTION
                WHEN OTHERS THEN
                  NULL;
            END;
        END LOOP;
        
        is_finish := true;
        
        EXCEPTION
          WHEN snapshot_too_old THEN                         -- handle exception
            NULL;
        END;
        
        IF is_finish = true THEN
            EXIT; 
        END IF;
    END LOOP;
END;
/

CREATE GLOBAL TEMPORARY TABLE IF NOT EXISTS ltt_analyze_job1(
    OWNER          VARCHAR(64) NOT NULL,
    TABLE_NAME     VARCHAR(64) NOT NULL
) on commit preserve rows
/

CREATE GLOBAL TEMPORARY TABLE IF NOT EXISTS ltt_analyze_job2(
    OWNER          VARCHAR(64) NOT NULL,
    TABLE_NAME     VARCHAR(64) NOT NULL,
    PARTITION_NAME VARCHAR(64) NOT NULL
) on commit preserve rows
/

CREATE GLOBAL TEMPORARY TABLE IF NOT EXISTS ltt_analyze_job3(
    OWNER          VARCHAR(64) NOT NULL,
    TABLE_NAME     VARCHAR(64) NOT NULL,
    PARTITION_NAME VARCHAR(64) NOT NULL,
    ANALYZETIME    DATE
) on commit preserve rows
/

CREATE GLOBAL TEMPORARY TABLE IF NOT EXISTS ltt_analyze_job4(
    OWNER          VARCHAR(64) NOT NULL,
    TABLE_NAME     VARCHAR(64) NOT NULL,
    ANALYZETIME    TIMESTAMP(6)
) on commit preserve rows
/

CREATE OR  REPLACE PROCEDURE GATHER_CHANGE_STATS(
    estimate_percent NUMBER DEFAULT 10,
    change_percent   NUMBER DEFAULT 10,
    force            BOOLEAN DEFAULT TRUE,
    max_minutes      NUMBER  DEFAULT 60,
    method_opt       VARCHAR DEFAULT 'FOR ALL COLUMNS'
) 
--force false: don't gather when cbo is disable
--max_minutes: default 1 hour
IS
    cbo_enable   VARCHAR(3);
    start_time   DATE;
    curr_time    DATE;
    is_finish    boolean;
    snapshot_too_old  EXCEPTION;                    -- declare exception
    v_table      VARCHAR(130);
    v_part       VARCHAR(130);
    v_owner      VARCHAR(130);
    PRAGMA EXCEPTION_INIT (snapshot_too_old, 715);  -- assign error code to exception
BEGIN
    IF max_minutes < 1 OR max_minutes > 1440 THEN
        THROW_EXCEPTION(-20000, 'max_minutes should between [1, 1440]');
    END IF;    
    
    --check cbo flag
    IF force = FALSE THEN        
        SELECT VALUE INTO cbo_enable FROM SYS.DV_PARAMETERS WHERE NAME='CBO';
        IF UPPER(cbo_enable) = 'OFF' THEN
            RETURN;
        END IF;
    END IF;
        
    start_time := SYSDATE;
    --flush modification to table
    DBE_STATS.FLUSH_DB_STATS_INFO();
    --(1)gather the new table
    insert into ltt_analyze_job1 SELECT OWNER, TABLE_NAME FROM ADM_TABLES WHERE TABLE_TYPE in ('HEAP', 'NOLOGGING') AND LAST_ANALYZED is NULL AND OWNER != 'SYS';
    LOOP
        is_finish := false;
        BEGIN
        FOR ITEM IN (SELECT * FROM ltt_analyze_job1)
        LOOP    
            curr_time := SYSDATE;
            IF curr_time > (start_time + max_minutes/1440) THEN
                RETURN;
            END IF;
                        
            BEGIN
                v_table := '"'||ITEM.TABLE_NAME||'"';
                v_owner := '"'||ITEM.OWNER||'"';
                DBE_STATS.COLLECT_TABLE_STATS(ITEM.OWNER, v_table, NULL, estimate_percent, TRUE, method_opt);
            EXCEPTION
                WHEN OTHERS THEN
                  NULL;
            END;
        END LOOP;
        
        is_finish := true;

        EXCEPTION
            WHEN snapshot_too_old THEN                         -- handle exception
            NULL;
        END;
        
        IF is_finish = true THEN
            EXIT; 
        END IF;
    END LOOP;

    execute immediate 'truncate table ltt_analyze_job1';
    --(2)gather the new partition
    insert into ltt_analyze_job2 SELECT U.NAME AS OWNER, T.NAME AS TABLE_NAME, TP.NAME AS PARTITION_NAME
           FROM SYS.SYS_USERS U JOIN SYS.SYS_TABLES T ON U.ID = T.USER# 
           JOIN SYS.SYS_TABLE_PARTS TP ON T.USER# = TP.USER# AND T.ID = TP.TABLE# AND TP.ANALYZETIME IS NULL AND U.NAME != 'SYS';
    LOOP
        is_finish := false;
        
        BEGIN
        FOR ITEM IN (SELECT * FROM ltt_analyze_job2)
        LOOP    
            curr_time := SYSDATE;
            IF curr_time > (start_time + max_minutes/1440) THEN
                RETURN;
            END IF;
                        
            BEGIN
                v_table := '"'||ITEM.TABLE_NAME||'"';
                v_part  := '"'||ITEM.PARTITION_NAME||'"';
                v_owner := '"'||ITEM.OWNER||'"';
                DBE_STATS.COLLECT_TABLE_STATS(ITEM.OWNER, v_table, v_part, estimate_percent, TRUE, method_opt);
            EXCEPTION
                WHEN OTHERS THEN
                  NULL;
            END;
        END LOOP;

        is_finish := true;

        EXCEPTION
            WHEN snapshot_too_old THEN                         -- handle exception
            NULL;
        END;
        
        IF is_finish = true THEN
            EXIT; 
        END IF;
    END LOOP;

    execute immediate 'truncate table ltt_analyze_job2';
    --(3)gather the partition changed
    insert into ltt_analyze_job3 SELECT U.NAME AS OWNER, T.NAME AS TABLE_NAME, TP.NAME AS PARTITION_NAME, TP.ANALYZETIME
           FROM SYS.SYS_USERS U JOIN SYS.SYS_TABLES T ON U.ID = T.USER#
           JOIN SYS.SYS_TABLE_PARTS TP ON T.USER# = TP.USER# AND T.ID = TP.TABLE#
           JOIN SYS.SYS_DML_STATS MO ON T.USER# = MO.USER# AND T.ID = MO.TABLE# AND MO.PART# = TP.PART# 
           WHERE MO.PARTED = 1 AND MO.PART# <> -1 AND TP.ANALYZETIME < start_time AND U.NAME != 'SYS' AND
           ((NVL(MO.INSERTS, 0) + NVL(MO.UPDATES, 0) + NVL(MO.DELETES, 0))>= (CHANGE_PERCENT * TP.ROWCNT/100))
           ORDER BY TP.ANALYZETIME;
    LOOP
        is_finish := false;
        
        BEGIN
        FOR ITEM IN (select * from ltt_analyze_job3)
        LOOP    
            curr_time := SYSDATE;
            IF curr_time > (start_time + max_minutes/1440) THEN
                RETURN;
            END IF;
                        
            BEGIN
                v_table := '"'||ITEM.TABLE_NAME||'"';
                v_part  := '"'||ITEM.PARTITION_NAME||'"';
                v_owner := '"'||ITEM.OWNER||'"';
                DBE_STATS.COLLECT_TABLE_STATS(ITEM.OWNER, v_table, v_part, estimate_percent, TRUE, method_opt);
            EXCEPTION
                WHEN OTHERS THEN
                  NULL;
            END;
        END LOOP;
        
        is_finish := true;

        EXCEPTION
            WHEN snapshot_too_old THEN                         -- handle exception
            NULL;
        END;
        
        IF is_finish = true THEN
            EXIT; 
        END IF;
    END LOOP;

    execute immediate 'truncate table ltt_analyze_job3';
    --(4)gather the table changed
    insert into ltt_analyze_job4 SELECT U.NAME AS OWNER, T.NAME AS TABLE_NAME, T.ANALYZETIME FROM SYS.SYS_USERS U join SYS.SYS_TABLES T on T.USER# = U.ID
            JOIN SYS.SYS_DML_STATS MO ON T.USER# = MO.USER# AND T.ID = MO.TABLE# where T.RECYCLED = 0 AND T.type = 0 AND
            (MO.PARTED = 0 OR (MO.PARTED = 1 AND MO.PART#=-1)) AND T.ANALYZETIME < start_time AND U.NAME != 'SYS' AND
            ((NVL(MO.INSERTS, 0) + NVL(MO.UPDATES, 0) + NVL(MO.DELETES, 0))>= (CHANGE_PERCENT * T.NUM_ROWS/100))
            ORDER BY T.ANALYZETIME;
    LOOP
        is_finish := false;
        
        BEGIN
        FOR ITEM IN (select * from ltt_analyze_job4)
        LOOP    
            curr_time := SYSDATE;
            IF curr_time > (start_time + max_minutes/1440) THEN
                RETURN;
            END IF;
                        
            BEGIN
                v_table := '"'||ITEM.TABLE_NAME||'"';
                v_owner := '"'||ITEM.OWNER||'"';
                DBE_STATS.COLLECT_TABLE_STATS(ITEM.OWNER, v_table, NULL, estimate_percent, TRUE, method_opt);
            EXCEPTION
                WHEN OTHERS THEN
                  NULL;
            END;
        END LOOP;
    
        is_finish := true;

        EXCEPTION
            WHEN snapshot_too_old THEN                         -- handle exception
            NULL;
        END;
        
        IF is_finish = true THEN
            EXIT; 
        END IF;
    END LOOP;
    execute immediate 'truncate table ltt_analyze_job4';
END;
/

CREATE OR REPLACE PROCEDURE DB_STATS_BEGIN_RECORD(OWNER VARCHAR, TABLE_NAME VARCHAR, PART_NAME VARCHAR, OBJSIZE bigint, START_TIME DATE, PERCENT NUMBER)
IS
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
    INSERT INTO SYS_STATS_LOG VALUES(START_TIME, NULL, OWNER, TABLE_NAME, PART_NAME, OBJSIZE, PERCENT, 'BEGIN', NULL, NULL);
    commit;
END;
/

CREATE OR REPLACE PROCEDURE DB_STATS_END_RECORD(IN_OWNER VARCHAR, IN_TABLE_NAME VARCHAR, IN_PART_NAME VARCHAR, IN_START_TIME DATE, IERRCODE INT, IERRMSG VARCHAR)
IS
INNER_STATUS VARCHAR(10) := 'FINISHED';
BEGIN
IF (IERRCODE IS NOT NULL) THEN
INNER_STATUS := 'ERROR';
END IF;
IF IN_PART_NAME IS NOT NULL THEN
    UPDATE /*+INDEX(SYS_STATS_LOG SYS_STATS_LOG_IDX)*/ SYS_STATS_LOG SET END_TIME = SYSDATE, STATUS=INNER_STATUS, ERR_CODE=IERRCODE, ERR_MSG=IERRMSG WHERE START_TIME = IN_START_TIME AND OWNER=IN_OWNER AND TABLE_NAME = IN_TABLE_NAME AND PART_NAME=IN_PART_NAME;
ELSE 
    UPDATE /*+INDEX(SYS_STATS_LOG SYS_STATS_LOG_IDX)*/ SYS_STATS_LOG SET END_TIME = SYSDATE, STATUS=INNER_STATUS, ERR_CODE=IERRCODE, ERR_MSG=IERRMSG WHERE START_TIME = IN_START_TIME AND OWNER=IN_OWNER AND TABLE_NAME = IN_TABLE_NAME AND PART_NAME IS NULL;
END IF;
END;
/

CREATE OR REPLACE PROCEDURE DB_STATS_LOG_DELETE_OLD(SAVE_DAYS INT)
IS
SQL_DROP VARCHAR(128);
BEGIN
    FOR ITEM IN (SELECT TP.NAME,HIBOUNDVAL FROM SYS_TABLE_PARTS TP, SYS_TABLES T WHERE TP.TABLE#=T.ID AND TP.USER#=T.USER# AND T.NAME='SYS_STATS_LOG' AND TP.NAME != 'HISTORY_BASE') LOOP
        IF TO_DATE(ITEM.HIBOUNDVAL) < SYSDATE - SAVE_DAYS THEN 
            SQL_DROP := 'ALTER TABLE SYS_STATS_LOG DROP PARTITION '||ITEM.NAME;
            EXECUTE IMMEDIATE SQL_DROP;
        END IF;
    END LOOP;
END;
/

CREATE OR REPLACE PROCEDURE GATHER_DB_STATS_PART_TAB_PROC(ESTIMATE_PERCENT NUMBER, METHOD_OPT VARCHAR, MAX_PART_SIZE BIGINT, MAX_TABLE_SIZE BIGINT, OWNER VARCHAR, TABLE_NAME VARCHAR, PART_NAME VARCHAR)
IS 
OBJ_SIZE BIGINT;
RES_PERCENT NUMBER := ESTIMATE_PERCENT;
STAT_START_TIME date;
V_TABLE VARCHAR(130) := '"'||TABLE_NAME||'"';
V_PART VARCHAR(130) := '"'||PART_NAME||'"';
IS_ANALYZED INT;
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
SELECT COUNT(*) INTO IS_ANALYZED FROM SYS_TABLES T, SYS_USERS U WHERE T.ANALYZETIME IS NOT NULL AND T.NAME =TABLE_NAME AND T.USER#=U.ID AND U.NAME=OWNER;
IF (IS_ANALYZED = 0) THEN
    OBJ_SIZE := DBE_DIAGNOSE.DBA_PARTITIONED_TABSIZE(0, OWNER, V_TABLE);
    IF (OBJ_SIZE * ESTIMATE_PERCENT / 100 > MAX_TABLE_SIZE) THEN
        RES_PERCENT := TO_NUMBER(MAX_TABLE_SIZE)*100 / OBJ_SIZE;
    END IF;
ELSE 
    OBJ_SIZE := DBE_DIAGNOSE.DBA_TABLE_PARTSIZE(0, OWNER, V_TABLE, V_PART); 
    IF (OBJ_SIZE * ESTIMATE_PERCENT / 100 > MAX_PART_SIZE) THEN
        RES_PERCENT := TO_NUMBER(MAX_PART_SIZE)*100 / OBJ_SIZE;
    END IF;
END IF;
STAT_START_TIME := SYSDATE;
DB_STATS_BEGIN_RECORD(OWNER, TABLE_NAME, PART_NAME, OBJ_SIZE, STAT_START_TIME, RES_PERCENT);
DBE_STATS.COLLECT_TABLE_STATS(OWNER, V_TABLE, V_PART, RES_PERCENT, TRUE, METHOD_OPT);
DB_STATS_END_RECORD(OWNER, TABLE_NAME, PART_NAME, STAT_START_TIME, NULL, NULL);
COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        DB_STATS_END_RECORD(OWNER, TABLE_NAME, PART_NAME, STAT_START_TIME, SQL_ERR_CODE(), LEFT(SQL_ERR_MSG(), 2000));
        COMMIT;
END;
/

CREATE OR REPLACE PROCEDURE GATHER_DB_STATS_TAB_PROC(ESTIMATE_PERCENT NUMBER, METHOD_OPT VARCHAR, MAX_SIZE BIGINT, OWNER VARCHAR, TABLE_NAME VARCHAR, OBJ_SIZE BIGINT)
IS 
RES_PERCENT NUMBER := ESTIMATE_PERCENT;
STAT_START_TIME date;
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
IF (OBJ_SIZE * ESTIMATE_PERCENT / 100 > MAX_SIZE) THEN
    RES_PERCENT := TO_NUMBER(MAX_SIZE)*100 / OBJ_SIZE;
END IF;
STAT_START_TIME := SYSDATE;
DB_STATS_BEGIN_RECORD(OWNER, TABLE_NAME, NULL, OBJ_SIZE, STAT_START_TIME, RES_PERCENT);
DBE_STATS.COLLECT_TABLE_STATS(OWNER, '"'||TABLE_NAME||'"', NULL, RES_PERCENT, TRUE, METHOD_OPT);
DB_STATS_END_RECORD(OWNER, TABLE_NAME, NULL, STAT_START_TIME, NULL, NULL);
COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        DB_STATS_END_RECORD(OWNER, TABLE_NAME, NULL, STAT_START_TIME, SQL_ERR_CODE(), LEFT(SQL_ERR_MSG(), 2000));
        COMMIT;
END;
/


CREATE OR REPLACE PROCEDURE GATHER_DB_STATS_INDEX(ESTIMATE_PERCENT NUMBER, MAX_SIZE BIGINT, OWNER VARCHAR, TABLE_NAME VARCHAR, INDEX_NAME VARCHAR)
IS 
RES_PERCENT NUMBER := ESTIMATE_PERCENT;
OBJ_SIZE BIGINT := DBE_DIAGNOSE.DBA_INDEX_SIZE(0, OWNER, '"'||TABLE_NAME||'"', '"'||INDEX_NAME||'"');
STAT_START_TIME DATE;
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
IF (OBJ_SIZE * ESTIMATE_PERCENT / 100 > MAX_SIZE) THEN
    RES_PERCENT := TO_NUMBER(MAX_SIZE)*100 / OBJ_SIZE;
END IF;
STAT_START_TIME := SYSDATE;
DB_STATS_BEGIN_RECORD(OWNER, TABLE_NAME, NULL, OBJ_SIZE, STAT_START_TIME, RES_PERCENT);
DBE_STATS.COLLECT_INDEX_STATS(OWNER, '"'||INDEX_NAME||'"', TABLE_NAME, RES_PERCENT);
DB_STATS_END_RECORD(OWNER, TABLE_NAME, NULL, STAT_START_TIME, NULL, NULL);
COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        DB_STATS_END_RECORD(OWNER, TABLE_NAME, NULL, STAT_START_TIME, SQL_ERR_CODE(), LEFT(SQL_ERR_MSG(), 2000));
        COMMIT;
END;
/


CREATE OR REPLACE PROCEDURE GATHER_DB_STATS_EX(
    ESTIMATE_PERCENT NUMBER DEFAULT 10,
    CHANGE_PERCENT   NUMBER DEFAULT 10, 
    FORCE            BOOLEAN DEFAULT FALSE,
    MAX_MINUTES      INTEGER  DEFAULT 360,
    METHOD_OPT       VARCHAR DEFAULT 'FOR ALL COLUMNS',
    MAX_PART_SIZE    BIGINT DEFAULT 1024*1024*1024,
    MAX_TABLE_SIZE   BIGINT DEFAULT 4096*1024*1024,
    SAVE_DAYS        INTEGER DEFAULT 7 
)
IS
    CBO_ENABLE   VARCHAR(3);
    START_TIME   DATE;
    CURR_TIME    DATE;
    IS_FINISH    BOOLEAN;
    ALCK_RET          BINARY_INTEGER;
    SNAPSHOT_TOO_OLD  EXCEPTION;                    -- DECLARE EXCEPTION
    PRAGMA EXCEPTION_INIT (SNAPSHOT_TOO_OLD, 715);  -- ASSIGN ERROR CODE TO EXCEPTION
    PARAMETER_ERR  EXCEPTION;
    PRAGMA EXCEPTION_INIT (PARAMETER_ERR, -20000);
BEGIN
    IF MAX_MINUTES < 1 OR MAX_MINUTES > 1440 THEN
        THROW_EXCEPTION(-20000, 'max_minutes should between [1, 1440]');
    END IF;
    IF ESTIMATE_PERCENT <= 0 OR ESTIMATE_PERCENT > 100 THEN
        THROW_EXCEPTION(-20000, 'ESTIMATE_PERCENT should between (0, 100]');
    END IF;
    IF CHANGE_PERCENT <= 0 OR CHANGE_PERCENT > 100 THEN
        THROW_EXCEPTION(-20000, 'CHANGE_PERCENT should between (0, 100]');
    END IF;
    IF MAX_PART_SIZE <= 0 THEN
        THROW_EXCEPTION(-20000, 'MAX_PART_SIZE should bigger than 0');
    END IF;
    IF MAX_TABLE_SIZE <= 0 THEN
        THROW_EXCEPTION(-20000, 'MAX_TABLE_SIZE should bigger than 0');
    END IF;
    IF (GET_LOCK('SYS.GATHER_DB_STATS_EX') <> 1) THEN
        RETURN;
    END IF;
    START_TIME := SYSDATE;
    DB_STATS_LOG_DELETE_OLD(save_days);
    --check cbo flag
    IF FORCE = FALSE THEN
        SELECT VALUE INTO CBO_ENABLE FROM SYS.DV_PARAMETERS WHERE NAME='CBO';
        IF UPPER(CBO_ENABLE) = 'OFF' THEN
            ALCK_RET := RELEASE_LOCK('SYS.GATHER_DB_STATS_EX');
            RETURN;
        END IF;
    END IF; 

    --flush modification to table
    DBE_STATS.FLUSH_DB_STATS_INFO();
    
    --(1) gather index when:
           -- 1.1 global part table if DMLs changed
           -- 1.2 index stats is null, fix creating new index
    LOOP
       IS_FINISH := FALSE;
       BEGIN
           FOR ITEM IN (SELECT U.NAME AS OWNER, T.NAME AS TABLE_NAME, I.NAME AS INDEX_NAME FROM SYS_INDEXES I
                        JOIN SYS.SYS_USERS U ON I.FLAGS & 6 = 0 AND I.USER# = U.ID
                        JOIN SYS.SYS_TABLES T ON T.ID = I.TABLE# AND T.USER# = I.USER#
                        JOIN SYS.SYS_DML_STATS MO ON MO.USER# = I.USER# AND MO.TABLE# = I.TABLE#
                        WHERE I.PARTITIONED = 0 AND T.PARTITIONED=1 AND MO.PART# = -1 AND ((NVL(MO.INSERTS, 0) + NVL(MO.UPDATES, 0) + NVL(MO.DELETES, 0))>= (CHANGE_PERCENT * T.NUM_ROWS/100))
                        UNION 
                        SELECT U.NAME AS OWNER, T.NAME AS TABLE_NAME, I.NAME AS INDEX_NAME FROM SYS_INDEXES I
                        JOIN SYS.SYS_USERS U ON  I.FLAGS & 6 = 0 AND I.ANALYZETIME IS NULL AND I.USER# = U.ID
                        JOIN SYS.SYS_TABLES T ON T.ID = I.TABLE# AND T.USER# = I.USER#)
           LOOP
                CURR_TIME := SYSDATE;
                IF CURR_TIME > (START_TIME + MAX_MINUTES/1440) THEN
                    ALCK_RET := RELEASE_LOCK('SYS.GATHER_DB_STATS_EX');
                    RETURN;
                END IF;
                BEGIN
                    GATHER_DB_STATS_INDEX(ESTIMATE_PERCENT, MAX_TABLE_SIZE, ITEM.OWNER, ITEM.TABLE_NAME, ITEM.INDEX_NAME);
                EXCEPTION
                    WHEN OTHERS THEN
                      NULL;
                END;
            END LOOP;
            IS_FINISH := TRUE;
        EXCEPTION
            WHEN SNAPSHOT_TOO_OLD THEN
            NULL;
        END;
        IF IS_FINISH = TRUE THEN
            EXIT; 
        END IF;
    END LOOP;

    --(2) gather the new partition or turncated partition
    LOOP
        IS_FINISH := FALSE;
        BEGIN
            FOR ITEM IN (SELECT U.NAME AS OWNER, T.NAME AS TABLE_NAME, TP.NAME AS PARTITION_NAME
               FROM SYS.SYS_USERS U JOIN SYS.SYS_TABLES T ON U.ID = T.USER# AND T.RECYCLED = 0
               JOIN SYS.SYS_TABLE_PARTS TP ON T.USER# = TP.USER# AND T.ID = TP.TABLE# AND (TP.ANALYZETIME IS NULL OR (TP.ROWCNT * CHANGE_PERCENT > 100 * DBE_DIAGNOSE.DBA_TABLE_PARTSIZE(0, U.NAME, '"'||T.NAME||'"', '"'||TP.NAME||'"') / DECODE(TP.AVGRLN, NULL, 1, 0, 1, TP.AVGRLN))))
            LOOP    
                CURR_TIME := SYSDATE;
                IF CURR_TIME > (START_TIME + MAX_MINUTES/1440) THEN
                    ALCK_RET := RELEASE_LOCK('SYS.GATHER_DB_STATS_EX');
                    RETURN;
                END IF;
                BEGIN
                    GATHER_DB_STATS_PART_TAB_PROC(ESTIMATE_PERCENT, METHOD_OPT, MAX_PART_SIZE, MAX_TABLE_SIZE, ITEM.OWNER, ITEM.TABLE_NAME, ITEM.PARTITION_NAME);
                EXCEPTION
                    WHEN OTHERS THEN
                      NULL;
                END;
            END LOOP;
            IS_FINISH := TRUE;
        EXCEPTION
            WHEN SNAPSHOT_TOO_OLD THEN
            NULL;
        END;
        IF IS_FINISH = TRUE THEN
            EXIT; 
        END IF;
    END LOOP;
    
    --(3)gather the partition changed if DMLs changed
    LOOP
        IS_FINISH := FALSE;
        BEGIN
            FOR ITEM IN (SELECT U.NAME AS OWNER, T.NAME AS TABLE_NAME, TP.NAME AS PARTITION_NAME, TP.ANALYZETIME
               FROM SYS.SYS_USERS U JOIN SYS.SYS_TABLES T ON U.ID = T.USER# 
               JOIN SYS.SYS_TABLE_PARTS TP ON T.USER# = TP.USER# AND T.ID = TP.TABLE#
               JOIN SYS.SYS_DML_STATS MO ON T.USER# = MO.USER# AND T.ID = MO.TABLE# AND MO.PART# = TP.PART# 
               WHERE MO.PARTED = 1 AND MO.PART# <> -1 AND TP.ANALYZETIME < START_TIME AND
               ((NVL(MO.INSERTS, 0) + NVL(MO.UPDATES, 0) + NVL(MO.DELETES, 0))>= (CHANGE_PERCENT * TP.ROWCNT/100))
               ORDER BY TP.ANALYZETIME) 
            LOOP    
                CURR_TIME := SYSDATE;
                IF CURR_TIME > (START_TIME + MAX_MINUTES/1440) THEN
                    ALCK_RET := RELEASE_LOCK('SYS.GATHER_DB_STATS_EX');
                    RETURN;
                END IF;
                BEGIN
                    GATHER_DB_STATS_PART_TAB_PROC(ESTIMATE_PERCENT, METHOD_OPT, MAX_PART_SIZE, MAX_TABLE_SIZE, ITEM.OWNER, ITEM.TABLE_NAME, ITEM.PARTITION_NAME);
                EXCEPTION
                    WHEN OTHERS THEN
                      NULL;
                END;
            END LOOP;
            IS_FINISH := TRUE;
        EXCEPTION
            WHEN SNAPSHOT_TOO_OLD THEN
            NULL;
        END;
        IF IS_FINISH = TRUE THEN
            EXIT; 
        END IF;
    END LOOP;

    --(4)gather the new table or truncated table
    LOOP
        IS_FINISH := FALSE;
        
        BEGIN
            FOR ITEM IN (SELECT OWNER, TABLE_NAME, BYTES FROM ADM_TABLES WHERE TABLE_TYPE IN ('HEAP', 'NOLOGGING') AND (LAST_ANALYZED IS NULL OR (NUM_ROWS * CHANGE_PERCENT > 100 * BYTES / DECODE(AVG_ROW_LEN, NULL, 1, 0, 1, AVG_ROW_LEN))))
            LOOP    
                CURR_TIME := SYSDATE;
                IF CURR_TIME > (START_TIME + MAX_MINUTES/1440) THEN
                    ALCK_RET := RELEASE_LOCK('SYS.GATHER_DB_STATS_EX');
                    RETURN;
                END IF;
                BEGIN
                    GATHER_DB_STATS_TAB_PROC(ESTIMATE_PERCENT, METHOD_OPT, MAX_TABLE_SIZE, ITEM.OWNER, ITEM.TABLE_NAME, ITEM.BYTES);
                EXCEPTION
                    WHEN OTHERS THEN
                      NULL;
                END;
            END LOOP;
            IS_FINISH := TRUE;
        EXCEPTION
            WHEN SNAPSHOT_TOO_OLD THEN 
            NULL;
        END;
        IF IS_FINISH = TRUE THEN
            EXIT; 
        END IF;
    END LOOP;
    
    --(5)gather the table changed if DMLs changed
    LOOP
        IS_FINISH := FALSE;
        BEGIN
            FOR ITEM IN (SELECT A.OWNER, A.TABLE_NAME, A.LAST_ANALYZED, A.BYTES FROM ADM_TABLES A, ADM_TAB_MODIFICATIONS B 
            WHERE A.TABLE_TYPE IN ('HEAP', 'NOLOGGING') AND A.OWNER = B.TABLE_OWNER AND A.TABLE_NAME=B.TABLE_NAME 
            AND B.PARTITION_NAME IS NULL AND A.LAST_ANALYZED < START_TIME AND
                ((NVL(B.INSERTS, 0) + NVL(B.UPDATES, 0) + NVL(B.DELETES, 0))>= (CHANGE_PERCENT * A.NUM_ROWS/100))
                ORDER BY A.LAST_ANALYZED) 
            LOOP    
                CURR_TIME := SYSDATE;
                IF CURR_TIME > (START_TIME + MAX_MINUTES/1440) THEN
                    ALCK_RET := RELEASE_LOCK('SYS.GATHER_DB_STATS_EX');
                    RETURN;
                END IF;
                BEGIN
                    GATHER_DB_STATS_TAB_PROC(ESTIMATE_PERCENT, METHOD_OPT, MAX_TABLE_SIZE, ITEM.OWNER, ITEM.TABLE_NAME, ITEM.BYTES);
                EXCEPTION
                    WHEN OTHERS THEN
                      NULL;
                END;
            END LOOP;
            IS_FINISH := TRUE;
        EXCEPTION
            WHEN SNAPSHOT_TOO_OLD THEN
            NULL;
        END;
        IF IS_FINISH = TRUE THEN
            EXIT; 
        END IF;
    END LOOP;
    ALCK_RET := RELEASE_LOCK('SYS.GATHER_DB_STATS_EX');
    EXCEPTION
        WHEN PARAMETER_ERR THEN
            RAISE;
        WHEN OTHERS THEN
            ALCK_RET := RELEASE_LOCK('SYS.GATHER_DB_STATS_EX');
            INSERT INTO SYS_STATS_LOG VALUES(START_TIME, SYSDATE, '-', '-', '-', 0, 0, 'ERROR', SQL_ERR_CODE(), LEFT(SQL_ERR_MSG(), 2000));
            COMMIT;
END;
/


DECLARE
 JOBNO NUMBER;
BEGIN
 IF(UPDATE_JOB_RETURN_EXISTS('GATHER_DB_STATS(%);') = FALSE) THEN
    DBE_TASK.SUBMIT(JOBNO,'GATHER_DB_STATS(estimate_percent=>10, force=>FALSE);', TRUNC(SYSDATE+1) + 1/24, 'TRUNC(sysdate+1) +1/24');
    DBE_TASK.SUSPEND(JOBNO,true);
 END IF;
 COMMIT;
END;
/

DECLARE
 JOBNO NUMBER;
BEGIN
 IF(UPDATE_JOB_RETURN_EXISTS('GATHER_CHANGE_STATS(%);') = FALSE) THEN
     DBE_TASK.SUBMIT(JOBNO,'GATHER_CHANGE_STATS(estimate_percent=>10, change_percent=>25, force=>FALSE);', SYSDATE, 'SYSDATE+60/24/60');
 END IF;
 COMMIT;
END;
/

DECLARE
 JOBNO NUMBER;
 IS_BROKEN INT := 1;
BEGIN
--remove wrong arguments
FOR ITEM IN (SELECT JOB,BROKEN FROM SYS_JOBS WHERE WHAT LIKE 'GATHER_DB_STATS_EX(%MAX_SIZE=>2048*1024*1024);') LOOP
    DBE_TASK.CANCEL(ITEM.JOB);
    IS_BROKEN := ITEM.BROKEN;
END LOOP;
 IF(UPDATE_JOB_RETURN_EXISTS('GATHER_DB_STATS_EX(%);') = FALSE) THEN
     DBE_TASK.SUBMIT(JOBNO,'GATHER_DB_STATS_EX(estimate_percent=>10, change_percent=>10, force=>FALSE);', TRUNC(SYSDATE+1) + 1/24, 'TRUNC(sysdate+1) +1/24');
     IF (IS_BROKEN = 1) THEN
        DBE_TASK.SUSPEND(JOBNO,true);
     END IF;
 END IF;
 COMMIT;
END;
/

CREATE OR REPLACE PROCEDURE AUD$CLEAN_AUD_LOG(SUB_DATE INT DEFAULT 3)
IS
BEGIN
    IF SUB_DATE < 0 OR SUB_DATE > 100 THEN
        THROW_EXCEPTION(-20000, 'argrument should between [0, 100]');
    END IF;
    DELETE FROM SYS_AUDIT WHERE SYSDATE-SUB_DATE >= TO_DATE(RIGHT(CTIME, LENGTH(CTIME) - LOCATE(' ', CTIME)),'YYYY-MM-DD HH24:MI:SS.FF3');
    COMMIT;
END;
/

DECLARE
     I_L_JOBNO BINARY_INTEGER;
BEGIN
    IF (UPDATE_JOB_RETURN_EXISTS('AUD$CLEAN_AUD_LOG(%);') = FALSE) THEN
       DBE_TASK.SUBMIT(I_L_JOBNO, 'AUD$CLEAN_AUD_LOG();', TRUNC(SYSDATE) + 1, 'TRUNC(SYSDATE) + 1');
    END IF;
    COMMIT;
END;
/
--02
CREATE OR REPLACE PROCEDURE AUD$MODIFY_SETTING (SET_DAY  INT DEFAULT NULL, NEXT_TIME  INT DEFAULT NULL)
AS
       I_L_JOBNO BINARY_INTEGER;
       JOBWHAT VARCHAR(4000);
       NEXTTIME VARCHAR(4000);
BEGIN
    IF SET_DAY < 0 OR SET_DAY > 100 OR NEXT_TIME <= 0 THEN
        THROW_EXCEPTION(-20000, 'argrument1 should between [0, 100], argrument2 should be positive');
    END IF;
    FOR ITEM IN (
              SELECT JOB 
                FROM MY_JOBS
               WHERE WHAT like 'AUD$CLEAN_AUD_LOG(%);') LOOP
        DBE_TASK.CANCEL(ITEM.JOB);
        COMMIT;        
    END LOOP;    
    IF SET_DAY IS NULL THEN
        DBE_TASK.SUBMIT(I_L_JOBNO, 'AUD$CLEAN_AUD_LOG();', TRUNC(SYSDATE) + 1, 'TRUNC(SYSDATE) + 1');
        COMMIT;
    ELSE
        JOBWHAT := CONCAT('AUD$CLEAN_AUD_LOG(',SET_DAY, ');');
        IF NEXT_TIME IS NULL THEN
            NEXTTIME :=  'SYSDATE + '|| '1';
        ELSE
            NEXTTIME :=  'SYSDATE + ' || NEXT_TIME || '/86400';
        END IF;    
        DBE_TASK.SUBMIT(I_L_JOBNO, JOBWHAT, SYSDATE, NEXTTIME);
        COMMIT;
    END IF;
END;
/
--03
CREATE OR REPLACE FUNCTION check_global_view_param(view_name IN VARCHAR) RETURN BOOLEAN 
is
name varchar(8000);
result boolean := false;
begin
    name := upper(view_name);
    CASE name
    WHEN 'DV_BUFFER_POOLS'          then result := true;
    WHEN 'DV_HA_SYNC_INFO'          then result := true;
    WHEN 'DV_DATA_FILES'            then result := true;
    WHEN 'DV_TABLESPACES'           then result := true;
    WHEN 'DV_PARAMETERS'            then result := true;
    WHEN 'DV_GMA_STATS'             then result := true;
    WHEN 'DV_SYS_STATS'             then result := true;
    WHEN 'DV_LOG_FILES'             then result := true;
    WHEN 'DV_GLOBAL_TRANSACTIONS'   then result := true;
    WHEN 'SYS_PENDING_DIST_TRANS'   then result := true;
    WHEN 'SYS_PENDING_TRANS'        then result := true;
    WHEN 'ADM_TABLESPACES'          then result := true;
    WHEN 'ADM_TABLES'               then result := true;
    WHEN 'ADM_TAB_MODIFICATIONS'    then result := true;
    WHEN 'MY_TABLES'                then result := true;
    WHEN 'MY_INDEXES'               then result := true;
    WHEN 'MY_TAB_MODIFICATIONS'     then result := true;
    ELSE result := false;
    END CASE;
    RETURN result;
    exception
     when others then
     dbe_output.print_line('check global view param failed, ' || sql_err_msg);
end;
/

CREATE OR  REPLACE PROCEDURE create_global_view(view_name IN VARCHAR)
is
  sql varchar(10240);
  sql_create_obj varchar(2048);
  sql_col_type_list varchar(2048);
  sql_col_list varchar(2048);
  sql_col_list_ varchar(2048);
  sql_get_cols varchar(2048);
  sql_get_cols_2 varchar(2048);
  TYPE i_cursor_type IS REF CURSOR;
  my_cursor i_cursor_type;
  COLUMN_NAME varchar(128);
  COLUMN_NAME_ varchar(128);
  DATA_TYPE varchar(66);
  DATA_LENGTH BINARY_INTEGER;
  schema varchar(66);
  param_err EXCEPTION;
begin
  if check_global_view_param(view_name) != true then
    RAISE param_err;
  end if;

  schema := 'SYS';
  sql := 'create type if not exists ' || schema || '.O_GVIEW_GROUP_ID_NAME is object (GROUP_ID BINARY_INTEGER, NODE_NAME VARCHAR(128 BYTE)); /';
  dbe_output.print_line(sql);
  EXECUTE IMMEDIATE sql;
  sql := 'create type if not exists ' || schema || '.T_GVIEW_GROUP_ID_NAME is table of O_GVIEW_GROUP_ID_NAME; /';
  dbe_output.print_line(sql);
  EXECUTE IMMEDIATE sql;
  sql := 'drop type if exists ' || schema || '.T_GVIEW_' || view_name;
  dbe_output.print_line(sql);
  EXECUTE IMMEDIATE sql;
  sql := 'drop type if exists ' || schema || '.O_GVIEW_' || view_name;
  dbe_output.print_line(sql);
  EXECUTE IMMEDIATE sql;

  sql_get_cols := 'select if(COLUMN_NAME = ''COLUMNS'' or COLUMN_NAME = ''TEMPORARY'' or COLUMN_NAME = ''APPENDONLY'' or COLUMN_NAME = ''TIMESTAMP'' or COLUMN_NAME = ''TYPE'' or COLUMN_NAME = ''RANGE'' or COLUMN_NAME = ''LOGGING'' or COLUMN_NAME = ''IS_PRIMARY'', COLUMN_NAME || ''_'' , COLUMN_NAME) as COLUMN_NAME_,COLUMN_NAME,DATA_TYPE,DATA_LENGTH from DB_VIEW_COLUMNS where OWNER = ''' || schema || ''' and VIEW_NAME = ''' || view_name || '''';

  sql_get_cols_2 := 'select c.NAME as COLUMN_NAME_, c.NAME as COLUMN_NAME ,decode(c.DATATYPE, 20001, ''BINARY_INTEGER'', 20002, ''BINARY_BIGINT'', 20007, ''TIMESTAMP'', 20009, ''VARCHAR'', 20011, ''BINARY'', 20014, ''BLOB'', ''other'') as DATA_TYPE ,c.BYTES as DATA_LENGTH from SYS.SYS_USERS u, SYS.SYS_TABLES t, SYS.SYS_COLUMNS c  where u.NAME = ''' || schema || ''' and t.NAME = ''' || view_name || ''' and c.TABLE# = t.ID and t.USER# = u.ID and c.USER# = u.ID';
  sql_create_obj := 'create or replace type ' || schema || '.O_GVIEW_' || view_name || ' is object ( GROUP_ID BINARY_INTEGER , NODE_NAME VARCHAR(128)';
  if (view_name = 'SYS_PENDING_DIST_TRANS' or view_name = 'SYS_PENDING_TRANS') then
    sql_get_cols := sql_get_cols_2;
  end if;
  dbe_output.print_line(sql_get_cols);
  OPEN my_cursor FOR sql_get_cols;
  loop
    FETCH my_cursor INTO COLUMN_NAME_,COLUMN_NAME,DATA_TYPE,DATA_LENGTH;

    EXIT WHEN my_cursor%NOTFOUND;
	
	if (DATA_TYPE = 'VARCHAR' or DATA_TYPE = 'CHAR' or DATA_TYPE = 'BINARY') then
	  sql_create_obj := sql_create_obj || ' , ' || COLUMN_NAME_ || ' ' || DATA_TYPE || '(' || DATA_LENGTH || ')';
	  sql_col_type_list := sql_col_type_list || '' || COLUMN_NAME_ || ' ' || DATA_TYPE || '(' || DATA_LENGTH || ');';
	else
	  sql_create_obj := sql_create_obj || ' , ' || COLUMN_NAME_ || ' ' || DATA_TYPE;
	  sql_col_type_list := sql_col_type_list || '' || COLUMN_NAME_ || ' ' || DATA_TYPE || ';';
	end if;
	sql_col_list := sql_col_list || ' , ' || COLUMN_NAME;
	sql_col_list_ := sql_col_list_ || ' , ' || COLUMN_NAME_;

  end loop;
  sql_create_obj := sql_create_obj || ' ); /';
  dbe_output.print_line(sql_create_obj);
  dbe_output.print_line(sql_col_type_list);
  dbe_output.print_line(sql_col_list);
  
  EXECUTE IMMEDIATE sql_create_obj;
  sql := 'create or replace type ' || schema || '.T_GVIEW_' || view_name || ' is table of O_GVIEW_' || view_name || '; /';
  dbe_output.print_line(sql);
  EXECUTE IMMEDIATE sql;

  sql := 'create or replace function ' || schema || '.F_GET_G' || view_name || ' return T_GVIEW_' || view_name || chr(10) || chr(13) ||
'  is' || chr(10) || chr(13) ||
'   l_' || view_name || '_tab T_GVIEW_' || view_name || ' ;' || chr(10) || chr(13) ||
'   ' || sql_col_type_list || chr(10) || chr(13) ||

'   n integer := 0;' || chr(10) || chr(13) ||
'   m integer := 0;' || chr(10) || chr(13) ||
'   route_str VARCHAR2(256);' || chr(10) || chr(13) ||
'   group_id_tmp BINARY_INTEGER := 0;' || chr(10) || chr(13) ||
'   NODE_NAME_tmp VARCHAR(128);' || chr(10) || chr(13) ||
'   sql VARCHAR2(2048);' || chr(10) || chr(13) ||
'   l_group_id_name_tab T_GVIEW_GROUP_ID_NAME;' || chr(10) || chr(13) ||
'   TYPE i_cursor_type IS REF CURSOR;' || chr(10) || chr(13) ||
'   my_cursor i_cursor_type;' || chr(10) || chr(13) ||

'   begin' || chr(10) || chr(13) ||
'   l_' || view_name || '_tab := T_GVIEW_' || view_name || '();' || chr(10) || chr(13) ||
'   l_group_id_name_tab := T_GVIEW_GROUP_ID_NAME();' || chr(10) || chr(13) ||
'   FOR ITEM IN (select GROUP_ID,NODE_NAME from SYS.SYS_DATA_NODES where NODE_TYPE = ''DATANODE'' and IS_PRIMARY = 1)' || chr(10) || chr(13) ||
'   loop' || chr(10) || chr(13) ||
'      l_group_id_name_tab.extend;' || chr(10) || chr(13) ||
'      m := m + 1;      ' || chr(10) || chr(13) ||
'      l_group_id_name_tab(m) := O_GVIEW_GROUP_ID_NAME(ITEM.GROUP_ID, ITEM.NODE_NAME);' || chr(10) || chr(13) ||
'   end loop;' || chr(10) || chr(13) ||

'   n := 0;' || chr(10) || chr(13) ||

'   FOR i IN 1..l_group_id_name_tab.COUNT' || chr(10) || chr(13) ||
'   loop' || chr(10) || chr(13) ||
'      route_str := ''ROUTE BY NODE '' || l_group_id_name_tab(i).GROUP_ID;' || chr(10) || chr(13) ||
'      dbe_output.print_line(route_str);' || chr(10) || chr(13) ||
'      EXECUTE IMMEDIATE route_str;' || chr(10) || chr(13) ||
'      sql := ''select '' || l_group_id_name_tab(i).GROUP_ID || '' as GROUP_ID , '''''' || l_group_id_name_tab(i).NODE_NAME || '''''' as NODE_NAME ' || sql_col_list  || ' from ' || view_name || ''';' || chr(10) || chr(13) ||
'      dbe_output.print_line(sql);' || chr(10) || chr(13) ||
'      OPEN my_cursor FOR sql;' || chr(10) || chr(13) ||
'      loop' || chr(10) || chr(13) ||
'        FETCH my_cursor INTO group_id_tmp, NODE_NAME_tmp ' || sql_col_list_ || ';' || chr(10) || chr(13) ||
'         EXIT WHEN my_cursor%NOTFOUND;' || chr(10) || chr(13) ||
'         l_' || view_name || '_tab.extend;' || chr(10) || chr(13) ||
'         n := n + 1;' || chr(10) || chr(13) ||
'         l_' || view_name || '_tab(n) := O_GVIEW_' || view_name || '(group_id_tmp, NODE_NAME_tmp' || sql_col_list_ || ');' || chr(10) || chr(13) ||
'      end loop;' || chr(10) || chr(13) ||
'      dbe_output.print_line(''n = '' || n);' || chr(10) || chr(13) ||
'          EXECUTE IMMEDIATE  ''route by null'';' || chr(10) || chr(13) ||
'   end loop;' || chr(10) || chr(13) ||
'   dbe_output.print_line(''count = '' || l_' || view_name || '_tab.COUNT);' || chr(10) || chr(13) ||
'   return l_' || view_name || '_tab;' || chr(10) || chr(13) ||
'   exception' || chr(10) || chr(13) ||
'     when others then' || chr(10) || chr(13) ||
'     EXECUTE IMMEDIATE  ''route by null'';' || chr(10) || chr(13) ||
'     raise ;' || chr(10) || chr(13) ||
'  end;' || chr(10) || chr(13) ||
'  /';

 dbe_output.print_line(sql);
   EXECUTE IMMEDIATE sql;
   sql := 'create or replace view ' || schema || '.G' || view_name || ' as select * from table(cast(' || schema || '.F_GET_G' || view_name || ' as ' || schema || '.T_GVIEW_' || view_name || '))';
   dbe_output.print_line(sql);
   EXECUTE IMMEDIATE sql;
   sql := 'grant select on G' || view_name || ' to PUBLIC ';
   dbe_output.print_line(sql);
   EXECUTE IMMEDIATE sql;
   sql := 'grant execute on F_GET_G' || view_name || ' to PUBLIC ';
   dbe_output.print_line(sql);
   EXECUTE IMMEDIATE sql;
   sql := 'grant all on T_GVIEW_' || view_name || ' to PUBLIC ';
   dbe_output.print_line(sql);
   EXECUTE IMMEDIATE sql;
   sql := 'CREATE OR REPLACE PUBLIC SYNONYM G' || view_name || ' for ' || schema || '.G' || view_name;
   dbe_output.print_line(sql);
   EXECUTE IMMEDIATE sql;
   exception
     when param_err then
     dbe_output.print_line('create global view failed due to incorrect input parameter view name');
     when others then
     dbe_output.print_line('create global view failed, ' || sql_err_msg);
end create_global_view;
/
exec create_global_view('DV_BUFFER_POOLS')
/
exec create_global_view('DV_HA_SYNC_INFO')
/
exec create_global_view('DV_DATA_FILES')
/
exec create_global_view('DV_TABLESPACES')
/
exec create_global_view('DV_PARAMETERS')
/
exec create_global_view('DV_GMA_STATS')
/
exec create_global_view('DV_SYS_STATS')
/
exec create_global_view('DV_LOG_FILES')
/
exec create_global_view('DV_GLOBAL_TRANSACTIONS')
/
exec create_global_view('SYS_PENDING_DIST_TRANS')
/
exec create_global_view('SYS_PENDING_TRANS')
/
exec create_global_view('ADM_TABLESPACES')
/
exec create_global_view('ADM_TABLES')
/
exec create_global_view('ADM_TAB_MODIFICATIONS')
/
exec create_global_view('MY_TABLES')
/
exec create_global_view('MY_INDEXES')
/
exec create_global_view('MY_TAB_MODIFICATIONS')
/
--04
--This plsql is used to upgrade the old version to the new version with INHERIT PRIVILEGES.
--Upgrade compatibility is achieved by empowering the old users of the database.
declare
  cnt int;
begin
  select count(*) into cnt from SYS.SYS_USER_PRIVS where rownum <= 2; 
  if cnt = 0 then
    for USER_CUR in (select NAME from SYS.SYS_USERS where ID > 1) loop
        execute immediate 'grant INHERIT PRIVILEGES on User '|| USER_CUR.NAME ||' to PUBLIC';
    end loop;
  end if;
  EXCEPTION
    WHEN OTHERS THEN
      NULL;
end;
/

--This plsql is used to upgrade the old version to the new version with INHERIT PRIVILEGES.
--Upgrade compatibility is achieved by empowering the old users of the database.
declare
  cnt int;
begin
  select count(*) into cnt from SYS.SYS_USERS where rownum <= 3;
  if cnt > 2 then
    execute immediate 'grant INHERIT PRIVILEGES on User SYS to PUBLIC';
  end if;
  EXCEPTION
    WHEN OTHERS THEN
      NULL;
end;
/
--05
CREATE OR REPLACE PROCEDURE SYS_JOB_KILL_ACTIVE_DELAY(RANGE_TIME NUMBER DEFAULT 15/60/24, DELAY_TIME NUMBER DEFAULT 15/60/24)
IS
SQL1 VARCHAR(128);
CURR_TIME DATE := SYSDATE;
JOBNO INT;
R_COUNT INT;
BEGIN
--Delay these jobs which will run in range less than range_time
FOR ITEM IN (SELECT JOB, NEXT_DATE, WHAT, INTERVAL# FROM SYS_JOBS WHERE NEXT_DATE <= CURR_TIME + RANGE_TIME AND BROKEN = 0) LOOP
    DBE_TASK.CANCEL(ITEM.JOB);
    DBE_TASK.SUBMIT(JOBNO, ITEM.WHAT, CURR_TIME + DELAY_TIME, ITEM.INTERVAL#);
END LOOP;
COMMIT;

--Kill active running job task
LOOP
    SELECT COUNT(*) INTO R_COUNT FROM DV_RUNNING_JOBS;
    EXIT WHEN R_COUNT = 0;
    FOR ITEM IN (SELECT SESSION_ID,SERIAL_ID FROM DV_RUNNING_JOBS) LOOP
        SQL1 :='ALTER SYSTEM KILL SESSION '''||ITEM.SESSION_ID||','||ITEM.SERIAL_ID||'''';
        EXECUTE IMMEDIATE SQL1;
    END LOOP;
    SLEEP(1);
END LOOP;
END;
/

