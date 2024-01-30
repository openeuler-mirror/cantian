#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Perform hot backups of CantianDB100 databases.
# Copyright © Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.


import sys
sys.dont_write_bytecode = True
try:
    import os
    import getopt
    import subprocess
    import platform
    from Common import DefaultValue
except ImportError as e:
    sys.exit("Unable to import module: %s." % str(e))

old_core_tables = [
    "COLUMN$",
    "INDEX$",
    "TABLE$",
    "USER$"
    ]

old_systables = [
    "BACKUP_SET$",
    "COLUMN$",
    "COMMENT$",
    "CONSDEF$",
    "DATA_NODES$",
    "DBA_EXP$TBL_ORDER",
    "DBA_EXP$TBL_RELATIONS",
    "DEPENDENCY$",
    "DISTRIBUTE_RULE$",
    "DISTRIBUTE_STRATEGY$",
    "DUAL",
    "EXTERNAL$",
    "GARBAGE_SEGMENT$",
    "HIST_HEAD$",
    "HISTGRAM$",
    "INDEX$",
    "INDEXPART$",
    "JOB$",
    "LINK$",
    "LOB$",
    "LOBPART$",
    "LOGIC_REP$",
    "MON_MODS_ALL$",
    "OBJECT_PRIVS$",
    "PARTCOLUMN$",
    "PARTOBJECT$",
    "PARTSTORE$",
    "PENDING_DISTRIBUTED_TRANS$",
    "PENDING_TRANS$",
    "PROC$",
    "PROC_ARGS$",
    "PROFILE$",
    "RECYCLEBIN$",
    "ROLES$",
    "SEQUENCE$",
    "SHADOW_INDEX$",
    "SHADOW_INDEXPART$",
    "SYNONYM$",
    "SYS_PRIVS$",
    "TABLEPART$",
    "TMP_SEG_STAT$",
    "USER$",
    "USER_HISTORY$",
    "USER_ROLES$",
    "VIEW$",
    "VIEWCOL$",
    "SQL_MAP$",
]

new_core_tables = [
    "SYS_COLUMNS",
    "SYS_INDEXES",
    "SYS_TABLES",
    "SYS_USERS"
    ]

new_systables = [
    "SYS_BACKUP_SETS",
    "SYS_COLUMNS",
    "SYS_COMMENTS",
    "SYS_CONSTRAINT_DEFS",
    "SYS_DATA_NODES",
    "EXP_TAB_ORDERS",
    "EXP_TAB_RELATIONS",
    "SYS_DEPENDENCIES",
    "SYS_DISTRIBUTE_RULES",
    "SYS_DISTRIBUTE_STRATEGIES",
    "SYS_DUMMY",
    "SYS_EXTERNAL_TABLES",
    "SYS_GARBAGE_SEGMENTS",
    "SYS_HISTGRAM_ABSTR",
    "SYS_HISTGRAM",
    "SYS_INDEXES",
    "SYS_INDEX_PARTS",
    "SYS_JOBS",
    "SYS_LINKS",
    "SYS_LOBS",
    "SYS_LOB_PARTS",
    "SYS_LOGIC_REPL",
    "SYS_DML_STATS",
    "SYS_OBJECT_PRIVS",
    "SYS_PART_COLUMNS",
    "SYS_PART_OBJECTS",
    "SYS_PART_STORES",
    "SYS_PENDING_DIST_TRANS",
    "SYS_PENDING_TRANS",
    "SYS_PROCS",
    "SYS_PROC_ARGS",
    "SYS_PROFILE",
    "SYS_RECYCLEBIN",
    "SYS_ROLES",
    "SYS_SEQUENCES",
    "SYS_SHADOW_INDEXES",
    "SYS_SHADOW_INDEX_PARTS",
    "SYS_SYNONYMS",
    "SYS_PRIVS",
    "SYS_TABLE_PARTS",
    "SYS_TMP_SEG_STATS",
    "SYS_USERS",
    "SYS_USER_HISTORY",
    "SYS_USER_ROLES",
    "SYS_VIEWS",
    "SYS_VIEW_COLS",
    "SYS_SQL_MAPS",
]


def isSameSqlList(list1, list2):
    '''
    two lists of string
    compare(ignore cases) if they are same
    '''

    if len(list1) != len(list2):
        return False
    for i in range(len(list1)):
        if list1[i].strip().upper() != list2[i].strip().upper():
            return False

    return True


class CreateTableSql(object):
    '''
    this class process the SQL:
    CREATE TABLE items
    '''
    def __init__(self, sql):
        '''
        init a create table sql
        '''

        sqls = str(sql).split('\n')
        if sqls[0][0:2] == '--':
            sqls.pop(0)
        self.__sql = '\n'.join(sqls)
        self.__items = []
        # divide create table sql to 3 parts
        # 1. before the 'relational_properties'
        # 2. the 'relational_properties' (colums)
        # 3. after the 'relational_properties'
        # the relational_properties embraced by a pair of parentheses
        # find the first left parenthesis and it's peer right one
        self.__indexOfLeftParenthesis = self.__sql.index('(')
        self.__indexOfRightParenthesis =\
            self.find_right_parenthesis(self.__sql,
                                        self.__indexOfLeftParenthesis)
        self.__preSql = self.__sql[0:self.__indexOfLeftParenthesis]
        self.__postSql = self.__sql[self.__indexOfRightParenthesis+1:]

        contentSql = self.__sql[self.__indexOfLeftParenthesis+1:
                                self.__indexOfRightParenthesis]

        for i in contentSql.split('\n'):
            if i.strip().strip(','):
                self.__items.append(i.strip().strip(','))

        if not self.__items:
            raise Exception("Syntax Error:\n%s" % self.__sql)

    def find_right_parenthesis(self, content, index_left_p):
        '''
        find the corresponding right parenthesis
        if left parenthesis encountered , level plus 1 : means enter
        if right parenthesis encountered, if level is zero , found
                                          else level minus 1
        unexpected : retuen -1
        '''

        # verify left index is correct
        if content[index_left_p] != '(':
            return -1

        level = 0
        count = 0

        # start from left plus 1
        for i in content[index_left_p+1:]:
            if i == '(':
                level += 1
            elif i == ')':
                if level == 0:
                    return index_left_p + 1 + count
                else:
                    level -= 1
            else:
                pass
            count += 1

        # have not found
        return -1

    def tableSpace(self):
        '''
        return tablespace of this table
        '''
        contents = self.__postSql.split()
        try:
            i = contents.index("TABLESPACE")
            ts = contents[i+1]
            return ts
        except ValueError as e:
            print(str(e))
            return "UNKNOWN"

    def isSamePreContent(self, other):
        '''
        self should from new initdb
        other should from old initdb
        we split this sql to 3 parts:
        1. create table xxx (
        2. colum items
        3. ) xxx
        this function compare part1
        '''

        pre1 = self.__preSql.split()
        pre2 = other.__preSql.split()
        return isSameSqlList(pre1, pre2)

    def ignore_key_int(self, sql_str, key_str):
        '''
        ignore the 'key word' + 'int'
        '''
        content = sql_str.split()
        for i in range(len(content)):
            if content[i] == key_str:
                if content[i+1].isdigit():
                    content.pop(i)
                    content.pop(i)
                    return ' '.join(content)
        return sql_str

    def ignore_pctfree(self, sql_str):
        '''
        ignore the pctfree key word
        '''
        if sql_str.find("PCTFREE") < 0:
            return sql_str

        return self.ignore_key_int(sql_str, "PCTFREE")

    def ignore_storage(self, sql_str):
        '''
        ignore the storage key word
        '''

        index_of_storage = sql_str.find("STORAGE")
        if index_of_storage < 0:
            return sql_str

        index_of_end = sql_str.find(')', index_of_storage)

        return sql_str[0:index_of_storage] + sql_str[index_of_end+1:]

    def isSamePostContent(self, other):
        '''
        self should from new initdb
        other should from old initdb
        we split this sql to 3 parts:
        1. create table xxx (
        2. colum items
        3. ) xxx
        this function compare part3
        ignore PCTFREE xx (xx is a integer number)
        ignore STORAGE (INITIAL xxxK) (xxx is a integer number)
        '''
        storage_info = other.ignore_storage(other.__postSql)
        post1 =\
            self.ignore_pctfree(self.ignore_storage(self.__postSql)).split()
        post2 = other.ignore_pctfree(storage_info).split()

        return isSameSqlList(post1, post2)

    def incrementItems(self, other):
        '''
        self should from new initdb
        other should from old initdb
        we split this sql to 3 parts:
        1. create table xxx (
        2. colum items
        3. ) xxx
        this function process part2
        output new col items in create sql
        '''
        increment = []
        length1 = len(self.__items)
        length2 = len(other.__items)

        if length1 == length2:
            '''
            __isSame of SqlItem may not correct when sql has ','
            use strip(',') to pass the right sql to isSameSqlList
            '''
            for i in range(length1):
                li = self.__items[i].strip().strip(',')
                ll = other.__items[i].strip().strip(',')
                if not isSameSqlList(li.split(), ll.split()):
                    # output entire sqls for easy debug
                    raise Exception("Decrement items:\n%s\n%s\n"
                                    % (self.__sql, other.__sql))
            return increment

        if length1 < length2:
            # output entire sqls for easy debug
            raise Exception("Decrement items:\n%s\n%s\n"
                            % (self.__sql, other.__sql))

        for i in range(length2):
            if not isSameSqlList(self.__items[i].strip().strip(',').split(),
                                 other.__items[i].strip().strip(',').split()):
                # output entire sqls for easy debug
                raise Exception("Decrement items:\n%s\n%s\n"
                                % (self.__sql, other.__sql))

        for i in range(length2, length1):
            increment.append(self.__items[i].strip().strip(','))

        return increment


class SqlItem(object):

    """
    this class manage sql commands items
    compare 2 sql
    generate upgrade and rollback sql
    """

    def __init__(self, sql, flag=False, is_target=False, ignore=False):
        '''
        init from raw sql
        some sql use SYS.tablename
        will strip 'SYS.' prefix
        '''
        self.__sql = str(sql)
        self.__flag = flag
        self.__sql_type = 0
        self.__table_name = ''
        self.__index_name = ''
        self.__role_name = ''
        self.__sequence_name = ''
        self.__privilege_name = ''
        self.__grantee = ''
        self.__is_target = is_target
        self.__is_ignore = ignore
        self.__sql_version = 0
        self.__analyse()
        self.__diffs = []
        self.__add_table_items = []

        self.nameStyle = ''
        if self.__table_name:
            table_name = self.__table_name
            if table_name[0:4] == 'SYS.':
                table_name = table_name[4:]
            if table_name in old_systables:
                self.nameStyle = 'old'
            elif table_name in new_systables:
                self.nameStyle = 'new'
            else:
                self.nameStyle = ''

    def _replace(self, s, t):
        '''
        replace sql contents
        '''
        self.__sql = self.__sql.replace(s, t)

    def rename2old(self):
        '''
        rename table name to old style
        '''
        self.__rename()

    def rename2new(self):
        '''
        rename table name to new style
        '''
        self.__rename(to_new=True)

    def version(self):
        '''
        get the version
        '''
        return self.__sql_version

    def unique2normal(self):
        '''
        '''
        self.__sql = self.__sql.replace("CREATE UNIQUE", "CREATE")
        self.__analyse()

    def originSql(self):
        '''
        return the origin sql
        '''
        return self.__sql

    def index_name(self):

        if self.isCreateIndexSql():
            return self.__index_name

        return ""

    def tableName(self):
        '''
        return the related table name of this sql
        '''
        return self.__table_name

    def name(self):
        '''
        if create role return role name
        elif create sequence return sequence name
        else return table name
        '''
        if self.isCreateRoleSql():
            return self.__role_name
        elif self.isCreateSeqenceSql():
            return self.__sequence_name
        else:
            return self.__table_name

    def roleName(self):
        '''
        return the related role name of this sql
        '''
        return self.__role_name

    def genDrop(self):
        '''
        generate the Drop sql for index sql
        '''
        if self.isCreateIndexSql():
            drop = "DROP INDEX %s on %s" % (self.__index_name, self.__table_name)
            return drop
        return ''

    def isIndexSpecialCondition1(self, other):
        '''
        CREATE UNIQUE INDEX IX_PROCARGU_001 ON SYS_PROC_ARGS(USER#,
        OBJECT_NAME, PACKAGE, SEQUENCE, OVERLOAD) TABLESPACE SYSTEM
        CREATE UNIQUE INDEX IX_PROCARGU_001 ON PROC_ARGS
        $(USER#, OBJECT_NAME, SEQUENCE) TABLESPACE SYSTEM
        '''
        sqls1 = ['CREATE UNIQUE INDEX IX_PROCARGU_001 ON SYS_PROC_ARGS'
                 '(USER#, OBJECT_NAME, PACKAGE, SEQUENCE, OVERLOAD)'
                 ' TABLESPACE SYSTEM',
                 'CREATE UNIQUE INDEX IX_PROCARGU_001 ON PROC_ARGS'
                 '$(USER#, OBJECT_NAME, PACKAGE, SEQUENCE, OVERLOAD)'
                 ' TABLESPACE SYSTEM']
        sqls2 = ['CREATE UNIQUE INDEX IX_PROCARGU_001 ON SYS_PROC_ARGS'
                 '(USER#, OBJECT_NAME, SEQUENCE) TABLESPACE SYSTEM',
                 'CREATE UNIQUE INDEX IX_PROCARGU_001 ON PROC_ARGS'
                 '$(USER#, OBJECT_NAME, SEQUENCE) TABLESPACE SYSTEM']
        if not self.isCreateIndexSql():
            return False
        if not other.isCreateIndexSql():
            return False
        if self.__index_name != 'IX_PROCARGU_001':
            return False
        if self.originSql() in sqls2 and other.originSql() in sqls1:
            return True
        return False

    def setFlag(self, flag):
        '''
        this flag indicate whether this item has been fetched or not
        '''
        self.__flag = flag

    def isFlagTrue(self):
        '''
        retrun the internal flag
        '''
        return self.__flag

    def isTableSql(self):
        '''
        return if this sql is a table related sql
        '''
        if self.__sql_type in [1, 2, 3, 4, 5, 6, 10, 11]:
            return True
        return False

    def isCreateRoleSql(self):
        '''
        return if this sql is a create role sql
        '''
        if self.__sql_type in [7]:
            return True
        return False

    def isCreateSeqenceSql(self):
        '''
        return if this sql is a create sequence sql
        '''
        if self.__sql_type in [8]:
            return True
        return False

    def isGrantSql(self):
        '''
        return if this sql is a grant xxx|ALL to role sql
        '''
        if self.__sql_type in [9]:
            return True
        return False

    def isCreateTableSql(self):
        '''
        return if this sql is a create table sql
        '''
        if self.__sql_type in [1, 2, 3]:
            return True
        return False

    def isCreateIndexSql(self):
        '''
        return if this sql is a create index sql
        '''
        if self.__sql_type in [4, 5]:
            return True
        return False

    def isCreateNormalIndexSql(self):
        '''
        return if this sql is a create index sql
        '''
        if self.__sql_type in [4]:
            return True
        return False

    def isCreateUniqueIndexSql(self):
        '''
        return if this sql is a create index sql
        '''
        if self.__sql_type in [5]:
            return True
        return False

    def isAlterSystemSql(self):
        '''
        return if this sql is a create index sql
        '''
        if self.__sql_type in [6]:
            return True
        return False

    def isViewDropableSql(self):
        '''
        '''
        if self.__sql_type in [1, 2, 3, 4, 5, 8, 12, 13, 14, 15, 16, 17, 18]:
            return True
        return False

    def isCreateOrReplaceView(self):
        '''
        '''
        if self.__sql_type in [12]:
            return True
        return False

    def generate_drop_procedure(self, p_name):

        if self.__sql_type != 15:
            return ""

        end_symbol = '\n/\n\n'
        drop_sql = 'DROP PROCEDURE IF EXISTS %s' % p_name
        drop_sql += end_symbol
        drop_sql += "BEGIN\n"
        drop_sql += "    FOR ITEM IN "
        drop_sql += "(SELECT JOB FROM SYS_JOBS WHERE UPPER(WHAT) "
        drop_sql += "LIKE UPPER('{0}(%')) LOOP\n".format(p_name)
        drop_sql += "        DBE_TASK.CANCEL(ITEM.JOB);\n"
        drop_sql += "    END LOOP;\n"
        drop_sql += "    COMMIT;\n"
        drop_sql += "END;"
        return drop_sql

    def generateDropSql(self):
        '''
        '''
        if not self.isViewDropableSql():
            return ''

        if self.__sql_type == 8:
            return 'DROP SEQUENCE IF EXISTS %s' % self.__sequence_name
        if self.__sql_type == 12:
            return 'DROP VIEW IF EXISTS %s' % self.__table_name
        if self.__sql_type == 13:
            return 'DROP PUBLIC SYNONYM IF EXISTS %s' % self.__table_name
        if self.__sql_type == 14:
            return 'DROP SYNONYM IF EXISTS %s' % self.__table_name
        if self.__sql_type == 15:
            return self.generate_drop_procedure(self.__table_name)
        if self.__sql_type in [1, 2, 3, 16]:
            return 'DROP TABLE IF EXISTS %s' % self.__table_name
        if self.__sql_type in [4, 5, 17, 18]:
            return 'DROP INDEX IF EXISTS %s ON %s' % (self.__index_name, self.__table_name)

    def __isTableMatched(self, other):
        '''
        return if
        the 2 sqls operate the same table
        '''
        if self.__table_name == other.__table_name:
            return True
        return False

    def __isIndexMatched(self, other):
        '''
        return if the 2 sqls operate the same index
        '''
        if self.__index_name == other.__index_name:
            return True
        return False

    def __isSame(self, other):
        '''
        return if
        the 2 sqls are identical
        '''

        sql1 = self.__sql.split()
        sql2 = other.__sql.split()

        return isSameSqlList(sql1, sql2)

    def __isAllMatched(self, other):
        '''
        return if
        the 2 sqls are identical
        '''
        return self.__isSame(other)

    def isMatched(self, other):
        '''
        return if
        the 2 sqls create the same table
        or are identical
        '''

        if not isinstance(other, SqlItem):
            return False

        elif self.isCreateIndexSql():
            return self.__isIndexMatched(other)

        if self.__sql_type != other.__sql_type:
            return False
        elif self.isCreateTableSql():
            return self.__isTableMatched(other)
        elif self.isViewDropableSql():
            if self.__sql_type == 8:
                if self.__sequence_name == other.__sequence_name:
                    return True
                else:
                    return False
            else:
                return self.__isTableMatched(other)
        else:
            return self.__isAllMatched(other)

        return False

    def __incrementOfCreateTable(self, other):
        '''
        find increment items of Create Table
        '''

        createTable1 = CreateTableSql(self.__sql)
        createTable2 = CreateTableSql(other.__sql)

        if not createTable1.isSamePreContent(createTable2):
            print("Error SQLs:\n%s\n%s\n" % (self.__sql, other.__sql))
            sys.exit(1)

        if not createTable1.isSamePostContent(createTable2):
            print("Error SQLs:\n%s\n%s\n" % (self.__sql, other.__sql))
            sys.exit(1)

        return createTable1.incrementItems(createTable2)

    def generateDegradeSql(self, other):
        '''
        this is generate interface
        self is from old initdb file
        other is from new initdb file
        old and new is for upgrade script
        actually the old initdb file is newer one
        other may be None if self is totally new
        '''

        up = []
        self.__diffs = []

        if other:
            if not isinstance(other, SqlItem):
                raise Exception('unrecognized object %s' % str(other))

            if self.__isSame(other):
                '''
                process for:
                the same sqls
                '''
                return []

            else:
                '''
                process for:
                DECREMENT of CREATE TABLE
                '''
                # CREATE TABLE decrement
                decrementItems = other.__incrementOfCreateTable(self)
                for item in decrementItems:
                    if ' '.join(item.split()).upper().find("NOT NULL") >= 0:
                        if item.upper().find("DEFAULT") < 0:
                            raise Exception("Can not handle"
                                            " decrement sql: %s" % item)

        else:
            '''
            process for:
            new sqls
            '''
            if self.isCreateTableSql():
                up.append("DROP TABLE %s" % self.__table_name)
            elif self.isCreateIndexSql():
                up.append("DROP INDEX IF EXISTS %s on %s" % (self.__index_name, self.__table_name))
            elif self.__sql_type in [7]:
                up.append("DROP ROLE %s" % self.__role_name)
            elif self.__sql_type in [8]:
                up.append("DROP SEQUENCE IF EXISTS %s" % self.__sequence_name)
            elif self.__sql_type in [9]:
                up.append("REVOKE %s FROM %s"
                          % (self.__privilege_name, self.__grantee))
            elif self.__sql_type == 6:
                pass
            else:
                raise Exception("Unknown Sql:%s" % self.__sql)

        self.__diffs.extend(up)
        return up

    def generateUpgradeSql(self, other):
        '''
        this is generate interface
        self is from new initdb file
        other is from old initdb file
        other may be None if self is totally new
        '''

        up = []
        extra_sqls = []
        self.__diffs = []

        if other:
            if not isinstance(other, SqlItem):
                raise Exception('unrecognized object %s' % str(other))

            if self.__isSame(other):
                '''
                process for:
                the same sqls
                '''
                return [], []

            elif self.isCreateIndexSql():
                up.append("DROP INDEX %s on %s" % (other.__index_name, other.__table_name))
                up.append(self.__sql)

            else:
                '''
                process for:
                INCREMENT of CREATE TABLE
                '''
                # CREATE TABLE INCREMENT
                incrementItems = self.__incrementOfCreateTable(other)
                for item in incrementItems:
                    if ' '.join(item.split()).upper().find("NOT NULL") >= 0:
                        if item.upper().find("DEFAULT") < 0:
                            raise Exception("Can not handle"
                                            " increment sql: %s" % item)
                        else:
                            sql_content = [i.upper() for i in item.split()]
                            default_value =\
                                sql_content[sql_content.index("DEFAULT")+1]
                            update_sql = "UPDATE %s SET %s=%s"\
                                         % (self.__table_name,
                                            sql_content[0], default_value)
                            extra_sqls.append(update_sql)
                            extra_sqls.append("COMMIT")
                    upgrade_sql = "ALTER TABLE %s ADD %s"\
                                  % (self.__table_name,
                                     ' '.join(item.strip(',').split()))
                    self.__add_table_items.append(item.strip(','))
                    up.append(upgrade_sql)

        else:
            '''
            process for:
            new sqls
            '''
            up.append(self.__sql)

        self.__diffs.extend(up)
        self.__diffs.extend(extra_sqls)
        return up, extra_sqls

    def __str__(self):
        '''
        for easy output an object
        '''
        return "\nSQL:\n%s\nFetched:%s\n" % (self.__sql, str(self.__flag))

    def __analyse(self):
        '''
        analyse the syntax of a single sql string
        '''

        sql = self.__sql

        if not sql:
            return
        ###########################################
        # map for sql type and number
        # CREATE TABLE                 -- 1
        # CREATE TEMPORARY TABLE       -- 2
        # CREATE GLOBAL TEMPORARY TABLE-- 3
        # CREATE INDEX                 -- 4
        # CREATE UNIQUE INDEX          -- 5
        # ALTER SYSTEM                 -- 6
        # CREATE ROLE                  -- 7
        # CREATE SEQUENCE              -- 8
        # GRANT                        -- 9
        ###########################################
        tokens = sql.split()
        if tokens[0][0:2] == '--':
            if tokens[0][2:].isdigit():
                self.__sql_version = int(tokens[0][2:])
            tokens.pop(0)
            self.__sql = sql[sql.find(tokens[0]):]

        if (tokens[0].upper() == 'CREATE' and tokens[1].upper() == 'TABLE'):
            if (tokens[2] == 'IF' 
                and tokens[3] == 'NOT' 
                and tokens[4] == 'EXISTS'):
                self.__sql_type = 16
                self.__table_name = tokens[5]
            else:
                self.__sql_type = 1
                self.__table_name = tokens[2]

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'TEMPORARY'
              and tokens[2].upper() == 'TABLE'):
            self.__sql_type = 2
            self.__table_name = tokens[3]

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'GLOBAL'
              and tokens[2].upper() == 'TEMPORARY'
              and tokens[3].upper() == 'TABLE'):
            self.__sql_type = 3
            self.__table_name = tokens[4]

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'INDEX'
              and tokens[3].upper() == 'ON'):
            self.__sql_type = 4
            self.__index_name = tokens[2]
            self.__table_name = tokens[4].split('(')[0]

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'UNIQUE'
              and tokens[2].upper() == 'INDEX'
              and tokens[4].upper() == 'ON'):
            self.__sql_type = 5
            self.__index_name = tokens[3]
            self.__table_name = tokens[5].split('(')[0]

        elif (tokens[0].upper() == 'ALTER'
              and tokens[1].upper() == 'SYSTEM'
              and tokens[2].upper() == 'LOAD'
              and tokens[3].upper() == 'DICTIONARY'
              and tokens[4].upper() == 'FOR'):

            self.__sql_type = 6
            self.__table_name = tokens[5].strip()

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'ROLE'):
            self.__sql_type = 7
            self.__role_name = tokens[2].strip()

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'SEQUENCE'):
            self.__sql_type = 8
            self.__sequence_name = tokens[2].strip()

        elif (tokens[0].upper() == 'GRANT'):

            indexOfTO = 0
            endOfIndex = len(tokens)
            for tok in tokens:
                if tok.upper() == 'TO':
                    indexOfTO = tokens.index(tok)
                    break
            else:
                raise Exception("Syntax Error: %s" % sql)

            privileges = tokens[1:indexOfTO]
            self.__sql_type = 9
            self.__privilege_name = ' '.join(privileges)
            self.__role_name = tokens[indexOfTO+1]

            if tokens[-1].upper() == 'OPTION':
                if tokens[-2].upper() == 'ADMIN'\
                        and tokens[-3].upper() == 'WITH':
                    endOfIndex -= 3

                    self.__grantee = ' '.join(tokens[indexOfTO+1:endOfIndex])

        elif (tokens[0].upper() == 'ALTER'
              and tokens[1].upper() == 'TABLE'
              and self.__is_target):

            self.__sql_type = 10
            self.__table_name = tokens[2].strip()

        elif (tokens[0].upper() == 'DROP'
              and tokens[1].upper() == 'INDEX'
              and self.__is_target):

            self.__sql_type = 11
            self.__index_name = tokens[2].strip()

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'OR'
              and tokens[2].upper() == 'REPLACE'
              and tokens[3].upper() == 'VIEW'
              and self.__is_target):

            self.__sql_type = 12
            self.__table_name = tokens[4].strip()

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'OR'
              and tokens[2].upper() == 'REPLACE'
              and tokens[3].upper() == 'PUBLIC'
              and tokens[4].upper() == 'SYNONYM'
              and self.__is_target):

            self.__sql_type = 13
            self.__table_name = tokens[5].strip()

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'OR'
              and tokens[2].upper() == 'REPLACE'
              and tokens[3].upper() == 'SYNONYM'
              and self.__is_target):

            self.__sql_type = 14
            self.__table_name = tokens[4].strip()

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'OR'
              and tokens[2].upper() == 'REPLACE'
              and tokens[3].upper() == 'PROCEDURE'
              and self.__is_target):

            self.__sql_type = 15
            # procedure may have paramters after the name
            # like : create or replace procedure_name(parameter list)
            self.__table_name = tokens[4].strip().split('(')[0]

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'INDEX'
              and tokens[2].upper() == 'IF'
              and tokens[3].upper() == 'NOT'
              and tokens[4].upper() == 'EXISTS'
              and tokens[6].upper() == 'ON'):
            self.__sql_type = 17
            self.__index_name = tokens[5]
            self.__table_name = tokens[7].split('(')[0]

        elif (tokens[0].upper() == 'CREATE'
              and tokens[1].upper() == 'UNIQUE'
              and tokens[2].upper() == 'INDEX'
              and tokens[3].upper() == 'IF'
              and tokens[4].upper() == 'NOT'
              and tokens[5].upper() == 'EXISTS'
              and tokens[7].upper() == 'ON'):
            self.__sql_type = 18
            self.__index_name = tokens[6]
            self.__table_name = tokens[8].split('(')[0]

        else:
            if not self.__is_ignore:
                raise Exception("Syntax Error: %s" % sql)
            else:
                print("Unknown sql: %s\n" % sql)

    def add_table_items(self):

        return self.__add_table_items

    def last_generated_diff(self):

        return self.__diffs

    def __rename(self, to_new=False):
        '''
        rename all table_name with old name
        '''
        if self.__table_name.find('SYS.') == 0:
            self.__table_name = self.__table_name[4:]

        source_tables = new_systables
        target_tables = old_systables

        if to_new:
            source_tables = old_systables
            target_tables = new_systables

        if self.__table_name:
            if self.__table_name in source_tables:
                target_name =\
                    target_tables[source_tables.index(self.__table_name)]
                self.__sql = self.__sql.replace(' '+self.__table_name,
                                                ' '+target_name)
                self.__sql = self.__sql.replace(' SYS.'+self.__table_name,
                                                ' SYS.'+target_name)
                self.__table_name = target_name


g_later_delete_flag = False


class TableGroup(object):
    '''
    a group include all table sqls:
    create table
    create index
    create SEQUENCE
    '''

    def __init__(self, create_sql):
        '''
        init a TableGroup object from create table sql
        '''

        self.__table_name = ''
        self.__sqls = []
        self.__sqls_ct = []
        self.__sqls_ci = []
        self.__sqls_as = []
        self.__sqls_other = []
        self.__unmatched = []
        self.__sql_version = create_sql.version()
        self.__special_tables = ["SYS_HISTGRAM_ABSTR", "HIST_HEAD$",
                                 "MON_MODS_ALL$", "SYS_DML_STATS"]
        self.__sysaux_tables = ["SYS_HISTGRAM_ABSTR", "HIST_HEAD$",
                                "SYS_HISTGRAM", "HISTGRAM$"]

        if not isinstance(create_sql, SqlItem):
            raise Exception("Unexpected type:%s,"
                            " SqlItem is expected" % type(create_sql))
        if not create_sql.isCreateTableSql():
            raise Exception("Need 'Create table' sql :\n%s"
                            % create_sql.originSql())

        self.__table_name = create_sql.tableName()
        self.__sqls.append(create_sql)
        self.__sqls_ct.append(create_sql)

        self.__flag = False

        self.__special_case1 = False

        self.__table_diff = []

        self.__new_table_items = []
        self.__new_table = []
        self.__new_unique_index = []
        self.__modified_unique_index = []

    def get_new_table_items(self):

        return self.__new_table_items

    def get_new_table(self):

        return self.__new_table

    def get_new_unique_index(self):

        return self.__new_unique_index

    def get_modified_unique_index(self):

        return self.__modified_unique_index

    def __str__(self):
        '''
        this function for easy debug
        '''
        s = ''
        for item in self.__sqls:
            s += str(item)

        return s

    def version(self):
        '''
        get the version
        '''

        return self.__sql_version

    def tableName(self):
        '''
        return the table name
        '''

        return self.__table_name

    def name(self):
        '''
        return the table name
        '''

        return self.__table_name

    def append(self, sql):
        '''
        append to internal lists
        '''

        if sql.tableName() not in [self.__table_name,
                                   'SYS.'+self.__table_name]:
            raise Exception("Cannot append %s to table:%s"
                            % (sql.originSql(), self.__table_name))

        self.__sqls.append(sql)

        if sql.isCreateTableSql():
            self.__sqls_ct.append(sql)
        elif sql.isCreateIndexSql():
            self.__sqls_ci.append(sql)
        elif sql.isAlterSystemSql():
            self.__sqls_as.append(sql)
        else:
            self.__sqls_other.append(sql)

    def setFlag(self, flag):
        '''
        set flag for fetch
        '''

        self.__flag = flag

    def isFlagTrue(self):
        '''
        getreturn the flag
        '''

        return self.__flag

    def rename2old(self):
        '''
        rename table name to old
        '''

        for i in self.__sqls:
            i.rename2old()

        # rename table group table name
        if self.__table_name:
            if self.__table_name in new_systables:
                old_name =\
                    old_systables[new_systables.index(self.__table_name)]
                self.__table_name = old_name

    def rename2new(self):
        '''
        rename table name to new
        '''
        for i in self.__sqls:
            i.rename2new()

        # rename table group table name
        if self.__table_name:
            if self.__table_name in old_systables:
                _name = new_systables[old_systables.index(self.__table_name)]
                self.__table_name = _name

    def isMatched(self, other):
        '''
        if table name is the same
        '''

        if not isinstance(other, TableGroup):
            return False

        if other.tableName() == self.__table_name:
            return True

        return False

    def __fetch(self, sql, update_flag=True):
        '''
        fetch matched item
        '''
        matched = None
        for i in self.__sqls:
            if i.isMatched(sql):
                matched = i
                if update_flag:
                    i.setFlag(True)
                break
        return matched

    def __isAllMatched(self, other):
        '''
        check if all items matched
        '''

        for i in self.__sqls:
            if not i.isCreateIndexSql():
                other.__fetch(i)
        for i in other.__sqls:
            if not i.isCreateIndexSql():
                if not i.isFlagTrue():
                    self.__unmatched.append(i)
                    return False
        return True

    def __isDropIndex(self, other):
        '''
        shall we drop all index?
        '''

        if not other:
            return False
        if not isinstance(other, TableGroup):
            return False

        for i in self.__sqls_ci:

            matched = other.__fetch(i)

            if not matched:
                if i.isCreateUniqueIndexSql():
                    self.__new_unique_index.append(i.index_name())
                return True

            if self.__table_name in self.__special_tables:
                if i.isCreateUniqueIndexSql()\
                        and matched.isCreateNormalIndexSql():
                    i.unique2normal()

            if not isSameSqlList(i.originSql().split(),
                                 matched.originSql().split()):
                if i.isCreateUniqueIndexSql():
                    self.__modified_unique_index.append(i.index_name())
                if i.isIndexSpecialCondition1(matched):
                    self.__special_case1 = True
                return True

        for i in other.__sqls_ci:
            if not i.isFlagTrue():
                return True

        return False

    def __geneDropAllIndexSqls(self):
        '''
        generate drop index sqls
        '''

        drops = []

        for i in self.__sqls:
            if i.isCreateIndexSql():
                drops.append(i.genDrop())

        return drops

    def tableSpace(self):
        '''
        return the tablespace name
        '''
        return CreateTableSql(self.__sqls_ct[0].originSql()).tableSpace()

    def __checkTableSpaceChange(self, other):
        '''
        check if tablespace changes
        '''

        tablespace1 = self.tableSpace()
        tablespace2 = other.tableSpace()

        if tablespace1 == 'SYSTEM' and tablespace2 == 'SYSAUX':
            return True

        if tablespace1 == 'SYSAUX' and tablespace2 == 'SYSTEM':
            return True

        return False

    def generateDegradeSql(self, other):
        '''
        generate degrade sqls
        '''

        self.__table_diff = []
        upgrade_sqls = []
        load_sql = 'ALTER SYSTEM LOAD DICTIONARY FOR %s' % self.__table_name

        if not other:
            '''
            other is empty or none
            means all sqls are new
            '''

            upgrade_sqls.append(load_sql)
            upgrade_sqls.append("DROP TABLE %s" % self.__table_name)
            self.__table_diff.append("DROP TABLE %s" % self.__table_name)

        else:
            '''
            other is not none
            check is all matched
            then check if need drop all index
            then generate the sqls
            '''

            if not isinstance(other, TableGroup):
                raise Exception("Unexpected type %s" % type(other))

            if self.__checkTableSpaceChange(other)\
                    and self.__table_name in self.__sysaux_tables:
                for i in self.__sqls_ct:
                    i._replace("TABLESPACE SYSAUX", "TABLESPACE SYSTEM")
                for i in other.__sqls_ct:
                    i._replace("TABLESPACE SYSAUX",
                               "TABLESPACE SYSTEM")

            if not self.__isAllMatched(other):
                raise Exception("Unmatched item %s"
                                % self.__unmatched[0].originSql())

            if other.__isDropIndex(self):

                upgrade_sqls.append(load_sql)

                global g_later_delete_flag

                if self.__table_name in self.__special_tables:
                    self.__table_diff.append("DELETE FROM %s"
                                             % self.__table_name)
                    self.__table_diff.append("COMMIT")

                if self.__table_name == 'SYS_PROC_ARGS'\
                        and other.__special_case1:
                    g_later_delete_flag = True
                    self.__table_diff.append("DELETE FROM SYS_PROCS"
                                             " WHERE TYPE IN ('S','B')")
                    self.__table_diff.append("DELETE FROM SYS_PROC_ARGS"
                                             " WHERE LENGTH(PACKAGE)>0")
                    self.__table_diff.append("COMMIT")

                if self.__table_name == 'PROC_ARGS$'\
                        and other.__special_case1:
                    g_later_delete_flag = True
                    self.__table_diff.append("DELETE FROM PROC$"
                                             " WHERE TYPE IN ('S','B')")
                    self.__table_diff.append("DELETE FROM PROC_ARGS$"
                                             " WHERE LENGTH(PACKAGE)>0")
                    self.__table_diff.append("COMMIT")

                if self.__table_name == 'SYS_DEPENDENCIES'\
                        and g_later_delete_flag:
                    self.__table_diff.append("DELETE FROM SYS_DEPENDENCIES"
                                             " WHERE D_TYPE# IN (15, 16)"
                                             " OR P_TYPE# IN (15, 16)")
                    self.__table_diff.append("COMMIT")

                if self.__table_name == 'DEPENDENCY$' and g_later_delete_flag:
                    self.__table_diff.append("DELETE FROM DEPENDENCY$"
                                             " WHERE D_TYPE# IN (15, 16)"
                                             " OR P_TYPE# IN (15, 16)")
                    self.__table_diff.append("COMMIT")

                up = self.__geneDropAllIndexSqls()
                up += [sql.originSql() for sql in other.__sqls_ci]
                self.__table_diff.extend(up)

                for i in other.__sqls:

                    if i.isCreateIndexSql():
                        continue

                    if i.isAlterSystemSql():
                        up = [sql.originSql() for sql in other.__sqls_as]
                        upgrade_sqls.extend(self.__table_diff)
                        upgrade_sqls.extend(up)
                        break

                    matched = self.__fetch(i)
                    up = i.generateDegradeSql(matched)
                    self.__table_diff.extend(up)
            else:

                modify_flag = False

                for i in other.__sqls:
                    matched = self.__fetch(i)
                    up = i.generateDegradeSql(matched)
                    if not i.isAlterSystemSql() and up:
                        modify_flag = True
                        self.__table_diff.append(up)
                    upgrade_sqls.extend(up)

                if modify_flag:
                    upgrade_sqls.insert(0, load_sql)

        return upgrade_sqls

    def generateUpgradeSql(self, other):
        '''
        generate upgrade sqls
        '''

        self.__table_diff = []

        upgrade_sqls = []
        extra_sqls = []
        load_sql = 'ALTER SYSTEM LOAD DICTIONARY FOR %s' % self.__table_name

        if not other:
            '''
            other is empty or none
            means all sqls are new
            '''

            self.__new_table.append(self.__table_name)

            for i in self.__sqls:
                up, extra = i.generateUpgradeSql(None)
                upgrade_sqls.extend(up)
                extra_sqls.extend(extra)
                if not i.isAlterSystemSql():
                    self.__table_diff.extend(up)

        else:
            '''
            other is not none
            check is all matched
            then check if need drop all index
            then generate the sqls
            '''

            if not isinstance(other, TableGroup):
                raise Exception("Unexpected type %s" % type(other))

            if self.__checkTableSpaceChange(other)\
                    and self.__table_name in self.__sysaux_tables:
                for i in self.__sqls_ct:
                    i._replace("TABLESPACE SYSAUX", "TABLESPACE SYSTEM")
                for i in other.__sqls_ct:
                    i._replace("TABLESPACE SYSAUX", "TABLESPACE SYSTEM")

            if not self.__isAllMatched(other):
                raise Exception("Unmatched item %s"
                                % self.__unmatched[0].originSql())

            if self.__isDropIndex(other):

                upgrade_sqls.append(load_sql)
                for i in self.__sqls:
                    up = []

                    if i.isCreateIndexSql():
                        continue

                    if i.isAlterSystemSql():
                        if extra_sqls:
                            self.__table_diff.extend(extra_sqls)
                        up += other.__geneDropAllIndexSqls()
                        up += [sql.originSql() for sql in self.__sqls_ci]
                        self.__table_diff.extend(up)
                        up += [sql.originSql() for sql in self.__sqls_as]
                        upgrade_sqls.extend(up)
                        break

                    matched = other.__fetch(i)
                    up, extra = i.generateUpgradeSql(matched)
                    upgrade_sqls.extend(up)
                    extra_sqls.extend(extra)
                    self.__table_diff.extend(up)
                    if i.add_table_items():
                        self.__new_table_items.extend(i.add_table_items())
            else:

                for i in self.__sqls:
                    matched = other.__fetch(i)
                    up, extra = i.generateUpgradeSql(matched)
                    extra_sqls.extend(extra)
                    if i.isAlterSystemSql():
                        break
                    upgrade_sqls.extend(up)
                    if i.add_table_items():
                        self.__new_table_items.extend(i.add_table_items())

                if upgrade_sqls:
                    self.__table_diff.extend(upgrade_sqls)
                    self.__table_diff.extend(extra_sqls)
                    upgrade_sqls.insert(0, load_sql)
                upgrade_sqls.append(load_sql)

        return upgrade_sqls, extra_sqls

    def last_generated_diff(self):

        return self.__table_diff


class ViewGroup(object):
    '''
    ex: __01(No.) is a view group
    The No. is unique
    '''
    def __init__(self):
        self.__number = 0
        self.__sqls = ''

    def init(self, number):
        self.__number = number

    def number(self):
        return self.__number

    def add_sql(self, sql):
        self.__sqls += sql

    def all_sqls(self):
        return self.__sqls

    def __same_sqls(self, sql2):
        sql1 = self.all_sqls().strip()
        sql2 = sql2.strip()
        if len(sql1) != len(sql2):
            return False
        return (sql1 == sql2)

    def is_same(self, other):

        if not isinstance(other, ViewGroup):
            return False
        if self.number() != other.number():
            return False
        return self.__same_sqls(other.all_sqls())


class RoleGroup(object):
    '''
    a role group include sqls:
    create role
    grant xxx,xxx|ALL to role
    '''

    def __init__(self, role_sql):
        '''
        init a TableGroup object from greate table sql
        '''

        self.__sqls = []
        self.__sqls.append(role_sql)
        self.__role_name = role_sql.roleName()
        self.__sql_version = role_sql.version()
        self.__diffs = []
        self.__flag = False

    def setFlag(self, flag):
        '''
        set flag for fetch
        '''

        self.__flag = flag

    def tableName(self):
        '''
        empty
        '''
        return ''

    def roleName(self):
        '''
        return the role name
        '''
        return self.__role_name

    def name(self):
        '''
        empty
        '''
        return self.__role_name

    def rename2old(self):
        '''
        do nothing (this group do not need rename)
        '''
        return

    def rename2new(self):
        '''
        do nothing (this group do not need rename)
        '''
        return

    def append(self, sql):
        '''
        append to internal lists
        '''
        self.__sqls.append(sql)

    def isMatched(self, other):
        '''
        if table name is the same
        '''

        if not isinstance(other, RoleGroup):
            return False

        if other.roleName() == self.__role_name:
            return True

        return False

    def create_role_sql(self):
        '''
        return the create role sql in this group
        '''

        for sql in self.__sqls:
            if sql.isCreateRoleSql():
                return sql
        return None

    def grant_sql(self):
        '''
        get the grant sql in this group
        '''

        for sql in self.__sqls:
            if sql.isGrantSql():
                return sql
        return None

    def generateDegradeSql(self, other):
        '''
        generate degrade sqls
        '''
        self.__diffs = []

        if not other:
            for sql in self.__sqls:
                up = sql.generateDegradeSql(None)
                self.__diffs.extend(up)
            return self.__diffs, []

        for sql in self.__sqls:
            if sql.isCreateRoleSql():
                up = sql.generateDegradeSql(other.create_role_sql())
                self.__diffs.extend(up)
            if sql.isGrantSql():
                up = sql.generateDegradeSql(other.grant_sql())
                self.__diffs.extend(up)
        return self.__diffs

    def generateUpgradeSql(self, other):
        '''
        generate upgrade sqls
        '''
        self.__diffs = []

        if not other:
            for sql in self.__sqls:
                up, _ = sql.generateUpgradeSql(None)
                self.__diffs.extend(up)
            return self.__diffs, []

        for sql in self.__sqls:
            if sql.isCreateRoleSql():
                up, _ = sql.generateUpgradeSql(other.create_role_sql())
                self.__diffs.extend(up)
            if sql.isGrantSql():
                up, _ = sql.generateUpgradeSql(other.grant_sql())
                self.__diffs.extend(up)

        return self.__diffs, []

    def isFlagTrue(self):
        '''
        retrun the internal flag
        '''
        return self.__flag

    def last_generated_diff(self):

        return self.__diffs

    def version(self):
        '''
        get the version
        '''

        return self.__sql_version


class InitDbSqls(object):

    def __init__(self):
        '''
        init item list
        '''
        self.__all_items = []
        self.__style = set()
        self.__fast_ref = {}
        self.__fast_ref_role = {}
        self.__last_version = None

    def __str__(self):
        '''
        this function for easy debug
        '''
        s = ''
        for item in self.__all_items:
            s += str(item)

        return s

    def get_last_version(self):
        '''
        get last version
        '''
        return self.__last_version

    def getStyle(self):
        '''
        return table name style
        '''
        if 'old' in self.__style:
            return 'old'
        else:
            return 'new'

    def rename2old(self):
        '''
        rename all item to old style
        '''
        for i in self.__all_items:
            i.rename2old()

    def rename2new(self):
        '''
        rename all item to new style
        '''
        for i in self.__all_items:
            i.rename2new()

    def init(self, sql_file):
        '''
        init from a initdb.sql like file
        '''
        with open(sql_file, 'r') as fp:
            content = fp.read()
            # translate to unix format
            content = content.replace('\r\n', '\n')
            cmds = content.split('/')
            for cmd in cmds:
                if cmd.strip():
                    self.__append(cmd.strip())

        if len(self.__style) != 1:
            raise Exception("Error: mixed table name")

    def __iter__(self):
        '''
        iterator of item list
        '''
        def item_iter():
            for item in self.__all_items:
                yield item
        return item_iter()

    def __check_version(self, sql_item):
        '''
        check table, role, sequence 's version
        '''

        if self.__last_version is None:
            self.__last_version = sql_item.version()
        else:
            ver = sql_item.version()
            if ver >= 1 and self.__last_version == 0:
                raise Exception("Unsupported versions! \n%s" % str(sql_item))
            if ver == 0 and self.__last_version >= 1:
                raise Exception("Unsupported versions! \n%s" % str(sql_item))

    def __append(self, sql):
        '''
        append sql item to item list
        '''

        item = SqlItem(sql)

        if item.isCreateTableSql():

            group = TableGroup(item)
            self.__all_items.append(group)
            self.__fast_ref[item.tableName()] = group
            self.__fast_ref['SYS.'+item.tableName()] = group
            self.__check_version(item)

        elif item.isTableSql():

            try:
                self.__fast_ref[item.tableName()].append(item)

            except Exception as e:
                raise Exception("%s before create table %s"
                                % (item.originSql(), str(e)))

        elif item.isCreateRoleSql():

            group = RoleGroup(item)
            self.__all_items.append(group)
            self.__fast_ref_role[item.roleName()] = group
            self.__check_version(item)

        elif item.isGrantSql():

            try:
                self.__fast_ref_role[item.roleName()].append(item)

            except Exception as e:
                raise Exception("%s before create role %s"
                                % (item.originSql(), str(e)))

        else:
            self.__all_items.append(item)
            self.__check_version(item)

        if item.nameStyle:
            self.__style.add(item.nameStyle)

    def fetch(self, sql):
        '''
        fetch a sql from item list
        '''

        for item in self.__all_items:
            if item.isMatched(sql):
                item.setFlag(True)
                return item
        return None

    def checkUnMatchedItem(self):
        '''
        check if some item have not been fetched
        '''

        unmatched = []
        for item in self.__all_items:
            if not item.isFlagTrue():
                unmatched.append(item)

        if unmatched:
            for item in unmatched:
                print('Error unmatched: %s' % str(item))
            raise Exception("Some item(s) unmatched!")


class InitViewSqls(object):

    def __init__(self):
        '''
        init item list
        '''
        self.__all_items = []

    def init(self, sql_file):
        '''
        init from a initdb.sql like file
        '''
        with open(sql_file, 'r') as fp:
            content = fp.read()
            # translate to unix format
            content = content.replace('\r\n', '\n')
            cmds = content.split('\n/')
            for cmd in cmds:
                if cmd.strip():
                    self.__append(cmd.strip())

    def __iter__(self):
        '''
        iterator of item list
        '''
        def item_iter():
            for item in self.__all_items:
                yield item
        return item_iter()

    def __append(self, sql):
        '''
        append sql item to item list
        '''
        item = SqlItem(sql, is_target=True, ignore=True)
        self.__all_items.append(item)

    def fetch(self, sql):
        '''
        fetch a sql from item list
        '''

        for item in self.__all_items:
            if item.isMatched(sql):
                return item
        return None


class InitIncreaseView(object):

    def __init__(self):
        self.__viewGroups = []
        self.__numberList = []
        self.__path = ""

    def add_group(self, viewGroup):
        if viewGroup.all_sqls().rstrip() != '':
            self.__numberList.append(viewGroup.number())
            self.__viewGroups.append(viewGroup)
        elif viewGroup.number() != 0:
            gnum = viewGroup.number()
            raise Exception("In %s, the %d module is empty!" % (self.__path,
                                                                gnum))

    def init(self, sqlfile):

        self.__path = sqlfile
        with open(sqlfile, 'r') as fp:
            line = fp.readline()
            if line.rstrip() != "--01":
                raise Exception("The %s should start with --01 !" % sqlfile)
            viewgroup = ViewGroup()
            while(line):
                if line.rstrip()[0:2] == '--' and line.rstrip()[2:].isdigit():
                    self.add_group(viewgroup)
                    number = int(line[2:])
                    viewgroup = ViewGroup()
                    viewgroup.init(number)
                else:
                    line = line.replace('\r\n', '\n')
                    viewgroup.add_sql(line)
                line = fp.readline()
            self.add_group(viewgroup)



    def get_all_group(self):
        return self.__viewGroups

    def fetch(self, viewgroup):
        matched = None
        for i in self.__viewGroups:
            if i.is_same(viewgroup):
                matched = i
                break
        return matched

    def check_sequence(self):
        if len(self.__numberList) == 1 and self.__numberList[0] == 0:
            raise Exception("The %s should be divided with -- !" % self.__path)
        if self.__numberList[0] != 1:
            raise Exception("The %s should start with --01 !" % self.__path)
        next_n = 1
        for group in self.get_all_group():
            if group.number() != next_n:
                msg = "In %s, " % self.__path
                msg = "%sthe current is --%d, " % (msg, next_n - 1)
                msg = "%sthe next_n should be --%d, " % (msg, next_n)
                msg = "%sbut it is --%d !" % (msg, group.number())
                raise Exception(msg)
            if group.all_sqls() == []:
                msg = "In %s, " % self.__path
                msg = "%sthe %d module is empty!" % (msg, group.number())
                raise Exception(msg)
            next_n += 1

    def get_numberlist(self):
        return self.__numberList


def writeFile(filename, contents):
    """
    write file
    """

    with open(filename, 'w') as fp:
        fp.write(contents)

    cmd = 'chmod %s %s' % (DefaultValue.KEY_FILE_MODE, filename)
    p = subprocess.Popen(['bash', '-c', cmd],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdoutdata, stderrdata) = p.communicate()
    status = p.returncode
    output = stdoutdata + stderrdata

    gPyVersion = platform.python_version()
    if gPyVersion[0] == "3":
        output = output.decode()

    if status != 0:
        raise Exception("Can not change %s mode.\nError:%s"
                        % (filename, output))


def generateRenameSqlFile(outputFilePath, appeared, is_rename2new=True):
    """
    generate Rename sql file
    """

    if not appeared:
        return

    upgradeRename = os.path.join(outputFilePath, "upgradeRename.sql")

    tables_name = 'SYS_TABLES'
    if is_rename2new:
        s_core_tables = old_core_tables
        t_core_tables = new_core_tables
        s_systables = old_systables
        t_systables = new_systables
    else:
        s_core_tables = new_core_tables
        t_core_tables = old_core_tables
        s_systables = new_systables
        t_systables = old_systables

    updateList = []

    for item in s_core_tables:
        updateNameSql = 'UPDATE %s SET NAME=\'%s\' WHERE NAME=\'%s\''\
                        % (tables_name,
                           t_core_tables[s_core_tables.index(item)], item)
        updateList.append(updateNameSql)
    updateList.append('ALTER SYSTEM LOAD DICTIONARY FOR %s'
                      % tables_name)

    for item in s_systables:
        if item not in s_core_tables:
            if item in appeared:
                updateNameSql = 'ALTER TABLE %s rename to %s'\
                                % (item, t_systables[s_systables.index(item)])
                updateList.append(updateNameSql)
                updateNameSql = 'ALTER SYSTEM LOAD DICTIONARY FOR %s'\
                                % (t_systables[s_systables.index(item)])
                updateList.append(updateNameSql)

    if updateList:
        upgradeRenameString = "\n/\n\n".join(updateList) + "\n/\n"
        writeFile(upgradeRename, upgradeRenameString)


class CmdOption(object):
    """
    :define global parameters
    """
    def __init__(self):
        """
        initial assignment
        """
        self.action = ""
        self.new_init_db = ""
        self.old_init_db = ""
        self.init_db = ""
        self.generate_path = ""
        self.new = ""
        self.old = ""
        self.generate_file = ""
        self.sqls_path = ""
        self.isDegrade = False
        self.isAdjacent = False


# instance global parameter object
g_opts = CmdOption()


def usage():
    """
sql_process.py is a utility to upgrade.

Usage:
  python sql_process.py -? | --help
  python sql_process.py -t generate --new-initdb=NEW_INITDB_SQL_FILE
   --old-initdb=OLD_INITDB_SQL_FILE --outdir=OUT_DIR
    --sqls-path=SQLS_DIR [--degrade]
  python sql_process.py -t gen-view --new=NEW_SQL_FILE --old=OLD_SQL_FILE
   --outfile=OUT_FILE
  python sql_process.py -t gen-dict --initdb=INITDB_SQL_FILE
   --outdir=OUT_DIR
  python sql_process.py -t check-initdb --old-initdb=LOW_INITDB_SQL_FILE
   --new-initdb=HIGH_INITDB_SQL_FILE [--adjacent]
  python sql_process.py -t check-whitelist --sqls-path=SQLS_DIR
  python sql_process.py -t gen-increase-view --new=NEW_SQL_FILE
   --old=OLD_SQL_FILE --outfile=OUT_FILE

General options:
  -t                                Specified the action.
    --new-initdb                    Specified new initdb file.
    --old-initdb                    Specified old initdb file.
    --initdb                        Specified initdb file.
    --outdir                        Specified output directory.
    --new                           Specified new sql file.
    --old                           Specified old sql file.
    --outfile                       Specified output file.
    --sqls-path                     Specified upgrade and degrade sqls' path
    --degrade                       From high version to low version.
    --adjacent                      The two initdb.sql are adjacent versions.
  -?, --help                        Show help information for this utility,
   and exit the command line mode.
    """
    print(usage.__doc__)


def parseCommandLine():
    """
    input: NA
    output: NA
    description: get command line arguments and values
    """

    try:
        (opts, args) = getopt.getopt(sys.argv[1:], "t:?", ["new-initdb=",
                                                           "old-initdb=",
                                                           "initdb=",
                                                           "outdir=",
                                                           "new=",
                                                           "old=",
                                                           "outfile=",
                                                           "sqls-path=",
                                                           "degrade",
                                                           "adjacent",
                                                           "help"])
    except Exception as e:
        print(str(e))
        sys.exit(2)

    # The error is exited if an illegal parameter appears
    if (len(args) > 0):
        raise Exception("Unknown parameter [%s]." % args[0])
    # the command must contains parameters
    if (len(opts) == 0):
        raise Exception("Missing required parameters.")

    # the list of invalid characters
    VALUE_CHECK_LIST = ["|", ";", "&", "$", "<", ">",
                        "`", "\\", "'", "\"", "{", "}",
                        "(", ")", "[", "]", "~", "*", "?", "!", "\n"]
    # start to parse the parameter value
    for (key, value) in opts:
        for role in VALUE_CHECK_LIST:
            if value.find(role) >= 0:
                raise Exception("The value of parameter [%s]"
                                " contains invalid characters:"
                                " '%s'" % (key, role))
        # output version information and exit
        if (key == "--help" or key == "-?"):
            usage()
            sys.exit(0)
        # get parameter value
        elif (key == "-t"):
            g_opts.action = value
        elif (key == "--new-initdb"):
            g_opts.new_init_db = os.path.realpath(value)
        elif (key == "--old-initdb"):
            g_opts.old_init_db = os.path.realpath(value)
        elif (key == "--initdb"):
            g_opts.init_db = os.path.realpath(value)
        elif (key == "--outdir"):
            if value:
                g_opts.generate_path = os.path.realpath(value)
        elif (key == "--new"):
            g_opts.new = os.path.realpath(value)
        elif (key == "--old"):
            g_opts.old = os.path.realpath(value)
        elif (key == "--outfile"):
            if value:
                g_opts.generate_file = os.path.realpath(value)
        elif (key == "--sqls-path"):
            if value:
                g_opts.sqls_path = os.path.realpath(value)
        elif (key == "--degrade"):
            g_opts.isDegrade = True
        elif (key == "--adjacent"):
            g_opts.isAdjacent = True
        else:
            raise Exception("unknown paramter: [-%s]." % key)


def checkFile(parame, filename):
    """
    input: parame: parameter name, string
           filename: file name
    output: NA
    description: determine the file validity of parameter value
    """

    # no value
    if filename == "":
        raise Exception("less necessary parameter [%s]." % parame)
    # file does not exist
    if not os.path.exists(filename):
        raise Exception("The value of necessary parameter"
                        " [%s] is not exists." % parame)
    # not a file type
    elif not os.path.isfile(filename):
        raise Exception("The value of parameter [%s]"
                        " is not file type." % parame)


def parseParams():
    """
    judge the validity of the parameters
    """

    # generate
    if g_opts.action == "generate":
        checkFile("--new-initdb", g_opts.new_init_db)
        checkFile("--old-initdb", g_opts.old_init_db)
        if g_opts.generate_path:
            if not os.path.exists(g_opts.generate_path):
                raise Exception("The value of parameter"
                                " [--outdir] is not exists.")
            if os.path.isfile(g_opts.generate_path):
                raise Exception("The value of parameter"
                                " [--outdir] is not dirctory.")
        else:
            raise Exception("The value of parameter [--outdir] is necessary.")

        if g_opts.sqls_path:
            if not os.path.exists(g_opts.sqls_path):
                raise Exception("The value of parameter"
                                " [--sqls-path] is not exists.")
            if os.path.isfile(g_opts.sqls_path):
                raise Exception("The value of parameter"
                                " [--sqls-path] is not dirctory.")
        else:
            raise Exception("The value of parameter"
                            " [--sqls-path] is necessary.")

    elif g_opts.action == "gen-view":
        if g_opts.new:
            checkFile("--new", g_opts.new)
        if g_opts.old:
            checkFile("--old", g_opts.old)
        if g_opts.generate_file:
            if os.path.exists(g_opts.generate_path):
                if not os.path.isfile(g_opts.generate_path):
                    raise Exception("The value of parameter"
                                    " [--outfile] is not a file.")
        else:
            raise Exception("The value of parameter"
                            " [--outfile] is necessary.")

    elif g_opts.action == "gen-dict":

        checkFile("--initdb", g_opts.init_db)

        if g_opts.generate_path:
            if not os.path.exists(g_opts.generate_path):
                raise Exception("The value of parameter"
                                " [--outdir] is not exists.")
            if os.path.isfile(g_opts.generate_path):
                raise Exception("The value of parameter"
                                " [--outdir] is not dirctory.")
        else:
            raise Exception("The value of parameter [--outdir] is necessary.")

    elif g_opts.action == "check-initdb":

        checkFile("--new-initdb", g_opts.new_init_db)
        checkFile("--old-initdb", g_opts.old_init_db)

    elif g_opts.action == "check-whitelist":

        if g_opts.sqls_path:
            if not os.path.exists(g_opts.sqls_path):
                raise Exception("The value of parameter"
                                " [--sqls-path] is not exists.")
            if os.path.isfile(g_opts.sqls_path):
                raise Exception("The value of parameter"
                                " [--sqls-path] is not dirctory.")
        else:
            raise Exception("The value of parameter"
                            " [--sqls-path] is necessary.")

    elif g_opts.action == "gen-increase-view":
        if g_opts.new:
            checkFile("--new", g_opts.new)
        else:
            raise Exception("The value of parameter"
                            " [--new] is necessary.")
        if g_opts.old:
            checkFile("--old", g_opts.old)
        else:
            raise Exception("The value of parameter"
                            " [--old] is necessary.")
        if g_opts.generate_file:
            if os.path.exists(g_opts.generate_path):
                if not os.path.isfile(g_opts.generate_path):
                    raise Exception("The value of parameter"
                                    " [--outfile] is not a file.")
        else:
            raise Exception("The value of parameter"
                            " [--outfile] is necessary.")
    else:
        raise Exception("The value of parameter [-t] is illegal.")


def get_system_table_names(init_db_obj):
    """
    return all system table name in the obj
    """

    systable_new = []
    it = iter(init_db_obj)

    for i in it:
        if i.tableName() not in systable_new:
            systable_new.append(i.tableName())

    return systable_new


def generate_1_0_degrade(zero_init_db, ver1_init_db):
    """
    generate version 1 to version 0 degrade sql file
    """

    it = iter(ver1_init_db)
    new_init_db = zero_init_db
    output_path = os.path.join(g_opts.generate_path, '01')
    if os.path.exists(output_path):
        for _root, _dirs, _files in os.walk(output_path, topdown=False):
            for fname in _files:
                os.remove(os.path.join(_root, fname))
    else:
        os.mkdir(output_path)

    for i in it:

        # find the contents of new initdb file in the old initdb file
        new_item = new_init_db.fetch(i)

        # get upgrade and rollback statements based on difference
        # between new initdb and old initdb
        i.generateDegradeSql(new_item)

        table_update = []
        name = i.name()
        if name in old_systables:
            name = new_systables[old_systables.index(name)]
        table_update = i.last_generated_diff()
        if table_update:
            outputSqlString = "\n/\n\n".join(table_update) + "\n/\n"
            writeFile(os.path.join(g_opts.generate_path, '01',
                                   name+'_degrade_1.sql'), outputSqlString)


def generate_0_1_upgrade(zero_init_db, ver1_init_db):
    """
    generate version 0 to version 1 upgrade sql file
    """

    it = iter(ver1_init_db)
    old_init_db = zero_init_db
    output_path = os.path.join(g_opts.generate_path, '01')
    if os.path.exists(output_path):
        for _root, _dirs, _files in os.walk(output_path, topdown=False):
            for fname in _files:
                os.remove(os.path.join(_root, fname))
    else:
        os.mkdir(output_path)

    # traversing instances of new initdb files
    for i in it:

        # find the contents of new initdb file in the old initdb file
        old_item = old_init_db.fetch(i)

        # get upgrade and rollback statements based on difference
        # between new initdb and old initdb
        i.generateUpgradeSql(old_item)

        table_update = []
        name = i.name()
        if name in old_systables:
            name = new_systables[old_systables.index(name)]
        table_update = i.last_generated_diff()
        if table_update:
            outputSqlString = "\n/\n\n".join(table_update) + "\n/\n"
            writeFile(os.path.join(g_opts.generate_path, '01',
                                   name+'_upgrade_1.sql'), outputSqlString)


def generate_degrade():
    """
    generate file related operations
    """

    generate_01_degrade = False

    # instance of the old initdb file content as an object
    old_init_db = InitDbSqls()
    old_init_db.init(g_opts.old_init_db)
    styleA = old_init_db.getStyle()

    # instance of the new initdb file content as an object
    new_init_db = InitDbSqls()
    new_init_db.init(g_opts.new_init_db)
    styleB = new_init_db.getStyle()

    if styleA == 'new' and styleB == 'old':
        new_init_db.rename2new()

    old_last_version = old_init_db.get_last_version()
    new_last_version = new_init_db.get_last_version()

    if new_last_version == 0 and old_last_version >= 1:
        generate_01_degrade = True

    initdb_01_file = os.path.join(g_opts.sqls_path, 'initdb_01.sql')
    if not os.path.exists(initdb_01_file):
        raise Exception("Can not find file %s" % initdb_01_file)

    initdb_01 = InitDbSqls()
    initdb_01.init(initdb_01_file)

    if styleA == 'new':
        initdb_01.rename2new()

    if generate_01_degrade:
        generate_1_0_degrade(new_init_db, initdb_01)

    if styleA == 'old' or styleB == 'new':
        systable_new = []
    else:
        systable_new = get_system_table_names(old_init_db)

    generateRenameSqlFile(g_opts.generate_path,
                          systable_new, is_rename2new=False)

    it = iter(old_init_db)

    output_content = ''
    output_file_name = os.path.join(g_opts.generate_path, 'upgradeFile.sql')

    for i in it:
        output_content = generateDegreFiles(i, new_init_db,
                                            initdb_01, old_systables,
                                            new_systables, output_content)
    sql = "ALTER SYSTEM INIT DICTIONARY\n/\n\n"
    output_content += sql
    writeFile(output_file_name, output_content)
    # check if some itme have not been fetched
    new_init_db.checkUnMatchedItem()


def checkDegredFile(item_01, name):

    if item_01:
        degrade_01_file = os.path.join(g_opts.generate_path, '01',
                                       name+'_degrade_1.sql')
        if not os.path.exists(degrade_01_file):
            raise Exception("Cannot find degrade file for"
                            " version_1 to version_0 %s"
                            % degrade_01_file)
    else:
        degrade_01_file = os.path.join(g_opts.sqls_path,
                                       name+'_degrade_1.sql')
        if not os.path.exists(degrade_01_file):
            raise Exception("Cannot find degrade file for"
                            " version_1 to version_0 %s"
                            % degrade_01_file)
        upgrade_01_file = os.path.join(g_opts.sqls_path,
                                       name+'_degrade_1.sql')
        if not os.path.exists(upgrade_01_file):
            raise Exception("Cannot find upgrade file for"
                            " version_0 to version_1 %s"
                            % upgrade_01_file)
    return degrade_01_file


def generateDegreFiles(i, ndb, i01, osystables, nsystables, output):

    diff_files = []
    high_ver = i.version()
    low_ver = 0
    low_item = ndb.fetch(i)
    if low_item:
        low_ver = low_item.version()
    item_01 = i01.fetch(i)
    name = i.name()
    if name in osystables:
        name = nsystables[osystables.index(name)]
    if not low_item:
        degrade_01_file = checkDegredFile(item_01, name)
    else:
        degrade_01_file = os.path.join(g_opts.generate_path, '01',
                                       name+'_degrade_1.sql')
    if os.path.exists(degrade_01_file):
        diff_files.append(degrade_01_file)
    start_ver = max(2, low_ver+1)
    for t in range(start_ver, high_ver+1):
        de_file = os.path.join(g_opts.sqls_path,
                               name+'_degrade_'+str(t)+'.sql')
        up_file = os.path.join(g_opts.sqls_path,
                               name+'_upgrade_'+str(t)+'.sql')
        if not os.path.exists(de_file):
            raise Exception("Cannot find file %s" % de_file)
        if not os.path.exists(up_file):
            raise Exception("Cannot find file %s" % up_file)
        diff_files.append(de_file)
    if isinstance(i, TableGroup):
        sql = "ALTER SYSTEM LOAD DICTIONARY FOR %s\n/\n\n" % i.name()
        output += sql

    white_list_file = os.path.join(g_opts.sqls_path, 'degrade_whitelist')
    wl_rules = get_whitelist_rules(white_list_file)

    for f in diff_files[::-1]:
        check_wl_on_file(f, wl_rules)
        with open(f, 'r') as fp:
            content = fp.read()
            output += content
            output += '\n'
    if low_item and diff_files and isinstance(i, TableGroup):
        sql = "ALTER SYSTEM LOAD DICTIONARY FOR %s\n/\n\n" % i.name()
        output += sql
    return output


def remove_comment(text):
    '''
    remove comment which begin with '--'
    '''

    all_text = []

    if not text:
        return ''

    lines = text.strip().split('\n')
    for line in lines:
        if line.strip().find('--') != 0:
            all_text.append(line)

    return '\n'.join(all_text)


def generate_upgrade():
    """
    generate file related operations
    """

    generate_01_upgrade = False

    # instance of the old initdb file content as an object
    old_init_db = InitDbSqls()
    old_init_db.init(g_opts.old_init_db)
    styleA = old_init_db.getStyle()

    # instance of the new initdb file content as an object
    new_init_db = InitDbSqls()
    new_init_db.init(g_opts.new_init_db)
    styleB = new_init_db.getStyle()

    if styleA == 'old' and styleB == 'new':
        new_init_db.rename2old()

    old_last_version = old_init_db.get_last_version()
    new_last_version = new_init_db.get_last_version()

    if old_last_version == 0 and new_last_version >= 1:
        generate_01_upgrade = True

    initdb_01_file = os.path.join(g_opts.sqls_path, 'initdb_01.sql')
    if not os.path.exists(initdb_01_file):
        raise Exception("Can not find file %s" % initdb_01_file)

    initdb_01 = InitDbSqls()
    initdb_01.init(initdb_01_file)

    if styleA == 'old':
        initdb_01.rename2old()

    if generate_01_upgrade:
        generate_0_1_upgrade(old_init_db, initdb_01)

    if styleA == 'new' or styleB == 'old':
        systable_new = []
    else:
        systable_new = get_system_table_names(new_init_db)

    generateRenameSqlFile(g_opts.generate_path, systable_new)

    it = iter(new_init_db)

    output_content = ''
    output_file_name = os.path.join(g_opts.generate_path, 'upgradeFile.sql')

    for i in it:

        diff_files = []
        diff_files, old_item = generateFileName(diff_files, i, old_systables,
                                                old_init_db, initdb_01,
                                                new_systables)
        if old_item:
            if isinstance(i, TableGroup):
                sql = "ALTER SYSTEM LOAD DICTIONARY FOR %s\n/\n\n" % i.name()
                output_content += sql
        output_content = readDiffFiles(i, diff_files, output_content, styleA)
    sql = "ALTER SYSTEM INIT DICTIONARY\n/\n\n"
    output_content += sql
    writeFile(output_file_name, output_content)
    old_init_db.checkUnMatchedItem()


def generateFileName(diff_files, i, otables, old_db, initdb_01, ntables):

    new_ver = i.version()
    old_ver = 0
    old_item = old_db.fetch(i)
    if old_item:
        old_ver = old_item.version()
    item_01 = initdb_01.fetch(i)
    name = i.name()
    if name in otables:
        name = ntables[otables.index(name)]
    if not old_item:
        upgrade_01_file = checkFileExist(item_01, name)
    else:
        upgrade_01_file = os.path.join(g_opts.generate_path, '01',
                                       name+'_upgrade_1.sql')
    if os.path.exists(upgrade_01_file):
        diff_files.append(upgrade_01_file)
    start_ver = max(2, old_ver+1)
    for t in range(start_ver, new_ver+1):
        up_file = os.path.join(g_opts.sqls_path,
                               name+'_upgrade_'+str(t)+'.sql')
        de_file = os.path.join(g_opts.sqls_path,
                               name+'_degrade_'+str(t)+'.sql')
        if not os.path.exists(up_file):
            raise Exception("Cannot find file %s" % up_file)
        if not os.path.exists(de_file):
            raise Exception("Cannot find file %s" % de_file)
        diff_files.append(up_file)
    return diff_files, old_item


def checkFileExist(item_01, name):
    if item_01:
        upgrade_01_file = os.path.join(g_opts.generate_path, '01',
                                       name+'_upgrade_1.sql')
        if not os.path.exists(upgrade_01_file):
            raise Exception("Cannot find upgrade file for"
                            " version_0 to version_1 %s"
                            % upgrade_01_file)
    else:
        upgrade_01_file = os.path.join(g_opts.sqls_path,
                                       name+'_upgrade_1.sql')
        if not os.path.exists(upgrade_01_file):
            raise Exception("Cannot find upgrade file for"
                            " version_0 to version_1 %s"
                            % upgrade_01_file)
        degrade_01_file = os.path.join(g_opts.sqls_path,
                                       name+'_degrade_1.sql')
        if not os.path.exists(degrade_01_file):
            raise Exception("Cannot find degrade file for"
                            " version_1 to version_0 %s"
                            % degrade_01_file)
    return upgrade_01_file


def readDiffFiles(i, diff_files, output_content, styleA):
    for f in diff_files:
        with open(f, 'r') as fp:
            content = fp.read()
            if styleA == 'old':
                content = content.replace('\r\n', '\n')
                content = remove_comment(content)
                sqls = content.split('\n/')
                sql_items = []
                for sql in sqls:
                    if sql.strip():
                        sql_item = SqlItem(sql,
                                           is_target=True,
                                           ignore=True)
                        sql_item.rename2old()
                        sql_items.append(sql_item)
                content = "\n/\n\n".join([sql.originSql().strip()
                                          for sql in sql_items])\
                          + "\n/\n\n"
                output_content += content
            else:
                output_content += content
                output_content += '\n'

        if diff_files and isinstance(i, TableGroup):
            sql = "ALTER SYSTEM LOAD DICTIONARY FOR %s\n/\n\n" % i.name()
            output_content += sql
    return output_content


def generate():
    """
    generate file related operations
    """
    if g_opts.isDegrade:
        generate_degrade()
    else:
        generate_upgrade()


def generateViewSqlFile(sqlList, outputFilename):
    """
    generate upgrade.sql
    base on sql item list
    """

    # generate file content using the ‘/’ splicing list
    upgradeSqlString = "\n/\n\n".join(sqlList) + "\n/\n"

    # write file
    writeFile(outputFilename, upgradeSqlString)


def generate_view():
    '''
    generate view file's diff
    '''
    drop_sqls = []
    drop_all = False
    drop_jobs = []

    drop_user_jobs = '''BEGIN
                            FOR ITEM IN (SELECT * FROM USER_JOBS WHERE
                                WHAT IN ('WSR$CREATE_SNAPSHOT();',
                                         'WSR$DROP_SNAPSHOT_TIME();',
                                         'WSR$CREATE_SESSION_SNAPSHOT();'))
                            LOOP
                                DBE_TASK.CANCEL(ITEM.JOB);
                            END LOOP;
                            COMMIT;
                        END;'''
    drop_my_jobs = '''BEGIN
                          FOR ITEM IN (SELECT * FROM MY_JOBS WHERE
                              WHAT IN ('WSR$CREATE_SNAPSHOT();',
                                       'WSR$DROP_SNAPSHOT_TIME();',
                                       'WSR$CREATE_SESSION_SNAPSHOT();'))
                          LOOP
                              DBE_TASK.CANCEL(ITEM.JOB);
                          END LOOP;
                          COMMIT;
                      END;'''

    if not g_opts.old:
        return

    # instance of the old view file content as an object
    old_view_sql = InitViewSqls()
    old_view_sql.init(g_opts.old)

    if not g_opts.new:
        drop_all = True
    else:
        # instance of the new view file content as an object
        new_view_sql = InitViewSqls()
        new_view_sql.init(g_opts.new)

    drop_sqls, drop_jobs =\
        init_jobsAndSqls(old_view_sql, new_view_sql, drop_jobs, drop_sqls,
                         drop_all, drop_my_jobs, drop_user_jobs)
    if drop_sqls:
        generateViewSqlFile(drop_sqls, g_opts.generate_file)
    if drop_jobs:
        generateViewSqlFile(drop_jobs, g_opts.generate_file+'_jobs')


def init_jobsAndSqls(oldSql, newSql, dropJobs, dropSqls, is_all, mjob, uJob):

    it = iter(oldSql)
    for i in it:
        if i.isViewDropableSql():
            if is_all:
                new_item = None
            else:
                new_item = newSql.fetch(i)
            if not new_item:
                drop_sql = i.generateDropSql()
                if (i.tableName() == 'USER_JOBS'
                    or i.tableName() == 'SYS.USER_JOBS')\
                        and i.isCreateOrReplaceView():
                    dropJobs.append(uJob)
                if (i.tableName() == 'MY_JOBS'
                    or i.tableName() == 'SYS.MY_JOBS')\
                        and i.isCreateOrReplaceView():
                    dropJobs.append(mjob)
                dropSqls.append(drop_sql)
    return dropSqls, dropJobs


def generate_increase_view():
    '''
    generate increase sql between old initview/initplsql/initwsr
    and new initview/initplsql/initwsr
    '''

    oldview = InitIncreaseView()
    newview = InitIncreaseView()

    oldview.init(g_opts.old)
    newview.init(g_opts.new)
    oldview.check_sequence()
    newview.check_sequence()
    if len(oldview.get_numberlist()) > len(newview.get_numberlist()):
        raise Exception("Please check %s, that module is less than %s"
                        % (g_opts.new, g_opts.old))
    viewgroups = newview.get_all_group()
    sqls = ''
    for viewgroup in viewgroups:
        matched = oldview.fetch(viewgroup)
        if not matched:
            sql = viewgroup.all_sqls()
            number = "--%s\n" % str(viewgroup.number())
            sql = number + sql
            sqls += sql
    if sqls != '':
        writeFile(g_opts.generate_file, sqls)


def generate_dictionary():
    '''
    generate alter system load dictionary for xxx sql file
    '''
    init_db = InitDbSqls()
    init_db.init(g_opts.init_db)
    it = iter(init_db)

    output_content = ''
    output_file_name = os.path.join(g_opts.generate_path, 'upgradeFile.sql')

    for i in it:
        if isinstance(i, TableGroup):
            sql = "ALTER SYSTEM LOAD DICTIONARY FOR %s\n/\n\n" % i.name()
            output_content += sql

    sql = "ALTER SYSTEM INIT DICTIONARY\n/\n\n"
    output_content += sql
    writeFile(output_file_name, output_content)


def check_initdb():
    '''
    check initdb.sql low version -- old  high version -- new
    if table has modified , version must change
    '''
    # instance of the old initdb file content as an object
    low_init_db = InitDbSqls()
    low_init_db.init(g_opts.old_init_db)
    low_version = low_init_db.get_last_version()

    # instance of the new initdb file content as an object
    high_init_db = InitDbSqls()
    high_init_db.init(g_opts.new_init_db)
    high_version = high_init_db.get_last_version()

    error_flag = False

    if low_version == 0:
        return

    if high_version == 0:
        raise Exception("Versions in %s should larger than zero!"
                        % g_opts.new_init_db)

    it = iter(high_init_db)
    for i in it:

        # find the contents of new initdb file in the old initdb file
        low_item = low_init_db.fetch(i)

        # get upgrade and rollback
        # statements based on difference
        # between new initdb and old initdb
        i.generateUpgradeSql(low_item)

        if isinstance(i, TableGroup):
            if g_opts.isDegrade:
                new_objs = []
                modified_objs = []
                new_objs.extend(i.get_new_unique_index())
                modified_objs.extend(i.get_modified_unique_index())
                if new_objs:
                    print("Unsupported new OBJECTS:")
                    print("\n".join(new_objs))
                if modified_objs:
                    print("Unsupported modified OBJECTS:")
                    print("\n".join(modified_objs))
                if new_objs or modified_objs:
                    error_flag = True

        diff = i.last_generated_diff()

        if not low_item:
            continue

        if diff:
            if low_item.version() == i.version():
                raise Exception("Version have to change"
                                " when %s changes." % i.name())
            elif g_opts.isAdjacent:
                if low_item.version() + 1 != i.version():
                    raise Exception("Version of %s shoud add one." % i.name())
            else:
                pass
        else:
            if g_opts.isAdjacent:
                if low_item.version() != i.version():
                    raise Exception("Version of %s"
                                    " shoud not change." % i.name())

    if error_flag:
        sys.exit(1)

    # check if some itme have not been fetched
    low_init_db.checkUnMatchedItem()


def is_upgrade_file(file_name, up_type):
    '''
    if file_name format as:
    xxx_upgrade_NN.sql or
    xxx_degrade_NN.sql where NN is digit numbers
    '''

    fname = file_name.rsplit('.', 1)
    if fname[-1] != 'sql':
        return False
    table_up_ver = fname[0].split('_')
    if len(table_up_ver) < 2:
        return False
    if table_up_ver[-2] == up_type:
        if table_up_ver[-1].isdigit():
            return True
    return False


def check_wl_on_sql(sql, rules):
    '''
    check one sql follow the white list
    '''

    for rule in rules:
        for i in range(len(rule)):
            if rule[i].lower() == 'xxx':
                continue
            try:
                if rule[i].upper() != sql[i].upper():
                    break
            except IndexError:
                break
        else:
            return True
    return False


def check_wl_on_file(file_name, rules):
    '''
    check the sql file follow the white list
    '''

    all_sqls = []
    with open(file_name, 'r') as fp:
        content = fp.read()
        # translate to unix format
        content = content.replace('\r\n', '\n')
        all_sqls = content.split('\n/')

    for sql in all_sqls:
        sql = sql.strip()
        if sql.find('--') == 0:
            continue
        if sql:
            if not check_wl_on_sql(sql.split(), rules):
                raise Exception("Sql %s is not in white list!" % sql)


def get_whitelist_rules(file_name):
    '''
    return the whitelist rules of list
    '''

    rules = []

    with open(file_name, 'r') as fp:
        content = fp.read()
        content = content.replace('\r\n', '\n')
        content = content.split('\n')
        for i in content:
            if i:
                rules.append(i.split())

    return rules


def check_whitelist():
    '''
    check xxx_upgrade_xx.sql xxx_degrade_xx.sql if pass the whitelist
    '''
    search_key = 'upgrade'

    if g_opts.isDegrade:
        white_list_file = os.path.join(g_opts.sqls_path, 'degrade_whitelist')
        search_key = 'degrade'
    else:
        white_list_file = os.path.join(g_opts.sqls_path, 'upgrade_whitelist')

    if not os.path.exists(white_list_file):
        raise Exception("Can not find whitelist"
                        " in %s" % g_opts.sqls_path)

    wl_rules = get_whitelist_rules(white_list_file)

    if os.path.exists(g_opts.sqls_path):
        for _root, _dirs, _files in os.walk(g_opts.sqls_path, topdown=False):
            for fname in _files:
                if is_upgrade_file(fname, search_key):
                    check_wl_on_file(os.path.join(_root, fname), wl_rules)



def main():
    """
    according to different action, the corresponding method is called
    """

    if g_opts.action == "generate":
        generate()

    if g_opts.action == "gen-view":
        generate_view()

    if g_opts.action == "gen-dict":
        generate_dictionary()

    if g_opts.action == "check-initdb":
        check_initdb()

    if g_opts.action == "check-whitelist":
        check_whitelist()

    if g_opts.action == "gen-increase-view":
        generate_increase_view()


if __name__ == '__main__':

    if(os.getuid() == 0):
        print("Failed: Cannot use root user for this operation!")
        sys.exit(1)

    try:
        # analyze command line parameters
        parseCommandLine()
        # analysis parameter validity
        parseParams()
        # core function
        main()
    except Exception as e:
        print(str(e))
        sys.exit(2)
