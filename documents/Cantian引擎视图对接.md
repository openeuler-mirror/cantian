## 参天视图对接

### 原理
1. 参天在拉起时已经创好了表，并会在参天侧插入数据；
2. MySQL侧拉起后创表定义；
3. 根据同名的MySQL和参天表，可以在MySQL侧查询参天数据；

### 对接一个新的参天系统表/系统视图到MySQL
（以系统视图 `SYS.DV_VERSION` 举例）

0. **前置条件**：在参天拉起时创了用户 `cantian`;

1. **创别名**：在 `initview.sql` 中创建 `SYS.DV_VERSION` 的别名 `cantian.dv_version`。将 `SYS` 改为 `cantian`, 表名/视图名改为小写名（不一定和原名相同）。
```sql
CREATE OR REPLACE SYNONYM cantian.dv_version FOR SYS.DV_VERSION
```

2. **改定义**： 系统表定义在 `knl_ctlg.c` 和 `initdb.sql` 中，系统视图在 `srv_view.c` 中。`参天列数据类型` -> `MySQL列数据类型` 转换关系如下：
    - `DATE` -> `DATETIME` 
    - `VARCHAR(n)` -> `VARCHAR(n)` 
    - `BINARY_INTEGER` -> `INTEGER` 
    - `BINARY_BIGING` -> `BIGING` 
    - `BINARY(n)` -> `VARBINARY(n)` 
    - `RAW` -> `BINARY/VARBINARY` 
    - `date` -> `datetime` 
    - `date` -> `datetime` 

3. **创新表**： 在文件 `cantian_defs.sql` 中新增表 `cantian.dv_version` 的定义。 
```sql
-- 提供内核版本信息: DV_VERSION
CREATE TABLE IF NOT EXISTS `cantian`.`dv_version`(
  `VERSION` VARCHAR(80)
) ENGINE = CTC DEFAULT CHARSET=utf8mb3 COLLATE=utf8_bin;
```
