WITH 
jennifer_0 AS (select  
    ref_10.GRANTOR as c0, 
    ref_8.GRANTOR as c1, 
    
      min(
        cast(ref_9.GRANTOR as BINARY_INTEGER)) over (partition by subq_1.c0 order by subq_0.c1,subq_1.c2,ref_10.UID,ref_8.GRANTOR,ref_4.GRANTOR,ref_10.GRANTOR,ref_8.GRANTOR) as c2, 
    ref_4.UID as c3, 
    ref_5.GRANTOR as c4, 
    subq_1.c0 as c5, 
    ref_5.GRANTOR as c6, 
    
      count(
        cast(cast(null as BINARY_BIGINT) as BINARY_BIGINT)) over (partition by ref_9.GRANTOR,ref_8.GRANTOR order by ref_4.GRANTOR) as c7, 
    subq_1.c1 as c8, 
    ref_10.GRANTOR as c9, 
    ref_10.GRANTOR as c10, 
    ref_5.GRANTOR as c11
  from 
    ((select  
            ref_0.GRANTOR as c0, 
            ref_1.GRANTOR as c1, 
            ref_1.GRANTOR as c2
          from 
            (SYS.SYS_USER_PRIVS as ref_0)
              inner join (SYS.SYS_USER_PRIVS as ref_1)
              on (ref_0.UID = ref_1.UID )
          where (EXISTS (
              select  
                  ref_0.GRANTOR as c0
                from 
                  SYS.SYS_USER_PRIVS as ref_2
                where (false) 
                  or ((false) 
                    or (ref_2.GRANTOR is NULL)))) 
            or ((true) 
              or (ref_1.GRANTOR is NULL))
          limit 22) as subq_0)
      inner join (((select  
              ref_3.GRANTOR as c0, 
              ref_3.GRANTOR as c1, 
              ref_3.GRANTOR as c2, 
              ref_3.GRANTOR as c3
            from 
              SYS.SYS_USER_PRIVS as ref_3
            where true) as subq_1)
        inner join (((SYS.SYS_USER_PRIVS as ref_4)
            inner join (SYS.SYS_USER_PRIVS as ref_5)
            on ((((true) 
                    or (ref_5.GRANTOR is not NULL)) 
                  or ((((true) 
                        and (false)) 
                      and (true)) 
                    or (((EXISTS (
                          select  
                              78 as c0, 
                              ref_5.GRANTOR as c1
                            from 
                              SYS.SYS_USER_PRIVS as ref_6
                            where true)) 
                        and (ref_4.UID is NULL)) 
                      or (EXISTS (
                        select  
                            ref_5.GRANTOR as c0, 
                            ref_7.GRANTOR as c1, 
                            (select GRANTOR from SYS.SYS_USER_PRIVS limit 1 offset 34)
                               as c2, 
                            ref_7.GRANTOR as c3, 
                            ref_4.GRANTOR as c4, 
                            ref_4.GRANTOR as c5, 
                            ref_7.GRANTOR as c6, 
                            14 as c7, 
                            ref_4.GRANTOR as c8, 
                            ref_5.GRANTOR as c9, 
                            ref_4.GRANTOR as c10, 
                            ref_7.GRANTOR as c11, 
                            ref_4.GRANTOR as c12, 
                            ref_4.UID as c13
                          from 
                            SYS.SYS_USER_PRIVS as ref_7
                          where false
                          limit 55))))) 
                or (true)))
          right join ((SYS.SYS_USER_PRIVS as ref_8)
            left join ((SYS.SYS_USER_PRIVS as ref_9)
              inner join (SYS.SYS_USER_PRIVS as ref_10)
              on (ref_9.UID = ref_10.UID ))
            on (ref_8.UID = ref_9.UID ))
          on (((false) 
                and (false)) 
              and ((((ref_10.UID is NULL) 
                    or (((true) 
                        or (false)) 
                      or (ref_9.GRANTOR is NULL))) 
                  or (false)) 
                or (((((ref_10.GRANTOR is not NULL) 
                        or ((false) 
                          and (false))) 
                      and (ref_5.GRANTOR is not NULL)) 
                    or (ref_9.GRANTOR is not NULL)) 
                  and (ref_4.GRANTOR is not NULL)))))
        on (((ref_5.UID is NULL) 
              or (ref_9.GRANTOR is NULL)) 
            and ((subq_1.c1 is not NULL) 
              and (EXISTS (
                select  
                    ref_5.GRANTOR as c0
                  from 
                    SYS.SYS_USER_PRIVS as ref_11
                  where true
                  limit 96)))))
      on (EXISTS (
          select  
              subq_1.c3 as c0, 
              subq_0.c2 as c1, 
              subq_1.c1 as c2, 
              ref_12.GRANTOR as c3, 
              51 as c4
            from 
              SYS.SYS_USER_PRIVS as ref_12
            where 89 is not NULL
            limit 109))
  where subq_1.c1 is not NULL)
select  
    ref_17.GRANTOR as c0, 
    ref_16.GRANTOR as c1, 
    subq_3.c0 as c2, 
    ref_14.GRANTOR as c3, 
    case when (subq_3.c0 is NULL) 
        or (((false) 
            and ((true) 
              or (true))) 
          or (false)) then ref_14.GRANTOR else ref_14.GRANTOR end
       as c4, 
    ref_16.GRANTOR as c5, 
    ref_14.GRANTOR as c6, 
    subq_2.c2 as c7, 
    ref_14.GRANTOR as c8, 
    subq_3.c0 as c9
  from 
    ((select  
            ref_13.UID as c0, 
            ref_13.GRANTOR as c1, 
            ref_13.GRANTOR as c2
          from 
            SYS.SYS_USER_PRIVS as ref_13
          where ref_13.GRANTOR is not NULL
          limit 139) as subq_2)
      inner join (((SYS.SYS_USER_PRIVS as ref_14)
          inner join ((select  
                ref_15.UID as c0
              from 
                SYS.SYS_USER_PRIVS as ref_15
              where ref_15.GRANTOR is NULL) as subq_3)
          on ((ref_14.GRANTOR is NULL) 
              and ((false) 
                and (true))))
        right join ((SYS.SYS_USER_PRIVS as ref_16)
          right join (SYS.SYS_USER_PRIVS as ref_17)
          on (ref_17.GRANTOR is NULL))
        on (ref_14.GRANTOR = ref_16.UID ))
      on (subq_3.c0 is NULL)
  where subq_2.c1 is NULL
  limit 155
;
