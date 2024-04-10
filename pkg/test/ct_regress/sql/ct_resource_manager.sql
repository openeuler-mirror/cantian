drop user if exists resmgr_user_1;
create user resmgr_user_1 identified by Cantian_234;
grant connect,resource to resmgr_user_1;

--unit test for create_plan
call DBE_RSRC_MGR.create_plan(name => 'test_plan', comment => 'Test resource plan');
call DBE_RSRC_MGR.create_plan(name => 'test_plan', comment => 'Duplicate test resource plan');
call DBE_RSRC_MGR.create_plan(name => 'plan_with_no_comm');
call DBE_RSRC_MGR.create_plan(comment => 'Plan with no name');
call DBE_RSRC_MGR.create_plan(); --plan with nothing
call DBE_RSRC_MGR.create_plan(name => 'plan_with_inv_arg', comment => 'Plan with invalid argument', num_rules => 3);
call DBE_RSRC_MGR.create_plan(name => '', comment => 'plan with empty string name');
call DBE_RSRC_MGR.create_plan(name => 'Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', comment => 'plan with a long name');
call DBE_RSRC_MGR.create_plan(name => 'Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', comment => 'plan with too long name');
call DBE_RSRC_MGR.create_plan(name => '12345', comment => 'plan with invalid plan name');
SELECT NAME, NUM_RULES, DESCRIPTION FROM SYS_RSRC_PLANS ORDER BY 1;

--unit test for update_plan
call DBE_RSRC_MGR.update_plan(name=> 'test_plan', comment => 'Plan with comment updated');
SELECT NAME, NUM_RULES, DESCRIPTION FROM SYS_RSRC_PLANS where name = upper('test_plan');

call DBE_RSRC_MGR.update_plan(name=> 'test_plan');
SELECT NAME, NUM_RULES, DESCRIPTION FROM SYS_RSRC_PLANS where name = upper('test_plan');
call DBE_RSRC_MGR.update_plan(name=> 'test_plan', comment => 'Plan with comment updated');
call DBE_RSRC_MGR.update_plan(); --update with nothing
call DBE_RSRC_MGR.update_plan(name=> 'test_plan', comment => 'Plan with comment updated');
call DBE_RSRC_MGR.update_plan(name => 'none_exists_plan');

--unit test for delete_plan
call DBE_RSRC_MGR.delete_plan(name => 'plan_with_no_comm');
call DBE_RSRC_MGR.delete_plan(name => 'plan_with_no_comm');
call DBE_RSRC_MGR.delete_plan();
call DBE_RSRC_MGR.delete_plan(name => '');
SELECT NAME, NUM_RULES, DESCRIPTION FROM SYS_RSRC_PLANS order by 1;

--unit test for create_control_group
call DBE_RSRC_MGR.create_control_group(name => 'cgroup_1', comment => 'Control group for user resmgr_user_1');
call DBE_RSRC_MGR.create_control_group(name => 'cgroup_2', comment => 'Control group for user resmgr_user_2');
call DBE_RSRC_MGR.create_control_group(name => 'Cgroup_1', comment => 'Control group for user resmgr_user_1');
call DBE_RSRC_MGR.create_control_group(name => '', comment => 'Control group for user resmgr_user_1');
call DBE_RSRC_MGR.create_control_group(name => 'cgroup_3');
call DBE_RSRC_MGR.create_control_group(name => 'default_groups');
call DBE_RSRC_MGR.create_control_group(name => 'consumer groups');

--unit test for update_control_group
call DBE_RSRC_MGR.update_control_group(name => 'cgroup_1', comment => 'Updated control group for user resmgr_user_1');
SELECT NAME, DESCRIPTION FROM SYS_RSRC_CONTROL_GROUPS order by 1;
call DBE_RSRC_MGR.delete_control_group(name => 'cgroup_3');
SELECT NAME, DESCRIPTION FROM SYS_RSRC_CONTROL_GROUPS order by 1;

--unit test for ADD_USER_TO_CONTROL_GROUP
call DBE_RSRC_MGR.ADD_USER_TO_CONTROL_GROUP(name => 'db_user', control_group => 'cgroup_1');
call DBE_RSRC_MGR.ADD_USER_TO_CONTROL_GROUP(name => 'db_user', control_group => 'cgroup_2');
call DBE_RSRC_MGR.ADD_USER_TO_CONTROL_GROUP(name => 'db_user', control_group => 'cgroup_3');
call DBE_RSRC_MGR.ADD_USER_TO_CONTROL_GROUP(name => 'username', control_group => 'cgroup_1');
call DBE_RSRC_MGR.ADD_USER_TO_CONTROL_GROUP(name => 'username', control_group => 'cgroup_1');
select * from sys_rsrc_group_mappings order by 1,2;
call DBE_RSRC_MGR.ADD_USER_TO_CONTROL_GROUP(name => 'db_user');
select * from sys_rsrc_group_mappings order by 1,2;


call DBE_RSRC_MGR.create_plan_rule(
	plan_name => 'test_plan',
	control_group => 'cgroup_1',
	comment => 'plan rule for test_plan, cgroup_1',
	cpu => 20,
	sessions => 50,
	active_sess => 20,
	queue_time => 30,
	temp_pool => 64,
	max_iops => 1000,
	max_commits => 1000,
	max_exec_time => 100
);

call DBE_RSRC_MGR.create_plan_rule(
	plan_name => 'test_plan',
	control_group => 'cgroup_2',
	comment => 'plan rule for test_plan, cgroup_2',
	cpu => 40,
	sessions => 50,
	active_sess => 30,
	queue_time => 30,
	max_iops => 1000,
	max_commits => 1000,
	max_exec_time => 100
);

select * from sys_rsrc_plan_rules order by 1,2;

call DBE_RSRC_MGR.update_plan_rule(
	plan_name => 'test_plan',
	control_group => 'cgroup_1',
	comment => 'Plan rule for test_plan, cgroup_1'
);

call DBE_RSRC_MGR.update_plan_rule(
	plan_name => 'test_plan',
	control_group => 'cgroup_2',
	comment => 'Plan rule for test_plan, cgroup_2',
	cpu => 80,
	sessions => 200,
	max_exec_time => -1
);
select * from sys_rsrc_plan_rules ORDER BY 1,2;

--cpu overflow
call DBE_RSRC_MGR.update_plan_rule(
	plan_name => 'test_plan',
	control_group => 'cgroup_2',
	comment => 'Plan rule for test_plan, cgroup_2',
	cpu => 101,
	sessions => 200,
	max_exec_time => -1
);
--sessions overflow
call DBE_RSRC_MGR.update_plan_rule(
	plan_name => 'test_plan',
	control_group => 'cgroup_2',
	sessions => -2
);
select * from sys_rsrc_plan_rules order by 1,2;

call DBE_RSRC_MGR.VALIDATE_PLAN(name=>'test_plan');

call DBE_RSRC_MGR.update_plan_rule(
    plan_name => 'test_plan',
    control_group => 'cgroup_2',
    temp_pool => 1000
);
call DBE_RSRC_MGR.VALIDATE_PLAN(name=>'test_plan');
call DBE_RSRC_MGR.update_plan_rule(
    plan_name => 'test_plan',
    control_group => 'cgroup_2',
    temp_pool => -1
);
alter system set resource_plan = 'test_plan';
select name,sessions,active_sessions,vm_pages from dv_rsrc_control_group;
call DBE_RSRC_MGR.delete_plan(name => 'test_plan');
call DBE_RSRC_MGR.delete_control_group(name => 'cgroup_1');

--privilege test
conn resmgr_user_1/Cantian_234@127.0.0.1:1611
call DBE_RSRC_MGR.delete_plan(name => 'test_plan');
call DBE_RSRC_MGR.delete_control_group(name => 'cgroup_1');
call DBE_RSRC_MGR.create_plan(name => 'test_plan_1', comment => 'Resource plan created by normal user');

conn / as sysdba
alter system set resource_plan = 'test_plan_1';
alter system set resource_plan = '';
call DBE_RSRC_MGR.delete_plan(name => 'Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
call DBE_RSRC_MGR.delete_plan(name => 'test_plan');
call DBE_RSRC_MGR.delete_control_group(name => 'cgroup_1');
call DBE_RSRC_MGR.delete_control_group(name => 'cgroup_2');

select * from dv_rsrc_control_group order by 1;
drop user resmgr_user_1 cascade;

--plsql/block
declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.create_control_group('nicec_test_group' || i,'dsvfds' || i);
   end loop;
end;
/
select name, description from sys.sys_rsrc_control_groups order by name;

declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.update_control_group('nicec_test_group' || i, 'updated_dsvfds' || i);
   end loop;
end;
/
select name, description from sys.sys_rsrc_control_groups order by name;

declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.create_plan('nicec_test_plan' || i,'dsvfds' || i);
   end loop;
end;
/
select name, description from sys.sys_rsrc_plans order by name;

declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.update_plan('nicec_test_plan' || i, 'updated_dsvfds' || i);
   end loop;
end;
/
select name, description from sys.sys_rsrc_plans order by name;


declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.create_plan_rule(
     plan_name=>'nicec_test_plan' || i,
     control_group=>'nicec_test_group' || i,
     comment=>'plan rule for nicec_test_plan' || i || ', nicec_test_group' || i,
     cpu=>10*i);
   end loop;
end;
/
select * from sys.sys_rsrc_plan_rules order by 1,2;

declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.update_plan_rule(
     plan_name=>'nicec_test_plan' || i,
     control_group=>'nicec_test_group' || i,
     comment=>'updated plan rule for nicec_test_plan' || i || ', nicec_test_group' || i,
     cpu=>10*i);
   end loop;
end;
/
select * from sys.sys_rsrc_plan_rules order by 1,2;

declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.REMOVE_PLAN_RULE(
     plan_name=>'nicec_test_plan' || i,
     control_group=>'nicec_test_group' || i);
   end loop;
end;
/

declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.ADD_USER_TO_CONTROL_GROUP('db_user', 'nicec_test_group' || i);
   end loop;
end;
/

--clean up
declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.delete_control_group('nicec_test_group' || i);
   end loop;
end;
/

declare 
BEGIN
   FOR i IN 1..10 LOOP
   DBE_RSRC_MGR.delete_plan('nicec_test_plan' || i);
   end loop;
end;
/