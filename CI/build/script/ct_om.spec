Name:ct_om
Version:3.0.0
Release:00
License:#None
Group:Applications/Productivity
Source:ct_om.tar.gz
Summary:ct_om service
BuildRoot:%{_tmppath}/%{name}-%{version}-%{release}-root
Vendor:Huawei Technologies Co., Ltd
%define user_path /opt/cantian/ct_om
%define __os_install_post %{nil}


%description
This package include:
ServiceTool ct_om module

%prep
%setup -c -n %{name}-%{version}

%install
install -d $RPM_BUILD_ROOT%{user_path}/
cp -a * $RPM_BUILD_ROOT%{user_path}/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}

%files
%defattr(0400,ctmgruser,ctmgruser)
%dir %attr (0770,ctmgruser,ctmgruser) %{user_path}
%dir %attr (0770,ctmgruser,ctmgruser) %{user_path}/service
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/cantian_exporter
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/cantian_exporter/scripts
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/cantian_exporter/exporter
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/cantian_exporter/config
%attr (0600,ctmgruser,ctmgruser) %{user_path}/service/ctcli/commands.json
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctcli
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctcli/params_factory
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/scripts
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/checker
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/logs_collection
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/checker
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/log_tool
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/tasks
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/common
%dir %attr (0700,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/tasks/inspection
%attr (0600,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/format_note.json
%attr (0600,ctmgruser,ctmgruser) %{user_path}/service/cantian_exporter/config/get_ctsql_info.sql
%attr (0600,ctmgruser,ctmgruser) %{user_path}/service/ctmgr/logs_collection/log_packing_progress.json
%{user_path}
