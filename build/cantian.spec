Name:cantian
Version:24.06
Release:00
License:#None
Group:Applications/Productivity
Source:cantian.tar.gz
Summary:cantian service
BuildRoot:%{_tmppath}/%{name}-%{version}-%{release}-root
Vendor:Huawei Technologies Co., Ltd
%define user_path /opt/cantian/image
%define __os_install_post %{nil}


%description
This package include:
ServiceTool cantian module

%prep
%setup -c -n %{name}-%{version}

%install
install -d $RPM_BUILD_ROOT%{user_path}/
cp -a * $RPM_BUILD_ROOT%{user_path}/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}

%post
chmod +x -R %{user_path}

%files
%defattr(-,root,root)
%{user_path}