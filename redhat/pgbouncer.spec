%define _use_cares %{?use_cares}%{?!use_cares:0}

%define _sourcedir %{_topdir}/SOURCES/%{name}

%define pgb_version %{?pgbouncer}%{?!pgbouncer:1.6.1}

%define pgb_builddir %{_builddir}/%{name}-%{pgb_version}
%define pgb_git_home https://github.com/pgbouncer/pgbouncer.git

%define pgb_user  pgbouncer
%define pgb_group pgbouncer

Name: pgbouncer
Version: %{pgb_version}
Release: 1%{?dist}
License: Unknown
Group: Applications/Databases

BuildArch: x86_64
Summary: Lightweight connection pooler for PostgreSQL

URL: http://pgbouncer.net

Requires: openssl >= 1.0.1

BuildRequires: git
BuildRequires: openssl >= 1.0.1
BuildRequires: autoconf, automake, libtool, autoconf-archive, pkgconfig
BuildRequires: python-docutils, asciidoc, xmlto

%if %{_use_cares}
BuildRequires: c-ares >= 1.10, c-ares-devel >= 2.0
%else
BuildRequires: libevent >= 2.0, libevent-devel >= 2.0
%endif

Source1: pgbouncer.service

%description
pgbouncer is a PostgreSQL connection pooler with the aim of lowering the performance impact
of opening new connections to PostgreSQL.

%prep
version=%{pgb_version}
if [ ! -d %{name}-%{version}/.git ]; then
  %{__rm} -rf %{name}-%{version}
  git clone %{pgb_git_home} %{name}-%{version}
fi

pushd %{name}-%{version}

git reset -q HEAD --hard
git clean -qffdx
git checkout master
git pull -q
git checkout -q pgb_${version//./_}
git submodule init
git submodule update

%build
pushd %{pgb_builddir}

./autogen.sh

%{_configure} \
  --prefix=/usr \
  --without-udns \
%if %{_use_cares}
  --without-libevent \
  --with-cares=%{_libdir}
%else
  --without-cares \
  --with-libevent=%{_libdir}
%endif

make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cd %{_builddir}/%{name}-%{version}
make DESTDIR=%{buildroot} install
cd %{buildroot}

mkdir -p %{buildroot}/etc/{sysconfig,pgbouncer}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_var}/{run,log}/pgbouncer

cp %{buildroot}%{_defaultdocdir}/pgbouncer/{userlist.txt,pgbouncer.ini} \
   %{buildroot}%{_sysconfdir}/pgbouncer/

cp %{SOURCE1} %{buildroot}%{_unitdir}/
touch %{buildroot}%{_sysconfdir}/sysconfig/pgbouncer

%pre
getent group %{pgb_group} > /dev/null || \
  groupadd -r %{pgb_group}

getent passwd %{pgb_user} > /dev/null || \
  useradd -r -g %{pgb_group} -d %{_var}/run/pgbouncer \
          -s /sbin/nologin -c "PGBouncer Daemon" %{pgb_user}

%post
systemctl daemon-reload
chown %{pgb_user}:%{pgb_group} %{_var}/log/pgbouncer
chown %{pgb_user}:%{pgb_group} %{_var}/run/pgbouncer

%preun
if [ 0$1 -eq 0 ]; then
  systemctl stop pgbouncer.service || :
  systemctl disable pgbouncer.service || :
  getent passwd %{pgb_user} >/dev/null && userdel -f %{pgb_user} || :
  getent group %{pgb_group} >/dev/null && groupdel %{pgb_group} || :
fi

%files
%defattr(-,root,root,-)
%attr(2775,%{pgb_user},%{pgb_group}) %dir %{_sysconfdir}/pgbouncer
%attr(0640,root,%{pgb_group}) %config(noreplace) %{_sysconfdir}/pgbouncer/pgbouncer.ini
%attr(0640,root,%{pgb_group}) %config(noreplace) %{_sysconfdir}/pgbouncer/userlist.txt
%config(noreplace) %{_sysconfdir}/sysconfig/pgbouncer

%{_bindir}/pgbouncer
%{_mandir}
%{_defaultdocdir}
%{_unitdir}/pgbouncer.service
%attr(2775,%{pgb_user},%{pgb_group}) %{_var}/log/pgbouncer
%attr(2775,%{pgb_user},%{pgb_group}) %{_var}/run/pgbouncer

%changelog
* Thur Sep 24 2015 Carl P. Corliss <carl.corliss@finalsite.com>
- initial release