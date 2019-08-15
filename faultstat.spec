%define version 0.01.01
%define debug_package %{nil}

Name:           faultstat
Version:        %{version}
Release:        1%{?dist}
Summary:        Page fault monitoring tool

License:        LGPLv3+
URL:            https://github.com/ColinIanKing/faultstat
Source0:        https://github.com/ColinIanKing/faultstat/archive/V%{version}.tar.gz

BuildRequires:  ncurses-devel ncurses gcc
Requires:       ncurses

%description
Faultstat reports the page fault activity of processes
running on a system. The tool supports a 'top' like mode
to dynamically display the top page faulting processes.

%prep
%setup -q

%build
make

%install
mkdir -p %{buildroot}/%{_bindir}
install -m 0755 %{name} %{buildroot}/%{_bindir}/%{name}

mkdir -p %{buildroot}/%{_mandir}/man8/
install -m 0755 %{name}.8 %{buildroot}/%{_mandir}/man8/%{name}.8


%files
%{_bindir}/%{name}
%{_mandir}/man8/%{name}.8.*

%changelog
* Wed Aug 14 2019 <imilos@gmail.com> 0.01.01
- Initial release to Fedora Copr

