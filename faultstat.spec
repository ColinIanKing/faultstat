%define version 0.01.01
%define debug_package %{nil}

Name:           faultstat
Version:        %{version}
Release:        1%{?dist}
Summary:        Page fault monitoring tool

License:        LGPLv3+
URL:            https://github.com/ColinIanKing/faultstat
Source0:        https://github.com/ColinIanKing/faultstat/releases/V%{version}.tar.gz

BuildRequires:  ncurses-devel
Requires:       ncurses

%description
Faultstat reports the page fault activity of processes
running on a system. The tool supports a 'top' like mode
to dynamically display the top page faulting processes.

%prep
#%autosetup -n 

%build
make

%install
%make_install

%files
##%{_bindir}/gtk3-version-polo
#%{_bindir}/polo-gtk

%changelog
* Wed Aug 14 2019 <imilos@gmail.com> 0.01.01
- Initial release to Fedora Copr


