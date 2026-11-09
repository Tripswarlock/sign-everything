%global debug_package %{nil}

Name:           sign-everything
Version:        1.1.0
Release:        1
Summary:        Mass file signing via CryptoPro CSP
License:        GPL-3.0-only
URL:            https://github.com/Tripswarlock/sign-everything
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
AutoReqProv:    no

Requires:       python3
Requires:       python3-qt5
Requires:       python3-cryptography
Recommends:     python3-keyring
Recommends:     pcscd

%description
Sign Everything is a desktop utility for recursively signing files with
detached signatures using cryptcp from CryptoPro CSP. It supports hardware
tokens, certificate selection, progress, cancellation and remembers the PIN
in the system keyring or an encrypted local vault.

%prep
%setup -q

%build
# Python-приложение, сборка не требуется.

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_datadir}/sign-everything
install -d %{buildroot}%{_datadir}/applications
install -d %{buildroot}%{_datadir}/icons/hicolor/256x256/apps

install -m 0755 Sign-everything.py %{buildroot}%{_datadir}/sign-everything/Sign-everything.py
install -m 0755 packaging/sign-everything-launcher %{buildroot}%{_bindir}/sign-everything
install -m 0644 packaging/sign-everything.desktop %{buildroot}%{_datadir}/applications/sign-everything.desktop
install -m 0644 packaging/sign-everything.png %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/sign-everything.png

%files
%license LICENSE
%doc README.md
%{_bindir}/sign-everything
%{_datadir}/sign-everything/Sign-everything.py
%{_datadir}/applications/sign-everything.desktop
%{_datadir}/icons/hicolor/256x256/apps/sign-everything.png

%changelog
* Mon Nov 09 2026 Dmitry Petrovsky <crashday_game@mail.ru> - 1.1.0-1
- Compact vertical interface.
- About dialog with author and project links.
- GPL-3.0 license.
- DEB and RPM packaging.
- PIN remembering in keyring or encrypted local vault.
