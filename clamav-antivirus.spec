# ClamAV Antivirus GUI — paquet RPM (Fedora et dérivés). Construit par build-rpm.sh à partir de l'arborescence
# commune (build-deb.sh --stage-only) : mêmes fichiers que le paquet Debian, manifeste d'intégrité signé inclus.
Name:           clamav-antivirus
Version:        %{version}
Release:        1%{?dist}
Summary:        ClamAV Antivirus GUI — interface graphique et service de protection pour ClamAV
License:        Proprietary
URL:            https://github.com/kahsky/clamav-antivirus
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz

Requires:       python3 >= 3.8
Requires:       python3-gobject
Requires:       python3-pyudev
Requires:       webkit2gtk4.1
Requires:       libayatana-appindicator-gtk3
Requires:       gtk3
Requires:       polkit
Requires:       clamav
Requires:       clamd
Requires:       clamav-update
Requires:       lynis
Requires:       unhide
Requires:       chkrootkit
Requires:       msmtp
Requires:       zenity
Requires:       systemd
Requires:       udisks2
Requires:       firewalld
Requires:       dnf-plugins-core
Recommends:     gnome-shell-extension-appindicator
Recommends:     timeshift
Recommends:     rsync
Recommends:     rclone
Recommends:     gocryptfs
Recommends:     flatpak
Recommends:     dnf-automatic
%{?systemd_requires}

%description
Interface graphique moderne pour ClamAV avec un service système : analyses complètes sans mot de passe,
mises à jour planifiées, surveillance des rafales d'écritures (fanotify), analyse des clés USB avant
mise à disposition, état du système (avis de sécurité dnf et CVE), pare-feu firewalld piloté depuis
l'application, vérification d'intégrité (rpm -V, chkrootkit, unhide, Lynis, noyau, processus),
notifications par courrier, interface en français, anglais, allemand et italien.
Développé par Dukiwi SA, Estavayer-le-Lac, Suisse.

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a tree/. %{buildroot}/
install -D -m 644 dukiwi-clamav.repo %{buildroot}%{_sysconfdir}/yum.repos.d/dukiwi-clamav.repo

%post
mkdir -p /var/lib/clamav-antivirus
if [ "$1" = "1" ] && [ ! -f /var/lib/clamav-antivirus/state.json ]; then
    touch /var/lib/clamav-antivirus/first-scan-pending
fi
# clamd@scan : Fedora livre LocalSocket commenté dans scan.conf ; sans lui, pas de moteur clamd (clamscan lent)
if [ -f /etc/clamd.d/scan.conf ] && ! grep -q '^LocalSocket' /etc/clamd.d/scan.conf; then
    sed -i '0,/^#\s*LocalSocket\s/s|^#\s*LocalSocket\s\+\(\S\+\)|LocalSocket \1|' /etc/clamd.d/scan.conf
    grep -q '^LocalSocket' /etc/clamd.d/scan.conf || echo 'LocalSocket /run/clamd.scan/clamd.sock' >> /etc/clamd.d/scan.conf
fi
systemctl enable clamd@scan.service >/dev/null 2>&1 || true
systemctl enable clamav-freshclam.service >/dev/null 2>&1 || true
systemctl start clamav-freshclam.service >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true
udevadm control --reload-rules >/dev/null 2>&1 || true
/opt/clamav-antivirus/clamav-antivirus-browser-setup install >/dev/null 2>&1 || true
systemctl enable clamav-antivirus-daemon.service >/dev/null 2>&1 || true
systemctl enable clamav-antivirus-update.timer >/dev/null 2>&1 || true
systemctl restart clamav-antivirus-daemon.service >/dev/null 2>&1 || true
systemctl start clamav-antivirus-update.timer >/dev/null 2>&1 || true
pkill -f "/opt/clamav-antivirus/clamav-antivirus.py" >/dev/null 2>&1 || true
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database /usr/share/applications/ >/dev/null 2>&1 || true; fi
if command -v restorecon >/dev/null 2>&1; then restorecon -R /opt/clamav-antivirus /var/lib/clamav-antivirus >/dev/null 2>&1 || true; fi

%preun
if [ "$1" = "0" ]; then
    /opt/clamav-antivirus/clamav-antivirus-browser-setup remove >/dev/null 2>&1 || true
    pkill -f "/opt/clamav-antivirus/clamav-antivirus.py" >/dev/null 2>&1 || true
    systemctl stop clamav-antivirus-update.timer >/dev/null 2>&1 || true
    systemctl disable clamav-antivirus-update.timer >/dev/null 2>&1 || true
    systemctl stop clamav-antivirus-daemon.service >/dev/null 2>&1 || true
    systemctl disable clamav-antivirus-daemon.service >/dev/null 2>&1 || true
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || true
udevadm control --reload-rules >/dev/null 2>&1 || true

%files
/opt/clamav-antivirus
%{_unitdir}/clamav-antivirus-daemon.service
%{_unitdir}/clamav-antivirus-update.service
%{_unitdir}/clamav-antivirus-update.timer
%{_udevrulesdir}/*.rules
%{_datadir}/applications/clamav-antivirus.desktop
%{_datadir}/nemo/actions/clamav-antivirus-nemo.nemo_action
%{_datadir}/polkit-1/actions/com.dukiwi.clamav-antivirus.policy
%config(noreplace) %{_sysconfdir}/xdg/autostart/clamav-antivirus-autostart.desktop
%config(noreplace) %{_sysconfdir}/yum.repos.d/dukiwi-clamav.repo

%changelog
* Thu Oct 15 2026 Dukiwi SA <info@dukiwi.ch> - %{version}-1
- Prise en charge de Fedora : dnf, rpm, firewalld, SELinux
