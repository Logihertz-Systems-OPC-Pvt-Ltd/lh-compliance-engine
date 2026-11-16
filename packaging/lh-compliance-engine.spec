Name:           lh-compliance-engine
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-compliance - Multi-Standard Control Maturity Crosswalk Function
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-compliance-engine
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
Automated regulatory compliance crosswalk and control-maturity engine mapping technical security telemetry to SOC 2 Type II, ISO/IEC 27001:2022, CIS Controls v8, PCI-DSS v4.0, and CERT-In.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-compliance ]; then
    install -m 0755 bin/lh-compliance %{buildroot}%{_bindir}/lh-compliance
elif [ -f lh-compliance ]; then
    install -m 0755 lh-compliance %{buildroot}%{_bindir}/lh-compliance
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-compliance-engine.
