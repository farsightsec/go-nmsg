%global debug_package %{nil}
# https://github.com/farsightsec/go-nmsg
%global goipath         github.com/farsightsec/go-nmsg

Name:           go-nmsg
Version:        0.2.0
Release:        1%{dist}
Summary:        Pure Golang NMSG Library

%gometa

License:        MPLv2.0
URL:            %{gourl}
Source0:        %{gosource}

BuildRequires:  %{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}
BuildRequires:  golang-github-dnstap-devel
Requires:       golang-google-protobuf-devel

%if %{rhel} == 9

BuildRequires:	git-lfs

%else

BuildRequires:  golang-gopkg-yaml-2-devel

%endif

%description
%{summary}
go-nmsg is a pure go implementation of the NMSG container and payload format used by the C nmsg toolkit and library.
This also provides the NMSG vendor base encoding modules Go code.

%package -n %{goname}-devel
Summary:	%{summary}
BuildArch:  noarch
%description -n %{goname}-devel
go-nmsg is a pure go implementation of the NMSG container and payload format used by the C nmsg toolkit and library.
This also provides the NMSG vendor base encoding modules Go code.

%prep
%setup -q

%build
mkdir -p /builddir/go/src/github.com/farsightsec
ln -s $PWD /builddir/go/src/github.com/farsightsec/go-nmsg

%install
# installs source code for building other projects
# find all *.go but no *_test.go files and generate file-list
# and no main.go as no executables her
install -d -p %{buildroot}/%{gopath}/src/%{goipath}/
for file in $(find . -iname "*.go" \! -iname "*_test.go" \! -iname "main.go" ) ; do
    echo "%%dir %%{gopath}/src/%%{goipath}/$(dirname $file)" >> file-list
    install -d -p %{buildroot}/%{gopath}/src/%{goipath}/$(dirname $file)
    cp -pav $file %{buildroot}/%{gopath}/src/%{goipath}/$file
    echo "%%{gopath}/src/%%{goipath}/$file" >> file-list
done
sort -u -o file-list file-list

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

%files -n %{goname}-devel -f file-list
# TODO: LICENSE
#%license LICENSE COPYRIGHT
%doc README.md COPYRIGHT LICENSE
%dir %{gopath}/src/%{provider}.%{provider_tld}/%{project}
%changelog
