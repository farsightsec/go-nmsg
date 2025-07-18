# Define backup go macros
%if %{rhel} == 8
%global gopkg %package -n %{goname}-devel \
Summary:	%{summary} \
BuildArch:  noarch \
%description -n %{goname}-devel \
%{common_description}
%global goprep(A) %setup -q
%global gopkginstall for file in $(find . -iname "*.go" \! -iname "*_test.go" \! -iname "main.go" ) ; do \
    echo "%%dir %%{gopath}/src/%%{goipath}/$(dirname $file)" >> devel.file-list ;\
    install -d -p %{buildroot}/%{gopath}/src/%{goipath}/$(dirname $file) ;\
    cp -pav $file %{buildroot}/%{gopath}/src/%{goipath}/$file ;\
    echo "%%{gopath}/src/%%{goipath}/$file" >> devel.file-list ;\
done ;\
sort -u -o devel.file-list devel.file-list
%global gopkgfiles %files -n %{goname}-devel -f devel.file-list
%global gocheck echo "skipping gocheck on rhel8"
%endif

%global debug_package %{nil}
# https://github.com/farsightsec/go-nmsg
%global goipath         github.com/farsightsec/go-nmsg
%global common_description %{expand:
go-nmsg is a pure go implementation of the NMSG container and payload format used by the C nmsg toolkit and library.
This also provides the NMSG vendor base encoding modules Go code.}

Name:           go-nmsg
Version:        0.2.0
Release:        1%{dist}
Summary:        Pure Golang NMSG Library
%gometa
License:        MPLv2.0
URL:            %{gourl}
Source0:        %{gosource}

%description
%{common_description}

BuildRequires:	%{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang} golang-github-dnstap-devel golang-github-pebbe-zmq4 golang-gopkg-yaml-2-devel

Requires: golang-google-protobuf-devel

%if %{rhel} == 9
BuildRequires:	git-lfs
%endif

%package -n %{goname}-devel
Summary:	%{summary}
BuildArch:  noarch
%description -n %{goname}-devel
%{common_description}
Requires: golang-github-dnstap golang-github-dnstap-devel golang-github-pebbe-zmq4

%prep
%goprep -A
%autopatch -p1

%install
%gopkginstall

%if %{with check}
%check
%gocheck
%endif

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

%gopkgfiles
%license LICENSE COPYRIGHT
%doc README.md COPYRIGHT LICENSE
%dir %{gopath}/src/%{goipath}

%changelog
