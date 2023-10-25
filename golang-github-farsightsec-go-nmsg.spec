%global debug_package %{nil}

# https://github.com/farsightsec/go-nmsg
%global goipath         github.com/farsightsec/go-nmsg
Version:                0.3.0

%gometa

%global common_description %{expand:
Pure go implementation of the NMSG container and payload format used by the C nmsg toolkit and library.}

%global golicences      LICENSE
%global godocs          README.md

Name:           %{goname}
Release:        %autorelease
Summary:        Pure Golang NMSG Library

License:        MPLv2.0
URL:            %{gourl}
Source0:        %{gosource}

%description
%{common_description}

%gopkg

%prep
%goprep

%generate_buildrequires
%go_generate_buildrequires

%install
%gopkginstall

%if %{with check}
%check
%gocheck
%endif

%gopkgfiles

%changelog
%autochangelog
