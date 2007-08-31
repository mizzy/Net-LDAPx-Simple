use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::LDAPx::Simple',
    AUTHOR              => 'Gosuke Miyashita <gosukenator@gmail.com>',
    VERSION_FROM        => 'lib/Net/LDAPx/Simple.pm',
    ABSTRACT_FROM       => 'lib/Net/LDAPx/Simple.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'version'    => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-LDAPx-Simple-*' },
);
