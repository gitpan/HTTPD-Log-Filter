use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'HTTPD::Log::Filter',
    'EXE_FILES'         => [ 'exclude_robots' ],
    'VERSION'     	=> '1.01',
    'PREREQ_PM'		=> {
        LWP::Simple => undef,
        Getopt::Long => undef,
    },
);
