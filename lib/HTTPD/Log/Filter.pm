package HTTPD::Log::Filter;

#------------------------------------------------------------------------------
#
# Standard pragmas
#
#------------------------------------------------------------------------------

use strict;
use warnings;

#------------------------------------------------------------------------------
#
# ModuleS
#
#------------------------------------------------------------------------------

use IO::File;

my $fields_order = {
    CLF => [ qw(
        host_re
        ident_re
        authexclude_re
        date_re
        request_re
        status_re
        bytes_re
    ) ],
    ELF => [ qw(
        host_re
        ident_re
        authexclude_re
        date_re
        request_re
        status_re
        bytes_re
        referer_re
        agent_re
    ) ],
    XLF => [ qw(
        host_re
        ident_re
        authexclude_re
        date_re
        request_re
        status_re
        bytes_re
        referer_re
        agent_re
        junk
    ) ],
};

my %in_quotes = map { $_ => 1 } qw(
    request_re
    referer_re
    agent_re
);

my %generic_fields_re = (
    host_re     => '\S+',
    ident_re    => '\S+',
    authexclude_re => '\S+',
    date_re     => '\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]',
    request_re  => '".*?"',
    status_re   => '\d{3}',
    bytes_re    => '(?:-|\d+)',
    referer_re  => '".*?"',
    agent_re    => '".*?"',
    junk        => '.*',
);

my @options = qw(
    exclusions_file
    invert
);

use vars qw( $VERSION );

$VERSION = '1.02';

#------------------------------------------------------------------------------
#
# Constructor
#
#------------------------------------------------------------------------------

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = bless {}, $class;
    $self->{exclusions_file} = delete $args{exclusions_file};
    if ( $self->{exclusions_file} )
    {
        $self->{efh} = new IO::File ">$self->{exclusions_file}";
        die "can't write to $self->{exclusions_file}: $!\n" unless $self->{efh};
    }
    $self->{invert} = delete $args{invert};
    $self->{format} = delete $args{format} || 'CLF';
    die "format option should be (CLF|ELF|XLF)\n" 
        unless $self->{format} =~ /^[CXE]LF$/
    ;
    my @fields_order = @{$fields_order->{$self->{format}}};
    my %valid_fields = map { $_ => 1 }  @fields_order;
    for ( keys %args )
    {
        die 
            "$_ is not a valid option; please use one of:\n",
            map { "\t$_\n" } keys( %valid_fields ), @options,
        unless $valid_fields{$_}
    }
    $self->{generic_fields_re} = 
        join( '\s', map( { $generic_fields_re{$_} } @fields_order ) )
    ;
    my %exclude_fields_re = ( 
        %generic_fields_re,
        map { 
            my $re = delete( $args{$_} ); 
            $_ => $in_quotes{$_} ? "\"$re\"" : $re 
        } 
        grep /_re$/,
        keys %args
    );
    $self->{exclude_fields_re} = 
        join( '\s', map( { $exclude_fields_re{$_} } @fields_order ) )
    ;
    return $self;
}

sub generic_re
{
    my $self = shift;
    return $self->{generic_fields_re};
}

sub re
{
    my $self = shift;
    return $self->{exclude_fields_re};
}

sub filter
{
    my $self = shift;
    my $line = shift;

    return undef unless $line =~ m{^$self->{generic_fields_re}$};
    if ( $self->{invert} )
    {
        return $line if $line !~ m{^$self->{exclude_fields_re}$};
    }
    else
    {
        return $line if $line =~ m{^$self->{exclude_fields_re}$};
    }
    if ( $self->{efh} )
    {
        $self->{efh}->print( $line );
    }
    return '';
}

#------------------------------------------------------------------------------
#
# Start of POD
#
#------------------------------------------------------------------------------

=head1 NAME

HTTPD::Log::Filter - a module to filter entries out of an httpd log.

=head1 SYNOPSIS

    my $hlf = HTTPD::Log::Filter->new(
        exclusions_file     => $exclusions_file,
        agent_re            => '.*Mozilla.*',
        format              => 'ELF',
    );

    while( <> )
    {
        my $ret = $hlf->filter( $_ );
        die "Error at line $.: invalid log format\n" unless defined $ret;
        print $line if $ret;
    }

    print grep { $hlf->filter( $_ ) } <>;

=head1 DESCRIPTION

This module provide a simple interface to filter entries out of an httpd
logfile. The constructor can be passed regular expressions to match against
particular fields on the logfile.  It does its filtering line by line, using a
filter method that takes a line of a logfile as input, and returns true if it
matches, and false if it doesn't.

There are two possible non-matching (false) conditions; one is where the line
is a valid httpd logfile entry, but just doesn't happen to match the filter
(where "" is returned). The other is where it is an invalid entry according to
the format specified in the constructor.

=head1 CONSTRUCTOR

The constructor is passed a number of options as a hash. These are:

=over 4

=item exclusions_file

This option can be used to specify a filename for entries that don't match the
filter to be written to.

=item invert

This option, is set to true, will invert the logic of the fliter; i.e. will
return only non-matching lines.

=item format

This should be one of:

=over 4

=item CLF

Common Log Format (CLF):

"%h %l %u %t \"%r\" %>s %b" 

=item ELF

NCSA Extended/combined Log format:

"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" 

=item XLF

Some bespoke format based on extended log format + some junk at the end:

"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" %j

where %j is .* in regex-speak.

See L<http://httpd.apache.org/docs/mod/mod_log_config.html> for more
information on log file formats.

=back

=item (host|ident|authexclude|date|request|status|bytes|referer|agent)_re

This class of options specifies the regular expression or expressions which are
used to filter the 

=back

=head1 METHODS

=head2 filter

Filters a line of a httpd logfile. returns true (the line) if it
matches, and false ("" or undef) if it doesn't.

There are two possible non-matching (false) conditions; one is where the line
is a valid httpd logfile entry, but just doesn't happen to match the filter
(where "" is returned). The other is where it is an invalid entry according to
the format specified in the constructor.

=head2 re

Returns the current filter regular expression.

=head1 AUTHOR

Ave Wrigley <Ave.Wrigley@itn.co.uk>

=head1 COPYRIGHT

Copyright (c) 2001 Ave Wrigley. All rights reserved. This program is free
software; you can redistribute it and/or modify it under the same terms as Perl
itself.

=cut

#------------------------------------------------------------------------------
#
# End of POD
#
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
#
# True ...
#
#------------------------------------------------------------------------------

1;
