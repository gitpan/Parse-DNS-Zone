#!/usr/bin/perl
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile (
	NAME => 'Parse::DNS::Zone',
	AUTHOR => 'Olof Johansson <zibri@cpan.org>',
	LICENSE => 'perl',
	ABSTRACT_FROM => 'lib/Parse/DNS/Zone.pm',
	VERSION_FROM => 'lib/Parse/DNS/Zone.pm',
	SIGN => 1,
);
