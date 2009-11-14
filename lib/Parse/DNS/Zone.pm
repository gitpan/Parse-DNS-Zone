#!/usr/bin/perl
# Parse::DNS::Zone - DNS Zone File Parser
#
# Copyright (c) 2009 Olof 'zibri' Johansson <zibri@cpan.org>. 
# All rights reserved.
#
# This program is free software; you can redistribute it and/or 
# modify it under the same terms as Perl itself.

=pod

=head1 NAME

Parse::DNS::Zone - DNS Zone File Parser

=head1 SYNOPSIS

 use Parse::DNS::Zone;

 my $zone = Parse::DNS::Zone->new(
 	zonefile=>'db.example',
 	origin=>'example.org.',
	require_soa=>1,
 );

 my $a_rr = $zone->get_rdata('foo', 'A');
 my $mx_rr = $zone->get_rdata('@', 'MX'); # Get the origin's MX

 # Get SOA values
 my $mname = $zone->get_mname();
 my $rname = $zone->get_rname();
 my $serial = $zone->get_serial();
 # ... etc ...

=head1 DESCRIPTION

B<Parse::DNS::Zone> parses a zonefile, used to define a DNS Zone
and gives you the information therein, via an object oriented 
interface. Parse::DNS::Zone doesn't validate rrdata, except for 
SOA, and is used to 1) validate the basic structure of the file 
and 2) extract rdata so you can parse it and validate it yourself.

Parse::DNS::Zone supports RFC 1034 zones:

=over 4

=item * $INCLUDE

=item * $TTL

=item * $ORIGIN

=back

Parse::DNS::Zone does not support $GENERATE in this version. 

=cut 

package Parse::DNS::Zone;
our $VERSION = '0.21';
use warnings;
use strict;
use Carp;
use Data::Dumper;

=head1 CONSTRUCTOR

=head2 Parse::DNS::Zone->new( ARGS )

=over 4

=item B<Required Arguments>

=over 4 

=item * B<origin>

Origin

=item * B<zonefile>

Path to the zonefile being parsed

=back

=item B<Optional Arguments>

=over 4

=item * B<require_soa>

If set to a value other than 0, the parser will whine and die if 
the zonefile doesn't contain a SOA record. (Default: no)

=back

=back

=cut

sub new {
	my $class = shift;
	my $self = {
		require_soa=>1,
		@_
	};

	# append trailing .
	$self->{origin} .= '.' if($self->{origin}=~/[^[^\.]$/);
	bless($self, $class);

	_parse($self);

	if($self->{require_soa} && 
	   (!exists $self->{zone}{$self->{origin}}{soa})) {
		print Dumper($self->{zone});
		croak("No SOA in zonefile");
	}

	_parse_soa($self);

	return $self;
}

=head1 METHODS

=head2 General

=head3 $zone->get_rdata(name=>$name, rr=>$rr, n=>$n)

Is used to get the data associated with a specific name and rr 
type. The $name can be as the name appears in the zonefile, 
or a fqdn (with trailing .) as long as it is tracked by the 
zonefile. For multiple RRs for a name, you can specify a $n
argument to get a specific data set. Default is 0, so if you
only have one, you don't need to specify this.

=cut

sub get_rdata {
	my $self = shift;
	my $h = {
		n=>0,
		@_,
	};

	my $rr = $h->{rr};
	my $name = $h->{name};

	$name=~s/^\@ /$self->{origin} /g;
	$name=~s/ \@ / $self->{origin} /g;
	$name=~s/ \@$/ $self->{origin}/g;
	$name .= ".$self->{origin}" if(($name ne $self->{origin}) && 
	                               (!($name=~/\.$/)));

	return $self->{zone}{lc $name}{lc $rr}{val}[$h->{n}];
}

=head3 $zone->exists($name)

Returns non-zero if the name exists, and zero otherwise.

=cut

sub exists {
	my $self = shift;
	my $name = shift;

	return exists $self->{zone}{lc $name};
}

=head3 $zone->get_rrs($name)

Returns a list with all RR types for a specific name

=cut

sub get_rrs {
	my $self = shift;
	my $name = shift;
	my @rrs;

	foreach my $k (keys %{$self->{zone}{lc $name}}) {
		push @rrs, $k;
	}

	return @rrs;
}

=head3 $zone->get_dupes(name=>$name, rr=>$rr)

Returns how many RRs of a given type is defined for $name. For a simple
setup with a single RR for $name, this will return 1. If you have some
kind of load balancing or other scheme using mutiple RRs of the same 
type this sub will return the number of "dupes".

=cut

sub get_dupes {
	my $self = shift;
	my $h = {
		@_,
	};

	my $name = $h->{name};
	my $rr = $h->{rr};

	$name=~s/^\@ /$self->{origin} /g;
	$name=~s/ \@ / $self->{origin} /g;
	$name=~s/ \@$/ $self->{origin}/g;
	$name .= ".$self->{origin}" if(($name ne $self->{origin}) && 
	                               (!($name=~/\.$/)));

	return int($self->{zone}{lc $name}{lc $rr}{val});
}

=head3 $zone->get_names($name)

Returns a list with all names specified in the zone

=cut

sub get_names {
	my $self = shift;
	my @names;

	foreach my $n (keys %{$self->{zone}}) {
		push @names, $n;
	}

	return @names;
}

=head2 SOA

=head3 $zone->get_mname( )

Returns the MNAME part of the SOA.

=cut

sub get_mname {
	my $self = shift;
	return $self->{soa}{mname};
}

=head3 $zone->get_rname( )

=head3 $zone->get_rname( parse=>{0,1} )

Return the RNAME part of the SOA. If parse is set to a value 
other than 0, the value will be interpreted to show an 
emailaddress. (default: 0)

=cut

sub get_rname {
	my $self = shift;
	my %p = (
		parse=>0,
		@_
	);

	my $ret = $self->{soa}{rname};
	if($p{parse}) {
		my ($user,$host)=$self->{soa}{rname}=~/^([^\.]+)\.(.*)$/;
		$ret = "$user\@$host";
	}

	return $ret;
}

=head3 $zone->get_serial( )

Return the SERIAL value of a SOA.

=cut

sub get_serial {
	my $self = shift;
	return $self->{soa}{serial};
}

=head3 $zone->get_refresh( )

Return the REFRESH value of a SOA

=cut

sub get_refresh {
	my $self = shift;
	return $self->{soa}{refresh};
}

=head3 $zone->get_retry( )

Return the RETRY value of a SOA

=cut

sub get_retry {
	my $self = shift;
	return $self->{soa}{expire};
}

=head3 $zone->get_expire( )

Return the EXPIRE value of a SOA

=cut

sub get_expire {
	my $self = shift;
	return $self->{soa}{expire};
}

=head3 $zone->get_minimum( )

Return the MINIMUM value of a SOA

=cut

sub get_minimum {
	my $self = shift;
	return $self->{soa}{minimum};
}

1;

# Is used to populate the zone hash used internally. 
sub _parse {
	my $self = shift;
	my %zone = _parse_zone($self->{zonefile}, $self->{origin});

	undef $self->{zone};
	$self->{zone}={%zone};
}

# Is used internally to parse a zone from a filename. will do some
# recursion for the $include, so a procedural implementation is needed
sub _parse_zone {
	my ($zonefile, $origin) = @_;

	open ZONE, $zonefile or croak("Could not open $zonefile: $!");

	my $def_ttl;
	my $mrow;
	my $prev;
	my %zone;

	my $zentry = qr/^(\S+) ((?:\d+ )?)((?:(?:IN|CH|HS) )?)(\S+) (.*)$/;
	
	while(<ZONE>) {
		s/;.*$//;
		next if /^\s*$/;
		s/\s+/ /g;
		
		s/^\@ /$origin /g;
		s/ \@ / $origin /g;
		s/ \@$/ $origin/g;

		# handles mutlirow entries, with ()
		if($mrow) {
			$mrow.=$_;
			
			next if(! /\)/); 

			# End of multirow 
			$mrow=~s/[\(\)]//g;
			$mrow=~s/\n//mg;
			$mrow=~s/\s+/ /g;
			$mrow .= "\n";	

			$_ = $mrow;
			undef $mrow;
		} elsif(/^.*\([^\)]*$/) {
			# Start of multirow
			$mrow.=$_;
			next;
		}

		if(/^ /) {
			s/^/$prev/;
		}

		$origin = $1 if(/^\$ORIGIN ([\w\-\.]+)\s*$/i);
		$def_ttl = $1 if(/^\$TTL (\d+)\s*$/i);
		if(/^\$INCLUDE (\S+) (\S+)? .*$/i) {
			my $subo=defined $2?$2:$origin;
			my %subz=_parse_zone($1, $subo);

			foreach my $k (keys %subz) {
				$zone{$k}=$subz{$k};
			}
		}

		my($name,$ttl,$class,$type,$rdata) = /$zentry/i;
		$ttl = $def_ttl if !$ttl;

		next if (!$name || !$type || !$rdata);

		chop $ttl if $ttl;
		chop $class if $class;
		$prev=$name;
		$name.=".$origin" if(($name ne $origin) && !($name=~/\.$/));

		push(@{$zone{lc $name}{lc $type}{val}}, $rdata);
		push(@{$zone{lc $name}{lc $type}{ttl}}, $ttl) if $ttl;
		push(@{$zone{lc $name}{lc $type}{class}}, $class) if $class;
	}

	close ZONE;
	return %zone;
}

# Is used to parse the SOA and build the soa hash as used 
# internally..
sub _parse_soa {
	my $self = shift;
	my $soa_rd = get_rdata($self, (name=>"$self->{origin}", rr=>'SOA'));
	my($mname,$rname,$serial,$refresh,$retry,$expire,$minimum)=
		$soa_rd=~/^(\S+) (\S+) (\d+) (\d+) (\d+) (\d+) (\d+)\s*$/;
	
	$self->{soa}{mname}=$mname;
	$self->{soa}{rname}=$rname;
	$self->{soa}{serial}=$serial;
	$self->{soa}{refresh}=$refresh;
	$self->{soa}{retry}=$retry;
	$self->{soa}{expire}=$expire;
	$self->{soa}{minimum}=$minimum;
}

=head1 SEE ALSO

RFC 1034, RFC 1035, Bind Administrator's Guide

=head1 COPYRIGHT

Copyright (c) 2009 Olof 'zibri' Johansson <zibri@cpan.org>. 
All rights reserved.

This program is free software; you can redistribute it and/or 
modify it under the same terms as Perl itself.

=cut
