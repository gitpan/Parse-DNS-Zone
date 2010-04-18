#!/usr/bin/perl
use strict;
use warnings;
use feature qw/say/;
use Parse::DNS::Zone;

if($#ARGV != 1) {
	die("usage: perl example.pl <zonefile> <origin>");
}

my $file = shift;
my $origin = shift;

$origin .= '.' if $origin !~ /\.$/;

my $zone = Parse::DNS::Zone->new(
	zonefile => $file,
	origin => $origin,
);

foreach my $name ($zone->get_names) {
	foreach my $rr ($zone->get_rrs($name)) {
		for(my $i=0; $i<$zone->get_dupes(name=>$name, rr=>$rr); ++$i) {
			my $class = $zone->get_rdata(
				name=>$name, 
				rr=>$rr, 
				n=>$i,
				field=>'class'
			);

			my $ttl = $zone->get_rdata(
				name=>$name, 
				rr=>$rr, 
				n=>$i,
				field=>'ttl'
			);

			my $rdata = $zone->get_rdata(
				name=>$name, 
				rr=>$rr, 
				n=>$i,
			);

			say "$name ",uc$class," $ttl ",uc$rr," $rdata";
		}
	}
}

