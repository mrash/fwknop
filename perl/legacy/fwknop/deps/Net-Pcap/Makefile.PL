#
# Makefile.PL for Net::Pcap
#
# $Id: Makefile.PL 209 2005-03-21 02:37:37Z mbr $
#

use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'         => 'Net::Pcap',
	'DISTNAME'     => 'Net-Pcap',
	'VERSION_FROM' => 'Pcap.pm',
	'LIBS'         => ['-lpcap'], 
	dist => {
		'COMPRESS' => "gzip -9f",
		'SUFFIX'   => "gz"
	}
);
