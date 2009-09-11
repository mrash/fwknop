# $Id: Makefile.PL 1127 2008-06-07 17:39:44Z mbr $

require 5.006;

use ExtUtils::MakeMaker;

eval "use Test::Manifest 1.14";

WriteMakefile(
	'NAME'           => "Crypt::Rijndael",
    'VERSION_FROM'   => "Rijndael.pm",
	'LICENSE'        => 'gpl',
	'AUTHOR'         => 'Rafael R. Sevilla (maintained by brian d foy <bdfoy@cpan.org>)',
	'ABSTRACT'       => 'Crypt::CBC compliant Rijndael encryption module',
	
	'PREREQ_PM'    => { 
			'Test::More'         => '0',
			'Test::Manifest'     => '1.14',
			},


	'MAN3PODS'     => {
			'Rijndael.pm' => '$(INST_MAN3DIR)/Crypt::Rijndael.3',
			},

	clean          => { FILES    => q|*.bak *.old Crypt-*| },

	dist	       => {
	            PREOP	=> 'pod2text Rijndael.pm | tee README >$(DISTVNAME)/README; chmod -R u=rwX,go=rX . ;',
	            COMPRESS	=> 'gzip -9v',
	            SUFFIX	=> '.gz',
	           },

    OBJECT       => q[_rijndael$(OBJ_EXT) Rijndael$(OBJ_EXT)],
	); 
