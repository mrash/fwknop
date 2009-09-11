use Crypt::Rijndael;

sub crypt_decrypt
	{
	my( $mode ) = @_;
	
	my $key    = make_string( 32 );
	my $c      = Crypt::Rijndael->new( $key, $mode );

	my $data   = make_string( 32 * int( rand(16) + 1 ) );

	my $cipher = $c->encrypt( $data   );
	my $plain  = $c->decrypt( $cipher );

	return {
		data   => $data, 
		cipher => $cipher, 
		plain  => $plain,
		};
	}

sub make_string {
	my $size = shift;

	my $res;

	while( $size-- > 0 ) 
		{
		$res .= pack 'C', rand 256;
		}

	$res;
	}
	
1;