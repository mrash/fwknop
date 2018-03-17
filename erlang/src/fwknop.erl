%%  License (GNU General Public License):
%%
%%  This program is free software; you can redistribute it and/or
%%  modify it under the terms of the GNU General Public License
%%  as published by the Free Software Foundation; either version 2
%%  of the License, or (at your option) any later version.
%%
%%  This program is distributed in the hope that it will be useful,
%%  but WITHOUT ANY WARRANTY; without even the implied warranty of
%%  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%%  GNU General Public License for more details.
%%
%%  You should have received a copy of the GNU General Public License
%%  along with this program; if not, write to the Free Software
%%  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
%%  USA

-module( fwknop ).
-compile( export_all ).

-define( FwknopVersion, "2.0.2" ).
-define( CommandMode, 0 ).
-define( AccessMode, 1 ).

-import( lists,	[ dropwhile/2, nth/2, reverse/1, seq/2, split/2 ] ).
-import( pkcs7, [ pad/1 ] ).

packet( Proto, Ip, Port, RijndaelKeyB64, HmacKeyB64 ) ->
	E64 = fun( Bin ) -> base64:encode( Bin ) end,

	RijndaelKey	= base64:decode( RijndaelKeyB64 ),
	HmacKey		= base64:decode( HmacKeyB64 ),

	Rand		= random_digits( 16 ),
	User		= E64( os:getenv( "USER" ) ),
	Version		= ?FwknopVersion,
	MsgType		= integer_to_list( ?AccessMode ),
	Request		= strip_base64(E64( list_to_binary( io_lib:format( "~s,~s/~b", [ Ip, Proto, Port ] ) ) ) ),
	Time 		= timestamp(),

	Message		= list_to_binary( io_lib:format( "~s:~s:~p:~s:~s:~s", [ Rand, User, Time, Version, MsgType, Request ] ) ),
	error_logger:info_msg( "Message: ~s~n", [ Message ] ),
	Digest		= strip_base64( E64( crypto:hash( sha256, Message ) ) ),

	Plaintext	= pkcs7:pad( <<Message/binary, <<":">>/binary, Digest/binary>> ),
	Salt 		= crypto:strong_rand_bytes( 8 ),
	
	{Key, IV} 	= pbkdf1( Salt, RijndaelKey ),
	Magic		= <<"Salted__">>,

	Ciphertext 	= crypto:block_encrypt( aes_cbc256, Key, IV, Plaintext ),
	SpaData		= strip_base64( E64( <<Magic/binary, Salt/binary, Ciphertext/binary>> ) ),

	Hmac		= strip_base64( E64( crypto:hmac( sha256, HmacKey, SpaData ) ) ),
	error_logger:info_msg( "HMAC:   ~s~n", [ Hmac ] ),

	% strip encoded magic word
	SpaData2 = binary:part(SpaData, {10, size(SpaData) - 10} ),
	
	<< SpaData2/binary,  Hmac/binary>>.

%
%	miscellaneous utilities
%
pbkdf1( Salt, Key ) ->
	Round1 = erlang:md5( <<Key/binary, Salt/binary>> ),
	Round2 = erlang:md5( <<Round1/binary, Key/binary, Salt/binary>> ),
	Round3 = erlang:md5( <<Round2/binary, Key/binary, Salt/binary>> ),
	{ <<Round1/binary, Round2/binary>>, <<Round3/binary>> }.
		
strip_base64( Bin ) ->
	F = fun( C ) -> C == $= end,
	list_to_binary( reverse( dropwhile( F, reverse( binary_to_list( Bin ) ) ) ) ).

random_digits( N ) ->
	list_to_binary( [ nth( rand:uniform( 10 ), "0123456789" ) || _ <- seq( 1, N ) ] ).

timestamp() ->
	{ A, B, _ }	= os:timestamp(),
	list_to_integer( integer_to_list( (A * 1000000) + B ) ).

knock( Host, Port, RijndaelKeyB64, HmacKeyB64, { Proto, SrcIp, DstPort } ) ->
	Packet = packet( Proto, SrcIp, DstPort, RijndaelKeyB64, HmacKeyB64 ),
	{ ok, Socket } = gen_udp:open( 0, [binary] ),
	gen_udp:send( Socket, Host, Port, Packet ).
