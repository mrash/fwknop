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

-module( server ).
-compile( export_all ).

-import( fwknop, [ strip_base64/1, pbkdf1/2 ] ).
-export( [ start/2 ] ).

start(RijndaelKeyB64, HmacKeyB64) ->
	spawn(fun() -> server(62201, RijndaelKeyB64, HmacKeyB64) end).

server(Port, RijndaelKeyB64, HmacKeyB64) ->
	{ok, Socket} = gen_udp:open(Port, [binary, {active, false}]),
	accept(Socket, { RijndaelKeyB64, HmacKeyB64 } ).

accept(Socket, { Key, Hmac } = Creds) ->
	inet:setopts(Socket, [{active, once}]),
	receive
		{udp, Socket, Host, _, Bin} ->
			io:format("Client request:~p~n",[Host]),
			{ok, Ciphertext} 	= verify( Bin, Hmac ),
			{ok, Plaintext} 	= decrypt( Ciphertext, Key ),
			{ok, Message}		= decode( Plaintext ),
			error_logger:info_msg( "Got message: ~p", [ Message ] ),

			accept( Socket, Creds )
	end.

verify( SpaData, HmacKeyB64 ) ->
	Magic		= <<"U2FsdGVkX1">>,
	HmacKey		= base64:decode( HmacKeyB64 ),

	% sha2.h:#define SHA256_B64_LEN          43
	HmacLen 	= 43,

	% write something to just split this on size vs two parts
	DataHmac		= binary:part(SpaData, {byte_size(SpaData), -HmacLen}),
	EncodedMsg		= binary:part(SpaData, {0, byte_size(SpaData) - HmacLen}),

	ExpectedHmac		= fwknop:strip_base64( base64:encode( crypto:hmac( sha256, HmacKey, << Magic/binary, EncodedMsg/binary >> ) ) ),

	%io:format("DataHmac: ~s~n",[DataHmac]),
	%io:format("ExpectedHmac: ~s~n",[ExpectedHmac]),

	ExpectedHmac 	= DataHmac,

	% handle replay-attack (just compare hmacs or decode to digests?)
	% verify len is a blocksize?

	DecodedData		= base64:decode( unstrip_base64( <<Magic/binary, EncodedMsg/binary>> ) ),
	% skip "Salted__"
	DecodedMsg		= binary:part( DecodedData, {byte_size(DecodedData), -(byte_size(DecodedData) - 8) } ),
	
	{ ok, DecodedMsg }.

decrypt( Ciphertext, RijndaelKeyB64 ) ->
	RijndaelKey	= base64:decode( RijndaelKeyB64 ),

	% split again on size
	Salt 		= binary:part( Ciphertext, {0, 8} ),
	EncryptedMsg	= binary:part( Ciphertext, {byte_size(Ciphertext), -(byte_size(Ciphertext) - 8) } ),

	{Key, IV} 	= fwknop:pbkdf1( Salt, RijndaelKey ),

	{ok, crypto:block_decrypt( aes_cbc256, Key, IV, EncryptedMsg ) }.
	
decode( Plaintext ) ->
	Unpadded 		= pkcs7:unpad( Plaintext ),

	%[Rand, User, Time, Version, MsgType, Request, Digest] = re:split( Unpadded, ":", [{return,binary}]),
	%io:format( "~s:~s:~s:~s:~s:~s:~s~n", [ Rand, User, Time, Version, MsgType, Request, Digest] ),
	[_, _, _, _, _, Request, _] = re:split( Unpadded, ":", [{return,binary}]),

	[Ip, Proto, Port] = re:split( base64:decode( unstrip_base64( Request) ), "[,/]", [{return,binary}]),
	Message = list_to_binary( io_lib:format( "~s,~s/~s", [ Ip, Proto, Port ]  ) ),

	{ok, Message}.

%
%  miscellaneous utilities
%
unstrip_base64( Bin ) ->
	case ( size( Bin ) rem 4 ) of
		0 -> Bin;
		N -> Pad = list_to_binary(string:copies("=", (4-N) )),
			<< Bin/binary, Pad/binary >>
	end.
