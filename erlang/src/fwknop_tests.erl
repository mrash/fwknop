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

-module( fwknop_tests ).

-include_lib("eunit/include/eunit.hrl").

pbkdf1_test() ->
	Salt		= <<0,0,0,0,0,0,0,0>>,
	RijndaelKey	= base64:decode("Sz80RjpXOlhH2olGuKBUamHKcqyMBsS9BTgLaMugUsg="),

	ExpectedKey	= <<80,137,195,6,117,8,63,199,226,93,78,205,231,238,241,80,217,161,149,164,60,102,129,175,81,53,82,23,137,50,236,37>>,
	ExpectedIV	= <<56,251,47,154,60,96,84,106,192,163,161,216,59,202,166,203>>,

	{ExpectedKey, ExpectedIV} = fwknop:pbkdf1(Salt, RijndaelKey).

strip_base64_test() ->
	Encoded		= base64:encode( "Salted" ),
	Encoded2	= base64:encode( "Salted_" ),
	Encoded3	= base64:encode( "Salted__" ),

	<< "U2FsdGVk" >>	= fwknop:strip_base64(Encoded),
	<< "U2FsdGVkXw" >>	= fwknop:strip_base64(Encoded2),
	<< "U2FsdGVkX18" >>	= fwknop:strip_base64(Encoded3).
