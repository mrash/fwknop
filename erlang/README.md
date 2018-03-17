fwknop
=====

Experimental native erlang fwknop client with Rijndael support.

Build
-----

    $ rebar3 compile
    $ rebar3 eunit

Usage
-----
  
    $ rebar3 shell
    1> server:start("Sz80RjpXOlhH2olGuKBUamHKcqyMBsS9BTgLaMugUsg=", "c0TOaMJ2aVPdYTh4Aa25Dwxni7PrLo2zLAtBoVwSepkvH6nLcW45Cjb9zaEC2SQd03kaaV+Ckx3FhCh5ohNM5Q==").
    2> fwknop:knock("localhost", 62201, "Sz80RjpXOlhH2olGuKBUamHKcqyMBsS9BTgLaMugUsg=", "c0TOaMJ2aVPdYTh4Aa25Dwxni7PrLo2zLAtBoVwSepkvH6nLcW45Cjb9zaEC2SQd03kaaV+Ckx3FhCh5ohNM5Q==", { tcp, "1.1.1.1", 22 } ).
    =INFO REPORT==== 15-Nov-2016::15:49:16 ===
    Message: 0428888364523312:bXMxNzg0:1479224956:2.0.2:1:MTI3LjAuMC4xLHRjcC84NDQz
    =INFO REPORT==== 15-Nov-2016::15:49:16 ===
    HMAC:   KDZrTwZ+gFpqgzk8+BCXvYhRCxCzk084UyNzhihiWLU
    ok
    Client request:{127,0,0,1}
    Got message: <<"1.1.1.1,tcp/22">>
    3>
