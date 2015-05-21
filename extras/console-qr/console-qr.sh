#!/bin/sh
while read line; do
	line=$(echo "$line" | sed 's:#.*$::g')
	if [ "$(echo $line | grep -c 'SOURCE')" -ne "0" ]
	then
		source=$line
		if [ -n "$qr" ]
		then
			echo $'\n\n'$source
			qrencode -o - -t UTF8 "$qr"
			qr=""
		fi
	fi
	if [ "$(echo $line | grep -c 'KEY')" -ne "0" ]
	then
		trline="$(echo $line | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/ /:/')"
		qr="$qr$trline "
		fi
done
if [ -n "$qr" ]
then
	echo $'\n\n'$source
	qrencode -o - -t UTF8 "$qr"
fi
