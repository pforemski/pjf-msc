#!/bin/bash

protos="http iptv skype dns AVERAGE"

tpfp() { sed -re 's;.*TP\s+([0-9]+)% / FP\s+([0-9]+)%.*;\1 \2;g'; }
vinv() { sed -re 's;.*\(\s*([0-9]+)%\).*;\1;g'; }

echo "# signatures $protos valid invalid"

for i in 5 10 25 50 100 250 500; do
	echo -n "$i "

	for p in $protos; do
		v=`grep "$p" result-$i.txt | tpfp`
		echo -n "$v "
	done

	v=`grep " valid" result-$i.txt | vinv`
	echo -n "$v "

	v=`grep " invalid" result-$i.txt | vinv`
	echo -n "$v "

	echo
done
