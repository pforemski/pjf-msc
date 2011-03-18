default: pcap2mat
#default: pcap2mat.mexglx

pcap2mat: pcap2mat.c
	gcc -O3 -DNOMATLAB pcap2mat.c -o pcap2mat

pcap2mat.mexglx: pcap2mat.c
	mex pcap2mat.c

.PHONY: clean
clean:
	-rm -f pcap2mat.mexglx pcap2mat
