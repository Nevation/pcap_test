all : pcap_test

pcap_test: main.o packet_func.o
	g++ -g -o pcap_test main.o packet_func.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

packet_func:
	g++ -g -c -o packet_func.o packet_func.cpp

clean:
	rm -f pcap_test
	rm -f *.o

