pcap-test: pcap-test.cpp
	g++ pcap-test.cpp -o pcap-test -lpcap
clean:
	rm -f pcap-test