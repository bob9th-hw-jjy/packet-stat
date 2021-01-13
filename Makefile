all: ip-stat

ip-stat: ip-stat.cpp ethernet.h
	g++ ip-stat.cpp -o ip-stat -lpcap

clean:
	rm -rf ip-stat
