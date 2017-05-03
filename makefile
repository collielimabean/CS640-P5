all: build

build:
	rm -rf ./build && mkdir ./build
	javac -d ./build assign5/src/edu/wisc/cs/sdn/simpledns/*.java assign5/src/edu/wisc/cs/sdn/simpledns/packet/*.java

clean:
	rm -rf build

run: build
	cd build && java edu.wisc.cs.sdn.simpledns.SimpleDNS -r 8.8.8.8 -e ../assign5/ec2.csv 
