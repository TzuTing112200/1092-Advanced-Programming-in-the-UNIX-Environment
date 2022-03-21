CXX := g++

all: hw2 get_so

hw2: hw2.o
	$(CXX) hw2.o -o logger

get_so: logger.cpp
	$(CXX) -D_GNU_SOURCE -o logger.so -shared -fPIC logger.cpp -ldl

test2: test2.c
	gcc test2.c -o test2

test3: test3.c
	gcc test3.c -o test3

sample: sample.c
	gcc sample.c -o sample

clean:
	rm -f *.o *.so logger

