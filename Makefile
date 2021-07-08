c1p1: c1p1.o bytes.o
	gcc c1p1.o bytes.o -lssl -lcrypto
	rm *.o
	./a.out
	rm a.out
c1p2: c1p2.o bytes.o
	gcc c1p2.o bytes.o -lssl -lcrypto
	rm *.o 
	./a.out
	rm a.out
c1p3: c1p3.o bytes.o
	gcc c1p3.o bytes.o -lssl -lcrypto
	rm *.o 
	./a.out	
	rm a.out
c1p4: c1p4.o bytes.o
	gcc c1p4.o bytes.o -lssl -lcrypto
	rm *.o
	./a.out < input4.txt
	rm a.out
c1p5: c1p5.o bytes.o
	gcc c1p5.o bytes.o -lssl -lcrypto
	rm *.o
	./a.out 
	rm a.out
c1p6: c1p6.o bytes.o
	gcc c1p6.o bytes.o -lssl -lcrypto
	rm *.o
	./a.out 
	rm a.out
c1p7: c1p7.o bytes.o
	gcc c1p7.o bytes.o -lssl -lcrypto
	rm *.o
	./a.out
	rm a.out
