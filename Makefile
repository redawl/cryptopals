# Needs it own target, since the exe requires input4.txt redirected to stdin
c1p4.run: c1p4.o lib/bytes/bytes.o
	$(CC) $^  -lssl -lcrypto -o $@
	$(RM) $^
	./$@ < input4.txt
	$(RM) $@

%.run: %.o lib/bytes/bytes.o
	$(CC) $^  -g -lssl -lcrypto -o $@
	$(RM) $^
	./$@
	$(RM) $@
