SDKVER?=5.1
ARCH?=armv7
SDK=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS$(SDKVER).sdk/
CC=clang -arch $(ARCH)
CFLAGS=-Wall -isysroot $(SDK)

externalMethod.h: externalMethod.bin
	xxd -i $^ > $@

#hexdump hax to get correct endianness
externalMethod.bin: externalMethod.o
	otool -tX $^ | xxd -r | hexdump -v -e '/4 "%08x"' | xxd -r -p > $@ 

externalMethod.o: externalMethod.S
	$(CC) -c -o $@ $^

clean:
	rm -f externalMethod.o externalMethod.bin

