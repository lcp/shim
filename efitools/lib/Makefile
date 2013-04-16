FILES = simple_file.o pecoff.o guid.o sha256.o console.o \
	security_policy.o execute.o configtable.o shell.o
EFILIBFILES = $(patsubst %.o,%.efi.o,$(FILES)) variables.o 

include ../Make.rules

lib-efi.a: $(EFILIBFILES)

clean:
	rm -f lib-efi.a
	rm -f $(EFILIBFILES)

