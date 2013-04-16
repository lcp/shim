LIBFILES = asn1.o asn1_parser.o enumerator.o chunk.o oid.o identification.o \
	x509.o
EFILIBFILES = $(patsubst %.o,%.efi.o,$(LIBFILES))

include ../../Make.rules

libasn1-efi.a: $(EFILIBFILES)

clean:
	rm -f libasn1-efi.a
	rm -f $(EFILIBFILES)
