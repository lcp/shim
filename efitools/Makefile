include Make.rules

EFITOOL_LIBS=lib/lib-efi.a lib/asn1/libasn1-efi.a

all: $(EFITOOL_LIBS)

lib/lib-efi.a:
	$(MAKE) -C lib $(notdir $@)

lib/asn1/libasn1-efi.a:
	$(MAKE) -C lib/asn1 $(notdir $@)

clean:
	$(MAKE) -C lib clean
	$(MAKE) -C lib/asn1 clean
