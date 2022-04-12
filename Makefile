APXS=/usr/sbin/apxs2

.SUFFIXES: .c .o .la

.c.la:
	$(APXS) $(LDFLAGS) $(CFLAGS) -c $< 

all: mod_auth_signature.la

dist:
	rm -rf mod_auth_signature
	mkdir mod_auth_signature
	cp -a LICENSE Makefile mod_auth_signature.c examples mod_auth_signature
	tar czvf mod_auth_signature.tar.gz mod_auth_signature
	rm -rf mod_auth_signature
