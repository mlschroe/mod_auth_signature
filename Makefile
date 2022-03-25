APXS=/usr/sbin/apxs2

.SUFFIXES: .c .o .la

.c.la:
	$(APXS) $(LDFLAGS) $(CFLAGS) -c $< 

all: mod_auth_signature.la

dist:
	mkdir mod_auth_signature
	cp -a Makefile mod_auth_signature.c mod_auth_signature
	tar czvf mod_auth_signature.tar.gz mod_auth_signature
	rm -rf mod_auth_signature
