GXX = g++
GCC = gcc
AR = ar

INCLUDE = -I../
LIBS =
C_ARGS = -g -Wall $(INCLUDE)
AR_ARGS = rcs

BINARY = sign verify verifywithcert
sign_dep = sign.o ../ssl_sign.o
sign_lib = -lcrypto
verify_dep = verify.o ../ssl_sign.o
verify_lib = -lcrypto
verifywithcert_dep = verifywithcert.o ../ssl_sign.o
verifywithcert_lib = -lcrypto

ALL_OBJS = $(foreach d,$(BINARY),$($(d)_dep))

%.o : %.cpp
	$(GXX) $(C_ARGS) -c  $< -o $(patsubst %.cpp,%.o,$<)
%.o : %.cc
	$(GXX) $(C_ARGS) -c  $< -o $(patsubst %.cc,%.o,$<)
%.o : %.c
	$(GCC) $(C_ARGS) -c  $< -o $(patsubst %.c,%.o,$<)
	
all : $(BINARY)

$(BINARY) : $(ALL_OBJS)
	@echo "now building:" $@
	@echo "dependency:" $($@_dep)
	rm -f $@
	$(GXX) $(C_ARGS) -o $@ $($@_dep) $(LIBS) $($@_lib)

clean:
	rm -f $(ALL_OBJS) $(BINARY)

print:
	@echo "print all vars"
	@echo "all objs:" $(ALL_OBJS)
