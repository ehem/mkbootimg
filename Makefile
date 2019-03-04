# Andrew Huang <bluedrum@163.com>
# Copyright 2019 Elliott Mitchell <ehem+github@m5p.com>, Apache license

ifeq ($(CC),cc)
CC = gcc
endif
AR = ar rcv
ifeq ($(windir),)
EXE =
RM = rm -f
else
EXE = .exe
RM = del
endif

CFLAGS = -ffunction-sections -O3 -MMD -c -I. -Werror

ifneq (,$(findstring darwin,$(CROSS_COMPILE)))
    UNAME_S := Darwin
else
    UNAME_S := $(shell uname -s)
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -Wl,-dead_strip
else
    LDFLAGS += -Wl,--gc-sections -s
endif


TARGETS := mkbootimg unpackbootimg

mkbootimg_SRCS := mkbootimg.c
mkbootimg_LIBS := mincrypt

unpackbootimg_SRCS := unpackbootimg.c
unpackbootimg_LIBS :=


all: $(TARGETS:%=%$(EXE))

static:
	$(MAKE) LDFLAGS="$(LDFLAGS) -static"

libmincrypt.a:
	$(MAKE) -C libmincrypt


%.o: %.c %.d Makefile
	$(CROSS_COMPILE)$(CC) -o $@ $(CFLAGS) $<

clean:
	$(RM) *.a *.~ *.o *.d $(TARGETS:%=%$(EXE))
	$(MAKE) -C libmincrypt clean

-include *.d

.SECONDEXPANSION:

# At end in order to limit secondary expansion to the least rules (speed)
$(TARGETS:%=%$(EXE)): $$($$@_SRCS\:%.c=%.o) $$($$@_LIBS\:%=lib%.a)
	$(CROSS_COMPILE)$(CC) -o $@ $($@_SRCS:%.c=%.o) -L. $($@_LIBS:%=-l%) $(LDFLAGS)
