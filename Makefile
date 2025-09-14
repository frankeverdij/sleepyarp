# g++ compiler
CC = gcc

# g++ compiler flags
CFLAGS = -O2 -Wall

#linker
LD = gcc

# linker flags
LDFLAGS = 

# libraries
LIBS = -lpcap

# install script
INSTALL = install

SBINDIR = /usr/local/sbin

# Makefile
all: sleepyarp
sleepyarp: sleepyarp.o
	$(LD) $(LDFLAGS) -o sleepyarp sleepyarp.o $(LIBS)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
# Cleaning everything
.PHONY : clean
clean:
	rm -f sleepyarp sleepyarp.o
install: install-sbin install-service
install-sbin: sleepyarp
	$(INSTALL) -d $(SBINDIR)
	$(INSTALL) -m 755 sleepyarp $(SBINDIR)/sleepyarp
install-service:
	$(INSTALL) -m 644 sleepyarp.service /usr/lib/systemd/system/sleepyarp.service
# End
