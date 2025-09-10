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
# End
