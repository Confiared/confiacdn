MAKEFILE      = Makefile

EQ            = =

####### Compiler, tools and options

CC            = gcc
CXX           = g++
DEFINES       = -DFASTCGIASYNC
#DEFINES       = -DFASTCGIASYNC -DDEBUGFASTCGITCP
CFLAGS        = -pipe -O2 -g $(DEFINES)
CXXFLAGS      = -pipe -O2 -g -std=gnu++11 $(DEFINES)
INCPATH       = -I.
DEL_FILE      = rm -f
CHK_DIR_EXISTS= test -d
MKDIR         = mkdir -p
COPY          = cp -f
COPY_FILE     = cp -f
COPY_DIR      = cp -f -R
INSTALL_FILE  = install -m 644 -p
INSTALL_PROGRAM = install -m 755 -p
INSTALL_DIR   = cp -f -R
DEL_FILE      = rm -f
SYMLINK       = ln -f -s
DEL_DIR       = rmdir
MOVE          = mv -f
TAR           = tar -cf
COMPRESS      = gzip -9f
DISTNAME      = fastcgicdnhttp11
LINK          = g++
LFLAGS        = 
#LFLAGS        = -Wl,-fuse-ld=lld
#LFLAGS        = 
LIBS          = -lssl -lcrypto
AR            = ar cqs
RANLIB        = 
SED           = sed
STRIP         = strip

####### Output directory

OBJECTS_DIR   = ./

####### Files

SOURCES       = ./main.cpp \
		./Backend.cpp \
		./Client.cpp \
		./Common.cpp \
		./EpollObject.cpp \
		./Http.cpp \
		./Https.cpp \
		./Server.cpp \
		./ServerTCP.cpp \
		./Dns.cpp \
		./DnsSocket.cpp \
		./Timer.cpp \
		./Cache.cpp \
		./Timer/CheckTimeout.cpp \
		./Timer/DNSCache.cpp \
		./Timer/DNSQuery.cpp \
		./Timer/CleanOldCache.cpp 
OBJECTS       = main.o \
		Backend.o \
		Client.o \
		Common.o \
		EpollObject.o \
		Http.o \
		Https.o \
		Server.o \
		ServerTCP.o \
		Dns.o \
		DnsSocket.o \
		Timer.o \
		Cache.o \
		CheckTimeout.o \
		DNSCache.o \
		DNSQuery.o \
		CleanOldCache.o
DIST          = ./fastcgicdnhttp11.pro ./Backend.hpp \
		./Client.hpp \
		./Common.hpp \
		./EpollObject.hpp \
		./Http.hpp \
		./Https.hpp \
		./Server.hpp \
		./ServerTCP.hpp \
		./Dns.hpp \
		./DnsSocket.hpp \
		./Timer.hpp \
		./Cache.hpp \
		./Timer/CheckTimeout.hpp \
		./Timer/DNSCache.hpp \
		./Timer/DNSQuery.hpp ./Timer/CleanOldCache.hpp ./main.cpp \
		./Backend.cpp \
		./Client.cpp \
		./Common.cpp \
		./EpollObject.cpp \
		./Http.cpp \
		./Https.cpp \
		./Server.cpp \
		./ServerTCP.cpp \
		./Dns.cpp \
		./DnsSocket.cpp \
		./Timer.cpp \
		./Cache.cpp \
		./Timer/CheckTimeout.cpp \
		./Timer/DNSCache.cpp \
		./Timer/DNSQuery.cpp \
		./Timer/CleanOldCache.cpp
QMAKE_TARGET  = fastcgicdnhttp11
DESTDIR       = 
TARGET        = fastcgicdnhttp11

first: all
####### Build rules

fastcgicdnhttp11:  $(OBJECTS)  
	$(LINK) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(OBJCOMP) $(LIBS)

all: fastcgicdnhttp11

####### Compile

main.o: ./main.cpp ./Server.hpp \
		./EpollObject.hpp \
		./ServerTCP.hpp \
		./Client.hpp \
		./Http.hpp \
		./Backend.hpp \
		./Dns.hpp \
		./DnsSocket.hpp \
		./Cache.hpp \
		./Timer.hpp \
		./Timer/DNSCache.hpp \
		./Timer/DNSQuery.hpp \
		./Timer/CheckTimeout.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o main.o ./main.cpp

Backend.o: ./Backend.cpp ./Backend.hpp \
		./EpollObject.hpp \
		./Http.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Backend.o ./Backend.cpp

Client.o: ./Client.cpp ./Client.hpp \
		./EpollObject.hpp \
		./Dns.hpp \
		./Cache.hpp \
		./Http.hpp \
		./Backend.hpp \
		./Https.hpp \
		./Common.hpp \
		./xxHash/xxh3.h \
		./xxHash/xxhash.h
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Client.o ./Client.cpp

Common.o: ./Common.cpp ./Common.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Common.o ./Common.cpp

EpollObject.o: ./EpollObject.cpp ./EpollObject.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o EpollObject.o ./EpollObject.cpp

Http.o: ./Http.cpp ./Http.hpp \
		./EpollObject.hpp \
		./Backend.hpp \
		./Client.hpp \
		./Cache.hpp \
		./Common.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Http.o ./Http.cpp

Https.o: ./Https.cpp ./Https.hpp \
		./Http.hpp \
		./EpollObject.hpp \
		./Backend.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Https.o ./Https.cpp

Server.o: ./Server.cpp ./Server.hpp \
		./EpollObject.hpp \
		./Client.hpp \
		./Dns.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Server.o ./Server.cpp

ServerTCP.o: ./ServerTCP.cpp ./ServerTCP.hpp \
		./EpollObject.hpp \
		./Client.hpp \
		./Dns.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o ServerTCP.o ./ServerTCP.cpp

Dns.o: ./Dns.cpp ./Dns.hpp ./DnsSocket.hpp \
		./EpollObject.hpp \
		./Client.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Dns.o ./Dns.cpp
	
DnsSocket.o: ./Dns.hpp ./DnsSocket.hpp \
		./EpollObject.hpp \
		./Client.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o DnsSocket.o ./DnsSocket.cpp

Timer.o: ./Timer.cpp ./Timer.hpp \
		./EpollObject.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Timer.o ./Timer.cpp

Cache.o: ./Cache.cpp ./Cache.hpp \
		./EpollObject.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Cache.o ./Cache.cpp

CheckTimeout.o: ./Timer/CheckTimeout.cpp ./Timer/CheckTimeout.hpp \
		./Timer.hpp \
		./EpollObject.hpp \
		./Http.hpp \
		./Backend.hpp \
		./Https.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o CheckTimeout.o ./Timer/CheckTimeout.cpp

DNSCache.o: ./Timer/DNSCache.cpp ./Timer/DNSCache.hpp \
		./Timer.hpp \
		./EpollObject.hpp \
		./Dns.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o DNSCache.o ./Timer/DNSCache.cpp

CleanOldCache.o: ./Timer/CleanOldCache.cpp ./Timer/CleanOldCache.hpp \
		./Timer.hpp \
		./EpollObject.hpp \
		./Backend.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o CleanOldCache.o ./Timer/CleanOldCache.cpp

DNSQuery.o: ./Timer/DNSQuery.cpp ./Timer/DNSQuery.hpp \
		./Timer.hpp \
		./EpollObject.hpp \
		./Dns.hpp
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o DNSQuery.o ./Timer/DNSQuery.cpp

