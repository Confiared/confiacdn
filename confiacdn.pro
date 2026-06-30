QT -= gui

CONFIG += c++17 console
CONFIG -= app_bundle

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS FASTCGIASYNC

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

#DEFINES += DEBUGHTTPS
LIBS += -lssl -lcrypto -lngtcp2 -lnghttp3 -lngtcp2_crypto_ossl -lxxhash

CONFIG(debug, debug|release) {
DEFINES += DEBUGFASTCGI
DEFINES += DEBUGDNS
#DEFINES += DEBUGFILEOPEN
DEFINES += DEBUGFASTCGITCP
DEFINES += LOWTIMEDNSCACHE
DEFINES += DEBUGFROMIP
}

#DEFINES += HOSTSUBFOLDER

SOURCES += main.cpp \
    Client.cpp \
    ClientReload.cpp \
    Common.cpp \
    DnsSocket.cpp \
    EpollObject.cpp \
    Server.cpp \
    ServerReload.cpp \
    ServerTCP.cpp \
    Dns.cpp \
    Timer.cpp \
    Cache.cpp \
    Timer/CheckTimeout.cpp \
    Timer/CleanOldCache.cpp \
    Timer/DNSCache.cpp \
    Timer/DNSQuery.cpp

HEADERS += \
    Client.hpp \
    ClientReload.hpp \
    Common.hpp \
    DnsSocket.hpp \
    EpollObject.hpp \
    Server.hpp \
    ServerReload.hpp \
    ServerTCP.hpp \
    Dns.hpp \
    Timer.hpp \
    Cache.hpp \
    Timer/CheckTimeout.hpp \
    Timer/CleanOldCache.hpp \
    Timer/DNSCache.hpp \
    Timer/DNSQuery.hpp

SOURCES += Backend.cpp \
    Http.cpp \
    Https.cpp \
    Http3.cpp \
    Http3Probe.cpp
HEADERS += Backend.hpp \
        Http.hpp \
        Https.hpp \
        Http3.hpp \
        Http3Probe.hpp
