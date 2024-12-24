QT = core

CONFIG += c++17 cmdline

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        CExchangeKey.cpp \
        main.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

# Specify your boost dir here! | Search this on your MacOS
INCLUDEPATH += /usr/local/Cellar/boost/1.85.0/include
INCLUDEPATH += /usr/local/Cellar/openssl@1.1/1.1.1w/include

# NEW Boost patch Sonoma
LIBS += /usr/local/Cellar/openssl@1.1/1.1.1w/lib/libssl.a
LIBS += /usr/local/Cellar/openssl@1.1/1.1.1w/lib/libcrypto.a

HEADERS += \
    CExchangeKey.h
