TEMPLATE = app
TARGET = plc-qt
VERSION = 1.0.0

DEFINES += \
    QT_GUI \
    BOOST_THREAD_USE_LIB \
    BOOST_SPIRIT_THREADSAFE \
    HAVE_WORKING_BOOST_SLEEP_FOR \
    PACKAGE_NAME=$$quote(\"\\\"PLC Core\\\"\") \
    COPYRIGHT_HOLDERS=$$quote(\"\\\"The %s developers\\\"\") \
    COPYRIGHT_HOLDERS_SUBSTITUTION=$$quote(\"\\\"PLC Core\\\"\") \
    COPYRIGHT_HOLDERS_FINAL

QT += core gui network
greaterThan(QT_MAJOR_VERSION, 4) {
    QT += widgets
}

CONFIG += no_include_pwd

#CONFIG(release, debug|release): DEFINES += NDEBUG

# UNCOMMENT THIS SECTION TO BUILD ON WINDOWS
# Change paths if needed, these use the foocoin/deps.git repository locations

!include($$PWD/config.pri) {
   error(Failed to include config.pri)
 }

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build

# use: qmake "RELEASE=1"
contains(RELEASE, 1) {
    # Mac: compile for maximum compatibility (10.5, 32-bit)
    macx:QMAKE_CXXFLAGS += -mmacosx-version-min=10.5 -arch x86_64 -isysroot /Developer/SDKs/MacOSX10.5.sdk

    !windows:!macx {
        # Linux: static link
        LIBS += -Wl,-Bstatic
    }
}

!win32 {
# for extra security against potential buffer overflows: enable GCCs Stack Smashing Protection
QMAKE_CXXFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
QMAKE_LFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
# We need to exclude this for Windows cross compile with MinGW 4.2.x, as it will result in a non-working executable!
# This can be enabled for Windows, when we switch to MinGW >= 4.4.x.
}

# for extra security on Windows: enable ASLR and DEP via GCC linker flags
win32 {
    CONFIG(release, debug|release) {
        QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat
    }
}

QMAKE_CXXFLAGS *= -fpermissive -std=c++11 -fext-numeric-literals

# use: qmake "USE_QRCODE=1"
# libqrencode (http://fukuchi.org/works/qrencode/index.en.html) must be installed for support
contains(USE_QRCODE, 1) {
    message(Building with QRCode support)
    DEFINES += USE_QRCODE
    LIBS += -lqrencode
}

# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
# miniupnpc (http://miniupnp.free.fr/files/) must be installed for support
contains(USE_UPNP, -) {
    message(Building without UPNP support)
} else {
    message(Building with UPNP support)
    count(USE_UPNP, 0) {
        USE_UPNP=1
    }
    DEFINES += USE_UPNP=$$USE_UPNP STATICLIB
	DEFINES += USE_UPNP=$$USE_UPNP MINIUPNP_STATICLIB
    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
    win32:LIBS += -liphlpapi
}

# use: qmake "USE_DBUS=1"
contains(USE_DBUS, 1) {
    message(Building with DBUS (Freedesktop notifications) support)
    DEFINES += USE_DBUS
    QT += dbus
}

# use: qmake "USE_IPV6=1" ( enabled by default; default)
#  or: qmake "USE_IPV6=0" (disabled by default)
#  or: qmake "USE_IPV6=-" (not supported)
contains(USE_IPV6, -) {
    message(Building without IPv6 support)
} else {
    message(Building with IPv6 support)
    count(USE_IPV6, 0) {
        USE_IPV6=1
    }
    DEFINES += USE_IPV6=$$USE_IPV6
}

contains(BITCOIN_NEED_QT_PLUGINS, 1) {
    DEFINES += BITCOIN_NEED_QT_PLUGINS
    QTPLUGIN += qcncodecs qjpcodecs qtwcodecs qkrcodecs qtaccessiblewidgets
}

INCLUDEPATH += \
    src \
    src/qt \
    $$BOOST_INCLUDE_PATH \
    $$BDB_INCLUDE_PATH \
    $$OPENSSL_INCLUDE_PATH \
    $$QRENCODE_INCLUDE_PATH \
    src/leveldb/include \
    src/leveldb/helpers/memenv \
    src/univalue/include

LIBS += \
    $$join(BOOST_LIB_PATH,,-L,) \
    $$join(BDB_LIB_PATH,,-L,) \
    $$join(OPENSSL_LIB_PATH,,-L,) \
    $$join(QRENCODE_LIB_PATH,,-L,) \
    -L$$PWD/src/leveldb/out-static \
    -L$$PWD/src/univalue/.libs


LIBS += \
    -lleveldb \
    -lunivalue \
    -lmemenv \
    -lsecp256k1 \
    -lprotobuf \
    -lssl \
    -lcrypto \
    -ldb_cxx$$BDB_LIB_SUFFIX \
    -lpthread \
    -levent

windows {
    LIBS += \
        -lshlwapi \
        -lws2_32 \
        -lole32 \
        -loleaut32 \
        -luuid \
        -lcrypt32 \
        -lgdi32
}

unix:!macx {
    LIBS += \
        -lboost_system \
        -lboost_filesystem \
        -lboost_program_options \
        -lboost_thread \
        -lboost_date_time
}

SOURCES += \
    src/bloom.cpp \
    src/hash.cpp \
    src/amount.cpp \
    src/arith_uint256.cpp \
    src/base58.cpp \
    src/chain.cpp \
    src/chainparams.cpp \
    src/chainparamsbase.cpp \
    src/clientversion.cpp \
    src/coins.cpp \
    src/compressor.cpp \
    src/core_read.cpp \
    src/core_write.cpp \
    src/merkleblock.cpp \
    src/pow.cpp \
    src/pubkey.cpp \
    src/random.cpp \
    src/rest.cpp \
    src/rpc/rpcblockchain.cpp \
    src/rpc/rpcclient.cpp \
    src/wallet/rpcdump.cpp \
    src/rpc/rpcmining.cpp \
    src/rpc/rpcmisc.cpp \
    src/rpc/rpcnet.cpp \
    src/rpc/rpcprotocol.cpp \
    src/rpc/rpcrawtransaction.cpp \
    src/rpc/rpcserver.cpp \
    src/wallet/rpcwallet.cpp \
    src/timedata.cpp \
    src/txdb.cpp \
    src/txmempool.cpp \
    src/uint256.cpp \
    src/utilmoneystr.cpp \
    src/utilstrencodings.cpp \
    src/utiltime.cpp \
    src/validationinterface.cpp \
    src/qt/intro.cpp \
    src/qt/networkstyle.cpp \
    src/qt/openuridialog.cpp \
    src/qt/paymentrequestplus.cpp \
    src/qt/paymentserver.cpp \
    src/qt/peertablemodel.cpp \
    src/qt/platformstyle.cpp \
    src/qt/receivecoinsdialog.cpp \
    src/qt/receiverequestdialog.cpp \
    src/qt/recentrequeststablemodel.cpp \
    src/qt/splashscreen.cpp \
    src/qt/trafficgraphwidget.cpp \
    src/qt/utilitydialog.cpp \
    src/qt/walletframe.cpp \
    src/qt/walletmodeltransaction.cpp \
    src/qt/walletview.cpp \
    src/qt/winshutdownmonitor.cpp \
    src/compat/strnlen.cpp \
    src/crypto/hmac_sha256.cpp \
    src/crypto/hmac_sha512.cpp \
    src/crypto/ripemd160.cpp \
    src/crypto/scrypt.cpp \
    src/crypto/sha1.cpp \
    src/crypto/sha256.cpp \
    src/crypto/sha512.cpp \
    src/crypto/aes.cpp \
    src/crypto/c_jh.h \
    src/crypto/c_jh.c \
    src/crypto/c_skein.h \
    src/crypto/c_skein.c \
    src/crypto/c_keccak.h \
    src/crypto/c_keccak.c \
    src/crypto/c_groestl.h \
    src/crypto/c_groestl.c \
    src/crypto/c_blake256.h \
    src/crypto/c_blake256.c \
    src/crypto/CryptoNight.h \
    src/crypto/CryptoNight_arm.h \
    src/crypto/CryptoNight_x86.h \
    src/crypto/CryptoNight.cpp \
    src/primitives/block.cpp \
    src/primitives/transaction.cpp \
    src/script/bitcoinconsensus.cpp \
    src/script/interpreter.cpp \
    src/script/script.cpp \
    src/script/script_error.cpp \
    src/script/sigcache.cpp \
    src/script/sign.cpp \
    src/script/standard.cpp \
    src/compat/glibc_sanity.cpp \
    src/compat/glibcxx_sanity.cpp \
    src/support/cleanse.cpp \
    src/validation.cpp \
    src/support/lockedpool.cpp \
    src/httprpc.cpp \
    src/httpserver.cpp \
    src/script/ismine.cpp \
    src/netaddress.cpp \
    src/consensus/merkle.cpp \
    src/warnings.cpp \
    src/versionbits.cpp \
    src/net_processing.cpp \
    src/policy/fees.cpp \
    src/policy/policy.cpp \
    src/policy/rbf.cpp \
    src/dbwrapper.cpp \
    src/ui_interface.cpp \
    src/blockencodings.cpp \
    src/qt/modaloverlay.cpp \
    src/threadinterrupt.cpp \
    src/addrdb.cpp \
    src/scheduler.cpp \
    src/torcontrol.cpp \
    src/qt/bantablemodel.cpp \
    src/qt/bitcoin.cpp \
    src/rpc/rpcdebug.cpp

#protobuf generated
SOURCES += \
    src/qt/paymentrequest.pb.cc

#compat
#    src/compat/glibc_compat.cpp \
#    src/compat/glibcxx_compat.cpp \

#ENABLE_ZMQ
#    src/zmq/zmqabstractnotifier.cpp \
#    src/zmq/zmqnotificationinterface.cpp \
#    src/zmq/zmqpublishnotifier.cpp

#mac
#    src/qt/macdockiconhandler.mm \
#    src/qt/macnotificationhandler.mm \

!win32 {
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a
} else {
    # make an educated guess about what the ranlib command is called
    isEmpty(QMAKE_RANLIB) {
        QMAKE_RANLIB = $$replace(QMAKE_STRIP, strip, ranlib)
    }
    LIBS += -lshlwapi
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX TARGET_OS=OS_WINDOWS_CROSSCOMPILE $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libleveldb.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libmemenv.a
}
genleveldb.target = $$PWD/src/leveldb/libleveldb.a
genleveldb.depends = FORCE

#unix {
#    PRE_TARGETDEPS += $$PWD/src/leveldb/libleveldb.a
#    QMAKE_EXTRA_TARGETS += genleveldb
#    # Gross ugly hack that depends on qmake internals, unfortunately there is no other way to do it.
#    QMAKE_CLEAN += $$PWD/src/leveldb/libleveldb.a; cd $$PWD/src/leveldb ; $(MAKE) clean
#}

# regenerate src/build.h
#!windows|contains(USE_BUILD_INFO, 1) {
#    genbuild.depends = FORCE
#    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
#    genbuild.target = $$OUT_PWD/build/build.h
#    PRE_TARGETDEPS += $$OUT_PWD/build/build.h
#    QMAKE_EXTRA_TARGETS += genbuild
#    DEFINES += HAVE_BUILD_INFO
#}

contains(USE_O3, 1) {
    message(Building O3 optimization flag)
    QMAKE_CXXFLAGS_RELEASE -= -O2
    QMAKE_CFLAGS_RELEASE -= -O2
    QMAKE_CXXFLAGS += -O0
    QMAKE_CFLAGS += -O0
}

QMAKE_CXXFLAGS += -march=native
QMAKE_CFLAGS += -march=native

*-g++-32 {
    message("32 platform, adding -msse2 flag")

    QMAKE_CXXFLAGS += -msse4.1 -maes
    QMAKE_CFLAGS += -msse4.1 -maes
}

QMAKE_CXXFLAGS_WARN_ON = \
        -fdiagnostics-show-option \
        -Wall \
        -Wextra \
        -Wformat \
        -Wformat-security \
        -Wstack-protector \
        -Wno-deprecated-declarations

# Input
DEPENDPATH += \
    src \
    src/qt

HEADERS += \
    src/qt/bitcoingui.h \
    src/qt/transactiontablemodel.h \
    src/qt/addresstablemodel.h \
    src/qt/optionsdialog.h \
    src/qt/coincontroldialog.h \
    src/qt/coincontroltreewidget.h \
    src/qt/sendcoinsdialog.h \
    src/qt/addressbookpage.h \
    src/qt/signverifymessagedialog.h \
    src/qt/editaddressdialog.h \
    src/qt/bitcoinaddressvalidator.h \
    src/addrman.h \
    src/base58.h \
    src/checkpoints.h \
    src/compat.h \
    src/wallet/coincontrol.h \
    src/sync.h \
    src/util.h \
    src/uint256.h \
    src/serialize.h \
    src/miner.h \
    src/net.h \
    src/key.h \
    src/wallet/db.h \
    src/txdb.h \
    src/wallet/walletdb.h \
    src/init.h \
    src/qt/clientmodel.h \
    src/qt/guiutil.h \
    src/qt/transactionrecord.h \
    src/qt/guiconstants.h \
    src/qt/optionsmodel.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/bitcoinamountfield.h \
    src/wallet/wallet.h \
    src/keystore.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionview.h \
    src/qt/walletmodel.h \
    src/qt/overviewpage.h \
    src/qt/csvmodelwriter.h \
    src/wallet/crypter.h \
    src/qt/sendcoinsentry.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/bitcoinunits.h \
    src/qt/qvaluecombobox.h \
    src/qt/askpassphrasedialog.h \
    src/protocol.h \
    src/qt/notificator.h \
    src/ui_interface.h \
    src/qt/rpcconsole.h \
    src/version.h \
    src/netbase.h \
    src/clientversion.h \
    src/bloom.h \
    src/checkqueue.h \
    src/hash.h \
    src/limitedmap.h \
    src/threadsafety.h \
    src/qt/macnotificationhandler.h \    
    src/tinyformat.h \
    src/amount.h \
    src/arith_uint256.h \
    src/chain.h \
    src/chainparams.h \
    src/chainparamsbase.h \
    src/chainparamsseeds.h \
    src/coins.h \
    src/compressor.h \
    src/core_io.h \
    src/merkleblock.h \
    src/noui.h \
    src/pow.h \
    src/pubkey.h \
    src/random.h \
    src/rpc/rpcclient.h \
    src/rpc/rpcprotocol.h \
    src/rpc/rpcserver.h \
    src/streams.h \
    src/timedata.h \
    src/txmempool.h \
    src/undo.h \
    src/utilmoneystr.h \
    src/utilstrencodings.h \
    src/utiltime.h \
    src/validationinterface.h \
    src/qt/intro.h \
    src/qt/networkstyle.h \
    src/qt/openuridialog.h \
    src/qt/paymentrequestplus.h \
    src/qt/paymentserver.h \
    src/qt/peertablemodel.h \
    src/qt/platformstyle.h \
    src/qt/receivecoinsdialog.h \
    src/qt/receiverequestdialog.h \
    src/qt/recentrequeststablemodel.h \
    src/qt/splashscreen.h \
    src/qt/trafficgraphwidget.h \
    src/qt/utilitydialog.h \
    src/qt/walletframe.h \
    src/qt/walletmodeltransaction.h \
    src/qt/walletview.h \
    src/qt/winshutdownmonitor.h \
    src/compat/sanity.h \
    src/crypto/common.h \
    src/crypto/hmac_sha256.h \
    src/crypto/hmac_sha512.h \
    src/crypto/ripemd160.h \
    src/crypto/scrypt.h \
    src/crypto/sha1.h \
    src/crypto/sha256.h \
    src/crypto/sha512.h \
    src/crypto/cryptonight.h \
    src/crypto/cryptonight_oaes.h \
    src/primitives/block.h \
    src/primitives/transaction.h \
    src/script/bitcoinconsensus.h \
    src/script/interpreter.h \
    src/script/script.h \
    src/script/script_error.h \
    src/script/sigcache.h \
    src/script/sign.h \
    src/script/standard.h \
    src/support/cleanse.h \
    src/compat/endian.h \
    src/compat/byteswap.h \
    src/qt/res/bitcoin-qt-res.rc \
    src/validation.h \
    src/support/events.h \
    src/support/lockedpool.h \
    src/support/allocators/secure.h \
    src/support/allocators/zeroafterfree.h \
    src/httprpc.h \
    src/httpserver.h \
    src/script/ismine.h \
    src/netaddress.h \
    src/consensus/consensus.h \
    src/consensus/merkle.h \
    src/consensus/params.h \
    src/consensus/validation.h \
    src/warnings.h \
    src/versionbits.h \
    src/net_processing.h \
    src/policy/fees.h \
    src/policy/policy.h \
    src/policy/rbf.h \
    src/dbwrapper.h \
    src/blockencodings.h \
    src/qt/modaloverlay.h \
    src/threadinterrupt.h \
    src/addrdb.h \
    src/scheduler.h \
    src/torcontrol.h \
    src/qt/bantablemodel.h \
    src/rpc/rpcregister.h \
    src/qt/paymentrequest.pb.h \
    src/chainparams-checkpoints.h

#ENABLE_ZMQ
#    src/zmq/zmqabstractnotifier.h \
#    src/zmq/zmqconfig.h \
#    src/zmq/zmqnotificationinterface.h \
#    src/zmq/zmqpublishnotifier.h


SOURCES += \
    src/qt/bitcoingui.cpp \
    src/qt/transactiontablemodel.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/coincontroldialog.cpp \
    src/qt/coincontroltreewidget.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/bitcoinaddressvalidator.cpp \
    src/sync.cpp \
    src/util.cpp \
    src/netbase.cpp \
    src/key.cpp \
    src/miner.cpp \
    src/init.cpp \
    src/net.cpp \
    src/checkpoints.cpp \
    src/addrman.cpp \
    src/wallet/db.cpp \
    src/wallet/walletdb.cpp \
    src/qt/clientmodel.cpp \
    src/qt/guiutil.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/bitcoinamountfield.cpp \
    src/wallet/wallet.cpp \
    src/keystore.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionview.cpp \
    src/qt/walletmodel.cpp \
    src/qt/overviewpage.cpp \
    src/qt/csvmodelwriter.cpp \
    src/wallet/crypter.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/bitcoinunits.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/protocol.cpp \
    src/qt/notificator.cpp \
    src/qt/rpcconsole.cpp \
    src/noui.cpp

RESOURCES += \
    src/qt/bitcoin.qrc \
    src/qt/bitcoin_locale.qrc

FORMS += \
    src/qt/forms/coincontroldialog.ui \
    src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/transactiondescdialog.ui \
    src/qt/forms/overviewpage.ui \
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/askpassphrasedialog.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/helpmessagedialog.ui \
    src/qt/forms/intro.ui \
    src/qt/forms/openuridialog.ui \
    src/qt/forms/receivecoinsdialog.ui \
    src/qt/forms/receiverequestdialog.ui \
    src/qt/forms/debugwindow.ui \
    src/qt/forms/modaloverlay.ui


contains(USE_QRCODE, 1) {
HEADERS += src/qt/qrcodedialog.h
SOURCES += src/qt/qrcodedialog.cpp
FORMS += src/qt/forms/qrcodedialog.ui
}

CODECFORTR = UTF-8

# for lrelease/lupdate
# also add new translations to src/qt/bitcoin.qrc under translations/
TRANSLATIONS = $$files(src/qt/locale/bitcoin_*.ts)

isEmpty(QMAKE_LRELEASE) {
    win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]\\lrelease.exe
    else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale
# automatically build translations, so they can be included in resource file
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# "Other files" to show in Qt Creator
OTHER_FILES += \
    doc/*.rst \
    doc/*.txt \
    doc/README \
    README.md \
    res/bitcoin-qt-res.rc \
    configure.ac


# platform specific defaults, if not overridden on command line
#isEmpty(BOOST_LIB_SUFFIX) {
#    macx:BOOST_LIB_SUFFIX = -mt
#    windows:BOOST_LIB_SUFFIX = -mgw48-mt-s-1_55
#}

isEmpty(BOOST_THREAD_LIB_SUFFIX) {
    BOOST_THREAD_LIB_SUFFIX = $$BOOST_LIB_SUFFIX
}

isEmpty(BDB_LIB_PATH) {
    macx:BDB_LIB_PATH = /opt/local/lib/db48
}

isEmpty(BDB_LIB_SUFFIX) {
    macx:BDB_LIB_SUFFIX = -4.8
}

isEmpty(BDB_INCLUDE_PATH) {
    macx:BDB_INCLUDE_PATH = /opt/local/include/db48
}

isEmpty(BOOST_LIB_PATH) {
    macx:BOOST_LIB_PATH = /opt/local/lib
}

isEmpty(BOOST_INCLUDE_PATH) {
    macx:BOOST_INCLUDE_PATH = /opt/local/include
}

windows:DEFINES += WIN32
windows:QMAKE_RC = windres -DWINDRES_PREPROC
windows:RC_FILE = src/qt/res/bitcoin-qt-res.rc

windows:!contains(MINGW_THREAD_BUGFIX, 0) {
    # At least qmake's win32-g++-cross profile is missing the -lmingwthrd
    # thread-safety flag. GCC has -mthreads to enable this, but it doesn't
    # work with static linking. -lmingwthrd must come BEFORE -lmingw, so
    # it is prepended to QMAKE_LIBS_QT_ENTRY.
    # It can be turned off with MINGW_THREAD_BUGFIX=0, just in case it causes
    # any problems on some untested qmake profile now or in the future.
    DEFINES += _MT BOOST_THREAD_PROVIDES_GENERIC_SHARED_MUTEX_ON_WIN
    QMAKE_LIBS_QT_ENTRY = -lmingwthrd $$QMAKE_LIBS_QT_ENTRY
}

!windows:!macx {
    DEFINES += LINUX
    LIBS += -lrt
}

macx:HEADERS += src/qt/macdockiconhandler.h src/qt/macnotificationhandler.h
macx:OBJECTIVE_SOURCES += src/qt/macdockiconhandler.mm src/qt/macnotificationhandler.mm
macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:ICON = src/qt/res/icons/bitcoin.icns
macx:TARGET = "plc-Qt"
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_CXXFLAGS_THREAD += -pthread

# Set libraries and includes at end, to use platform-defined defaults if not overridden

# -lgdi32 has to happen after -lcrypto (see  #681)
windows:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
LIBS += \
    -lboost_system$$BOOST_LIB_SUFFIX \
    -lboost_filesystem$$BOOST_LIB_SUFFIX \
    -lboost_program_options$$BOOST_LIB_SUFFIX \
    -lboost_thread$$BOOST_THREAD_LIB_SUFFIX \
    -lboost_date_time$$BOOST_THREAD_LIB_SUFFIX

windows:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX

contains(RELEASE, 1) {
    !windows:!macx {
        # Linux: turn dynamic linking back on for c/c++ runtime libraries
        LIBS += -Wl,-Bdynamic
    }
}

system($$QMAKE_LRELEASE -silent $$_PRO_FILE_)

DISTFILES += \
    src/qt/paymentrequest.proto \
    src/Makefile.am
