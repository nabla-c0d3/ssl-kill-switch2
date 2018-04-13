export ARCHS := armv7 arm64
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = sslkillswitch
sslkillswitch_FILES = SSLKillSwitch/SSLKillSwitch.m 

sslkillswitch_FRAMEWORKS = Security

# Build as a Substrate Tweak
sslkillswitch_CFLAGS=-DSUBSTRATE_BUILD

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk


after-install::
	# Respring the device
	install.exec "killall -9 SpringBoard"