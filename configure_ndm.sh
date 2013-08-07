#!/bin/bash
autoreconf
./configure \
	--enable-daemon \
	--enable-utp \
	--enable-largefile \
	--enable-lightweight \
	--disable-cli \
	--disable-dependency-tracking \
	--without-gtk \
	--without-systemd-daemon
