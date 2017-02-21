CC=clang
CFLAGS=

build/iosdumpkernelfix:
	mkdir -p build;
	$(CC) $(CFLAGS) src/*.c -o $@

.PHONY:install
install:build/iosdumpkernelfix
	mkdir -p /usr/local/bin
	cp build/iosdumpkernelfix /usr/local/bin/iosdumpkernelfix

.PHONY:uninstall
uninstall:
	rm /usr/local/bin/iosdumpkernelfix

.PHONY:clean
clean:
	rm -rf build
