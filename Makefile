.PHONY: all test clean

TARGET = build/bin/libgmssl.so

all: $(TARGET)

# | build是顺序依赖，顺序依赖：只确保在构建目标之前依赖项存在，但依赖项的时间戳变化不会触发目标的重新构建
$(TARGET): | build
	cd build && cmake .. && make

build:
	mkdir -p build

test: all
	cd build && make test

install: $(TARGET)
	cp $(TARGET) $(ROOT)/luaclib/libgmssl.so.3

clean:
	rm -rf build
