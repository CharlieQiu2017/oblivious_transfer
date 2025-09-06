CC = /opt/aarch64-none-elf/bin/aarch64-none-elf-gcc
CXX = /opt/aarch64-none-elf/bin/aarch64-none-elf-g++
AS = /opt/aarch64-none-elf/bin/aarch64-none-elf-as
LD = /opt/aarch64-none-elf/bin/aarch64-none-elf-ld
M4 = m4
STDFLAGS = -std=c11
CXXSTDFLAGS = -std=c++20
FREEFLAGS = -nostdlib -ffreestanding
CXXFREEFLAGS = -nostdlib -ffreestanding -fno-exceptions -fno-rtti -fno-threadsafe-statics
WARNFLAGS = -Wall -Wextra -pedantic -Werror -Wfatal-errors
ARCHFLAGS = -march=armv8-a+crc+crypto -mtune=cortex-a72.cortex-a53
PROTFLAGS = -fomit-frame-pointer -fno-asynchronous-unwind-tables -fcf-protection=none -fno-stack-protector -fno-stack-clash-protection
GCFLAGS = -ffunction-sections
LDFLAGS = -nostdlib -static --no-dynamic-linker -e _start --gc-sections --build-id=none

ifeq ($(optimize),1)
  OPTFLAGS = -Os -fweb
else
  OPTFLAGS = -O0
  ifeq ($(debug),1)
    ifndef DEBUG_SRC_DIR
      OPTFLAGS += -g
    else
      OPTFLAGS += -g -fdebug-prefix-map=$$(pwd -L)=$(DEBUG_SRC_DIR)
    endif
  endif
endif

LIBGCC = /opt/aarch64-none-elf/lib/gcc/aarch64-none-elf/14.2.0/libgcc.a
LIBC = /home/z/mini_libc
LIBSUPCXX = /opt/aarch64-none-elf/aarch64-none-elf/lib/libsupc++_terminate.a

INCFLAGS = -I ./include -I $(LIBC)/include
EXTFLAGS = 

CFLAGS = $(STDFLAGS) $(FREEFLAGS) $(WARNFLAGS) $(ARCHFLAGS) $(PROTFLAGS) $(GCFLAGS) $(OPTFLAGS) $(INCFLAGS) $(EXTFLAGS)
CXXFLAGS = $(CXXSTDFLAGS) $(CXXFREEFLAGS) $(WARNFLAGS) $(ARCHFLAGS) $(PROTFLAGS) $(GCFLAGS) $(OPTFLAGS) $(INCFLAGS) $(EXTFLAGS)

# Template sources
# These files must be first processed by M4
C_TMPLS = $(shell find src -regex '.*\.c.m4')
C_TMPL_SRCS = $(patsubst src/%.c.m4,tmp/%.c,$(C_TMPLS))
C_TMPL_DIRS = $(sort $(patsubst %/,%,$(dir $(C_TMPL_SRCS))))

CXX_TMPLS = $(shell find src -regex '.*\.cpp.m4')
CXX_TMPL_SRCS = $(patsubst src/%.cpp.m4,tmp/%.cpp,$(CXX_TMPLS))
CXX_TMPL_DIRS = $(sort $(patsubst %/,%,$(dir $(CXX_TMPL_SRCS))))

# Raw sources
# These files can be compiled directly
C_SRCS = $(shell find src -regex '.*\.c')
CXX_SRCS = $(shell find src -regex '.*\.cpp')

# Object files
OBJS = $(patsubst src/%.c,obj/%.o,$(C_SRCS)) $(patsubst tmp/%.c,obj/%.o,$(C_TMPL_SRCS)) $(patsubst src/%.cpp,obj/%.o,$(CXX_SRCS)) $(patsubst tmp/%.cpp,obj/%.o,$(CXX_TMPL_SRCS))
LOBJS = $(patsubst src/%.c,obj/%.lo,$(C_SRCS)) $(patsubst tmp/%.c,obj/%.lo,$(C_TMPL_SRCS)) $(patsubst src/%.cpp,obj/%.lo,$(CXX_SRCS)) $(patsubst tmp/%.cpp,obj/%.lo,$(CXX_TMPL_SRCS))
OBJ_DIRS = $(sort $(patsubst %/,%,$(dir $(OBJS))))

# Unit tests
C_TEST_SRCS = $(shell find test-src -regex '.*\.c')
CXX_TEST_SRCS = $(shell find test-src -regex '.*\.cpp')
TEST_OBJS = $(patsubst test-src/%.c,test-bin/%.o,$(C_TEST_SRCS)) $(patsubst test-src/%.cpp,test-bin/%.o,$(CXX_TEST_SRCS))
TEST_BINS = $(patsubst test-src/%.c,test-bin/%,$(C_TEST_SRCS)) $(patsubst test-src/%.cpp,test-bin/%,$(CXX_TEST_SRCS))
TEST_OBJ_DIRS = $(sort $(patsubst %/,%,$(dir $(TEST_OBJS))))

all: libot.a libot_pic.a $(TEST_BINS)

archive:
	tar -C .. -czf ../libot.tar.gz oblivious

$(OBJS) $(LOBJS) : | $(OBJ_DIRS)

$(TMPL_SRCS) : | $(TMPL_DIRS)

$(TEST_OBJS) $(TEST_BINS) : | $(TEST_OBJ_DIRS)

$(OBJ_DIRS) $(TMPL_DIRS) $(TEST_OBJ_DIRS) :
	mkdir -p $@

obj/%.o : src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

obj/%.o : src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

tmp/%.c : src/%.m4
	$(M4) $< > $@

obj/%.o : tmp/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

obj/%.o : tmp/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

obj/%.lo : src/%.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

obj/%.lo : src/%.cpp
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

obj/%.lo : tmp/%.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

obj/%.lo : tmp/%.cpp
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

test-bin/%.o : test-src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test-bin/%.o : test-src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

libot.a : $(OBJS)
	$(AR) rc $@ $^

libot_pic.a : $(LOBJS)
	$(AR) rc $@ $^

test-bin/% : test-bin/%.o libot.a
	$(LD) $(LDFLAGS) -T $(LIBC)/default.lds -o $@ $(LIBC)/crt.o $^ $(LIBSUPCXX) $(LIBC)/libc.a $(LIBGCC)

clean :
	$(RM) -rf obj test-bin tmp libot.a libot_pic.a

.PHONY : all clean archive
