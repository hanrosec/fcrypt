MAKEFLAGS += --silent

CC = gcc

CFLAGS = -g -Wall -Wextra -std=c99 -Iinclude -Ilib/chacha

OBJDIR = build
TESTDIR = tests
LIBDIR = lib/chacha

SRCS = $(wildcard src/*.c)
TEST_SRCS = $(wildcard $(TESTDIR)/*.c)

OBJS = $(SRCS:src/%.c=$(OBJDIR)/%.o)
TEST_OBJS = $(TEST_SRCS:tests/%.c=$(OBJDIR)/%.o)

TARGET = $(OBJDIR)\fcrypt.exe

LIBRARY = $(LIBDIR)/libchacha.a

all: $(TARGET)

$(TARGET): $(OBJS) $(LIBRARY)
	$(CC) $(CFLAGS) -o $@ $^ -L$(LIBDIR) -lchacha

$(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: tests/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBRARY):
	$(MAKE) -C $(LIBDIR)

$(OBJDIR):
	mkdir $(OBJDIR)

run: $(TARGET)
	$(TARGET)

clean:
	if exist $(OBJDIR)\*.o del /f /q $(OBJDIR)\*.o
	if exist $(TARGET) del /f /q $(TARGET)
	if exist $(TEST_TARGET) del /f /q $(TEST_TARGET)
	$(MAKE) -C $(LIBDIR) clean

.PHONY: all clean run test
