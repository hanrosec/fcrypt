MAKEFLAGS += --silent

CC = gcc
CFLAGS = -g -Wall -Wextra -std=c99 -Iinclude -g

OBJDIR = build
TESTDIR = tests

ifeq ($(OS),Windows_NT)
    RM = del /f /q
    TARGET = $(OBJDIR)\fcrypt.exe
    LIBS =
    MKDIR = mkdir
else
    RM = rm -f
    TARGET = $(OBJDIR)/fcrypt
    LIBS =
    MKDIR = mkdir -p
endif

SRCDIR = src
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

TEST_SRCS = $(wildcard $(TESTDIR)/*.c)
TEST_OBJS = $(TEST_SRCS:$(TESTDIR)/%.c=$(OBJDIR)/%.o)
TEST_OBJS = src/fcrypt.c src/pbkdf.c src/sha3.c

.PHONY: all clean run test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -lssl -lcrypto

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: $(TESTDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	$(MKDIR) $(OBJDIR)

run: $(TARGET)
	./$(TARGET)

clean:
ifeq ($(OS),Windows_NT)
	$(RM) $(OBJDIR)\*.o
	$(RM) $(TARGET)
	$(RM) $(OBJDIR)\test_fcrypt.exe
else
	$(RM) $(OBJDIR)/*.o
	$(RM) $(TARGET)
	$(RM) $(OBJDIR)/test_fcrypt
endif