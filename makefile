MAKEFLAGS += --silent

CC = gcc
CFLAGS = -g -Wall -Wextra -std=c99 -Iinclude -Ilib/chacha

OBJDIR = build

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

SRCS = fcrypt.c main.c pbkdf.c
OBJS = $(SRCS:%.c=$(OBJDIR)/%.o)

VPATH = src:lib/chacha

.PHONY: all clean run chacha

all: chacha $(TARGET)

chacha:
	$(MAKE) -C lib/chacha

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -Llib/chacha -lchacha

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	$(MKDIR) $(OBJDIR)

run: $(TARGET)
	./$(TARGET)

clean:
	$(MAKE) -C lib/chacha clean
ifeq ($(OS),Windows_NT)
	$(RM) $(OBJDIR)\*.o
	$(RM) $(TARGET)
else
	$(RM) $(OBJDIR)/*.o
	$(RM) $(TARGET)
endif
