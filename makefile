CC = gcc
CFLAGS = -g -Wall -Wextra -std=c99 -Iinclude -O3
CFLAGS += -D_FORTIFY_SOURCE=3\
-D_GLIBCXX_ASSERTIONS\
-ftrivial-auto-var-init=zero\
-fPIE -pie

OBJDIR = build
LIBS = -lssl -lcrypto

RM = rm -f
MKDIR = mkdir

ifeq ($(OS),Windows_NT)
    TARGET = $(OBJDIR)\fcrypt.exe
else
    TARGET = $(OBJDIR)/fcrypt
endif

SRCDIR = src
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -fstack-protector-strong -fstack-clash-protection -s

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	$(MKDIR) $(OBJDIR)

run: $(TARGET)
	./$(TARGET)

clean:
	$(RM) $(OBJDIR)/*.o
	$(RM) $(TARGET)
