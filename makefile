CC = gcc
CFLAGS = -g -Wall -Wextra -std=c99 -Iinclude -g

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

SRCDIR = src
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -lssl -lcrypto

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	$(MKDIR) $(OBJDIR)

run: $(TARGET)
	./$(TARGET)

clean:
ifeq ($(OS),Windows_NT)
	$(RM) $(OBJDIR)\*.o
	$(RM) $(TARGET)
else
	$(RM) $(OBJDIR)/*.o
	$(RM) $(TARGET)
endif