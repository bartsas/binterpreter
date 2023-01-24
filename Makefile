CFLAGS     = -Wall -Wextra -std=gnu99 -pedantic -g
LDFLAGS    =
LIBS       = -lreadline
EXECUTABLE = binterpreter

.PHONY: all
all: $(EXECUTABLE)

.PHONY: clean
clean:
	rm -fv *.o *~

include rules.mk
