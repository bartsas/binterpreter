binterpreter.o: binterpreter.c input_parser.h
	$(CC) $(CFLAGS) -c $< -o $@

input_parser.o: input_parser.c input_parser.h
	$(CC) $(CFLAGS) -c $< -o $@

$(EXECUTABLE): binterpreter.o input_parser.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@
