#ifndef INPUT_PARSER_INCLUDED
#define INPUT_PARSER_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ERROR_MESSAGE_CAPACITY 128

bool parse_byte_string(
	const char *input_string,
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[]
);

#endif
