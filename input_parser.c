#include "input_parser.h"

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	BLOCK_SIZE         = 1024,
	NAME_CAPACITY      = 32,
	MAX_ARGUMENT_COUNT = 8,
	FILE_PATH_CAPACITY = 1024,
	COMMAND_CAPACITY   = 1024
};

static bool parse_integer_or_expression(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
);

static bool parse_bytes_concatenation(
	const char **const current_char,
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[]
);

static void skip_whitespace(
	const char **const current_char
) {
	while(isspace(**current_char)) {
		++*current_char;
	}
}

static bool consume_token(
	const char **const current_char,
	const char *const expected_token
) {
	const char *const start_char = *current_char;
	for(const char *expected_char = expected_token; *expected_char != '\0'; ++expected_char) {
		if(**current_char != *expected_char) {
			*current_char = start_char;
			return false;
		}
		++*current_char;
	}
	skip_whitespace(current_char);
	return true;
}

static bool append_format(
	char error_message[],
	size_t *const offset,
	const char *const format,
	...
) {
	if(*offset >= ERROR_MESSAGE_CAPACITY) {
		return false;
	}

	va_list arguments;
	va_start(arguments, format);
	const int result = vsnprintf(
		error_message + *offset,
		ERROR_MESSAGE_CAPACITY - *offset,
		format,
		arguments
	);
	va_end(arguments);

	if(result == EOF) {
		return false;
	}
	*offset += result;
	return true;
}

static void generate_unexpected_char_message(
	const char *const *const current_char,
	char error_message[],
	const char *const expected_char
) {
	size_t offset = 0;
	error_message[offset] = '\0';

	if(!append_format(
		error_message,
		&offset,
		"unexpected "
	)) {
		return;
	}
	if(**current_char == '\0') {
		if(!append_format(
			error_message,
			&offset,
			"end-of-file"
		)) {
			return;
		}
	} else {
		if(!append_format(
			error_message,
			&offset,
			"character '"
		)) {
			return;
		}
		if(isprint(**current_char)) {
			if(!append_format(
				error_message,
				&offset,
				"%c",
				**current_char
			)) {
				return;
			}
		} else {
			if(!append_format(
				error_message,
				&offset,
				"\\x02X",
				(unsigned int)**current_char
			)) {
				return;
			}
		}
		if(!append_format(
			error_message,
			&offset,
			"'"
		)) {
			return;
		}
	}
	if(expected_char != NULL) {
		if(!append_format(
			error_message,
			&offset,
			", expecting %s",
			expected_char
		)) {
			return;
		}
	}
}

static bool parse_string_char(
	const char **const current_char,
	const char forbidden_char,
	uint8_t *const result,
	char error_message[]
) {
	if(**current_char == '\\') {
		++*current_char;

		if(**current_char == 'x') {
			++*current_char;

			/* Make sure there is at least a single hexadecimal digit. */
			if(!isxdigit(**current_char)) {
				generate_unexpected_char_message(
					current_char,
					error_message,
					"hexadecimal digit"
				);
				return false;
			}

			/* Parse the value of the hexadecimal escape sequence. */
			*result = 0;
			for(size_t digit_count = 0; digit_count < 2; ++digit_count) {
				if('0' <= **current_char && **current_char <= '9') {
					*result = *result * 0x10 + (**current_char - '0');
				} else if('A' <= **current_char && **current_char <= 'F') {
					*result = *result * 0x10 + (**current_char - 'A' + 0xA);
				} else if('a' <= **current_char && **current_char <= 'f') {
					*result = *result * 0x10 + (**current_char - 'a' + 0xA);
				} else {
					break;
				}
				++*current_char;
			}
			return true;
		}

		if('0' <= **current_char && **current_char <= '7') {
			/* Parse the value of the octal escape sequence. */
			*result = 0;
			for(size_t digit_count = 0; digit_count < 3 && '0' <= **current_char && **current_char <= '7'; ++digit_count) {
				*result = *result * 010 + (**current_char - '0');
				++*current_char;
			}
			return true;
		}

		const char escape_char = *(*current_char)++;
		switch(escape_char) {
			case 'a': {
				*result = 0x07;
				return true;
			}

			case 'b': {
				*result = 0x08;
				return true;
			}

			case 'e': {
				*result = 0x1B;
				return true;
			}

			case 'f': {
				*result = 0x0C;
				return true;
			}

			case 'n': {
				*result = 0x0A;
				return true;
			}

			case 'r': {
				*result = 0x0D;
				return true;
			}

			case 't': {
				*result = 0x09;
				return true;
			}

			case 'v': {
				*result = 0x0B;
				return true;
			}

			case '\\': case '\'': case '\"': {
				*result = escape_char;
				return true;
			}
		}

		generate_unexpected_char_message(
			current_char,
			error_message,
			"escape character"
		);
		return false;
	}

	if(isprint(**current_char) && **current_char != forbidden_char) {
		*result = *(*current_char)++;
		return true;
	}

	generate_unexpected_char_message(
		current_char,
		error_message,
		"string character"
	);
	return false;
}

static bool parse_string_argument(
	const char **const current_char,
	char string[],
	const size_t capacity,
	char error_message[]
) {
	if(**current_char != '"') {
		generate_unexpected_char_message(
			current_char,
			error_message,
			"double quote"
		);
		return false;
	}
	++*current_char;

	size_t size = 0;
	while(!consume_token(current_char, "\"")) {
		const size_t new_size = size + 1;
		if(new_size >= capacity) {
			snprintf(
				error_message,
				ERROR_MESSAGE_CAPACITY,
				"string argument is too long"
			);
			return false;
		}

		uint8_t parsed_char;
		if(!parse_string_char(
			current_char,
			'\"',
			&parsed_char,
			error_message
		)) {
			return false;
		}
		string[size] = parsed_char;
		size = new_size;
	}
	string[size] = '\0';

	return true;
}

static bool parse_arguments(
	const char **const current_char,
	char error_message[],
	const char *const parameter_types,
	...
) {
	if(!consume_token(current_char, "(")) {
		generate_unexpected_char_message(
			current_char,
			error_message,
			"left parenthesis"
		);
		return false;
	}

	/* Va_start and va_end might introduce a new scope so make sure to define this
	   variable before calling va_start. */
	bool success = true;

	va_list arguments;
	va_start(arguments, parameter_types);

	for(const char *parameter_type = parameter_types; success; ++parameter_type) {
		if(consume_token(current_char, ")")) {
			if(tolower(*parameter_type) != *parameter_type) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"insufficient arguments"
				);
				success = false;
			}
			break;
		}

		if(parameter_type != parameter_types && !consume_token(current_char, ",")) {
			generate_unexpected_char_message(
				current_char,
				error_message,
				"comma"
			);
			success = false;
			break;
		}

		switch(tolower(*parameter_type)) {
			case '\0': {
				generate_unexpected_char_message(
					current_char,
					error_message,
					"right parenthesis"
				);
				success = false;
				break;
			}
			case 'i': {
				unsigned long *const argument = va_arg(
					arguments,
					unsigned long *
				);
				success = parse_integer_or_expression(
					NULL,
					current_char,
					argument,
					error_message
				);
				break;
			}
			case 's': {
				char *const string = va_arg(
					arguments,
					char *
				);
				const size_t capacity = va_arg(
					arguments,
					size_t
				);
				success = parse_string_argument(
					current_char,
					string,
					capacity,
					error_message
				);
				break;
			}
			default: {
				assert(false);
			}
		}
	}

	va_end(arguments);

	return success;
}

static bool determine_file_size(
	unsigned long *const result,
	char error_message[],
	const char *const file_path
) {
	bool success = false;

	FILE *const input_file = fopen(file_path, "r");
	if(input_file != NULL) {
		if(fseek(input_file, 0, SEEK_END) == 0) {
			const long file_size = ftell(input_file);
			if(file_size >= 0) {
				*result = file_size;
				success = true;
			} else {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"unable to determine size of %s",
					file_path
				);
				success = false;
			}
		} else {
			snprintf(
				error_message,
				ERROR_MESSAGE_CAPACITY,
				"unable to determine size of %s",
				file_path
			);
			success = false;
		}

		fclose(input_file);
	} else {
		snprintf(
			error_message,
			ERROR_MESSAGE_CAPACITY,
			"unable to open file: %s",
			file_path
		);
		success = false;
	}

	return success;
}

static bool perform_integer_function(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
) {
	if(strcmp(function_name, "filesize") == 0) {
		char file_path[FILE_PATH_CAPACITY];
		return parse_arguments(
			current_char,
			error_message,
			"S",
			file_path,
			FILE_PATH_CAPACITY
		) && determine_file_size(
			result,
			error_message,
			file_path
		);
	}
	if(strcmp(function_name, "min") == 0) {
		unsigned long right_operand;
		if(!parse_arguments(
			current_char,
			error_message,
			"II",
			result,
			&right_operand
		)) {
			return false;
		}
		if(right_operand < *result) {
			*result = right_operand;
		}
		return true;
	}
	if(strcmp(function_name, "max") == 0) {
		unsigned long right_operand;
		if(!parse_arguments(
			current_char,
			error_message,
			"II",
			result,
			&right_operand
		)) {
			return false;
		}
		if(right_operand > *result) {
			*result = right_operand;
		}
		return true;
	}
	if(strcmp(function_name, "null") == 0
		|| strcmp(function_name, "nul") == 0
	) {
		*result = 0x0;
		return true;
	}
	if(strcmp(function_name, "som") == 0
		|| strcmp(function_name, "soh") == 0
	) {
		*result = 0x1;
		return true;
	}
	if(strcmp(function_name, "eoa") == 0
		|| strcmp(function_name, "stx") == 0
	) {
		*result = 0x2;
		return true;
	}
	if(strcmp(function_name, "eom") == 0
		|| strcmp(function_name, "etx") == 0
	) {
		*result = 0x3;
		return true;
	}
	if(strcmp(function_name, "eot") == 0) {
		*result = 0x4;
		return true;
	}
	if(strcmp(function_name, "wru") == 0
		|| strcmp(function_name, "enq") == 0
	) {
		*result = 0x5;
		return true;
	}
	if(strcmp(function_name, "ru") == 0
		|| strcmp(function_name, "ack") == 0
	) {
		*result = 0x6;
		return true;
	}
	if(strcmp(function_name, "bell") == 0
		|| strcmp(function_name, "bel") == 0
	) {
		*result = 0x7;
		return true;
	}
	if(strcmp(function_name, "fe0") == 0
		|| strcmp(function_name, "bs") == 0
	) {
		*result = 0x8;
		return true;
	}
	if(strcmp(function_name, "ht") == 0) {
		*result = 0x9;
		return true;
	}
	if(strcmp(function_name, "lf") == 0) {
		*result = 0xA;
		return true;
	}
	if(strcmp(function_name, "vtab") == 0
		|| strcmp(function_name, "vt") == 0
	) {
		*result = 0xB;
		return true;
	}
	if(strcmp(function_name, "ff") == 0) {
		*result = 0xC;
		return true;
	}
	if(strcmp(function_name, "cr") == 0) {
		*result = 0xD;
		return true;
	}
	if(strcmp(function_name, "so") == 0) {
		*result = 0xE;
		return true;
	}
	if(strcmp(function_name, "si") == 0) {
		*result = 0xF;
		return true;
	}
	if(strcmp(function_name, "dc0") == 0
		|| strcmp(function_name, "dle") == 0
	) {
		*result = 0x10;
		return true;
	}
	if(strcmp(function_name, "dc1") == 0) {
		*result = 0x11;
		return true;
	}
	if(strcmp(function_name, "dc2") == 0) {
		*result = 0x12;
		return true;
	}
	if(strcmp(function_name, "dc3") == 0) {
		*result = 0x13;
		return true;
	}
	if(strcmp(function_name, "dc4") == 0) {
		*result = 0x14;
		return true;
	}
	if(strcmp(function_name, "err") == 0
		|| strcmp(function_name, "nak") == 0
	) {
		*result = 0x15;
		return true;
	}
	if(strcmp(function_name, "sync") == 0
		|| strcmp(function_name, "syn") == 0
	) {
		*result = 0x16;
		return true;
	}
	if(strcmp(function_name, "lem") == 0
		|| strcmp(function_name, "etb") == 0
	) {
		*result = 0x17;
		return true;
	}
	if(strcmp(function_name, "s0") == 0
		|| strcmp(function_name, "can") == 0
	) {
		*result = 0x18;
		return true;
	}
	if(strcmp(function_name, "s1") == 0
		|| strcmp(function_name, "em") == 0
	) {
		*result = 0x19;
		return true;
	}
	if(strcmp(function_name, "s2") == 0
		|| strcmp(function_name, "ss") == 0
		|| strcmp(function_name, "sub") == 0
	) {
		*result = 0x1A;
		return true;
	}
	if(strcmp(function_name, "s3") == 0
		|| strcmp(function_name, "esc") == 0
	) {
		*result = 0x1B;
		return true;
	}
	if(strcmp(function_name, "s4") == 0
		|| strcmp(function_name, "fs") == 0
	) {
		*result = 0x1C;
		return true;
	}
	if(strcmp(function_name, "s5") == 0
		|| strcmp(function_name, "gs") == 0
	) {
		*result = 0x1D;
		return true;
	}
	if(strcmp(function_name, "s6") == 0
		|| strcmp(function_name, "rs") == 0
	) {
		*result = 0x1E;
		return true;
	}
	if(strcmp(function_name, "s7") == 0
		|| strcmp(function_name, "us") == 0
	) {
		*result = 0x1F;
		return true;
	}
	if(strcmp(function_name, "del") == 0) {
		*result = 0x7F;
		return true;
	}

	snprintf(
		error_message,
		ERROR_MESSAGE_CAPACITY,
		"unknown function: %s",
		function_name
	);
	return false;
}

static bool parse_integer_primary(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
) {
	/* The function_name parameter is a hack. If the parse_bytes_primary function
	   parses a function it does not know it will pass this parameter to the
	   functions that parse integers. The parameter being set indicates that a
	   function name has already been parsed and that nothing else that does not
	   lead to an integer function call should be parsed. In this function nothing
	   else than a function call is considered if this parameter is set. */
	if(function_name != NULL) {
		return perform_integer_function(
			function_name,
			current_char,
			result,
			error_message
		);
	}

	if(consume_token(current_char, "(")) {
		return parse_integer_or_expression(
			NULL,
			current_char,
			result,
			error_message
		) && consume_token(
			current_char,
			")"
		);
	}

	if(consume_token(current_char, "~")) {
		if(!parse_integer_primary(
			NULL,
			current_char,
			result,
			error_message
		)) {
			return false;
		}
		*result = ~*result;
		return true;
	}

	if(isalpha(**current_char)) {
		char name[NAME_CAPACITY + 1];
		size_t name_size = 0;
		while(isalnum(**current_char)) {
			if(name_size >= NAME_CAPACITY) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"name too large"
				);
				return false;
			}
			name[name_size++] = tolower(*(*current_char)++);
		}
		name[name_size] = '\0';
		skip_whitespace(current_char);

		return perform_integer_function(
			name,
			current_char,
			result,
			error_message
		);
	}

	if(**current_char == '\'') {
		++*current_char;

		uint8_t parsed_char;
		if(!parse_string_char(
			current_char,
			'\'',
			&parsed_char,
			error_message
		)) {
			return false;
		}
		if(!consume_token(current_char, "\'")) {
			generate_unexpected_char_message(
				current_char,
				error_message,
				"single quote"
			);
			return false;
		}

		*result = parsed_char;
		return true;
	}

	if(**current_char == '0') {
		++*current_char;

		if(tolower(**current_char) == 'x') {
			++*current_char;

			/* Make sure there is at least one hexadecimal digit. */
			if(!isxdigit(**current_char)) {
				generate_unexpected_char_message(
					current_char,
					error_message,
					"hexadecimal digit"
				);
				return false;
			}

			*result = 0;
			while(true) {
				if('0' <= **current_char && **current_char <= '9') {
					*result = *result * 0x10 + (**current_char - '0');
				} else if('A' <= **current_char && **current_char <= 'F') {
					*result = *result * 0x10 + (**current_char - 'A' + 0xA);
				} else if('a' <= **current_char && **current_char <= 'f') {
					*result = *result * 0x10 + (**current_char - 'a' + 0xA);
				} else {
					break;
				}
				++*current_char;
			}

			skip_whitespace(current_char);
			return true;
		}

		*result = 0;
		while('0' <= **current_char && **current_char <= '7') {
			*result = *result * 010 + (**current_char - '0');
			++*current_char;
		}

		skip_whitespace(current_char);
		return true;
	}

	if(isdigit(**current_char)) {
		*result = 0;
		while(isdigit(**current_char)) {
			*result = *result * 10 + (**current_char - '0');
			++*current_char;
		}

		skip_whitespace(current_char);
		return true;
	}

	generate_unexpected_char_message(
		current_char,
		error_message,
		"TODO"
	);
	return false;
}

static bool parse_integer_multiplication(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
) {
	if(!parse_integer_primary(
		function_name,
		current_char,
		result,
		error_message
	)) {
		return false;
	}

	while(true) {
		if(consume_token(current_char, "*")) {
			unsigned long operand;
			if(!parse_integer_primary(
				NULL,
				current_char,
				&operand,
				error_message
			)) {
				return false;
			}
			if(*result != 0 && ~0ul / *result < operand) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"cannot multiply %lu and %lu",
					*result,
					operand
				);
				return false;
			}
			*result *= operand;
		} else if(consume_token(current_char, "/")) {
			unsigned long operand;
			if(!parse_integer_primary(
				NULL,
				current_char,
				&operand,
				error_message
			)) {
				return false;
			}
			if(operand == 0) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"cannot divide by zero"
				);
				return false;
			}
			*result /= operand;
		} else if(consume_token(current_char, "%")) {
			unsigned long operand;
			if(!parse_integer_primary(
				NULL,
				current_char,
				&operand,
				error_message
			)) {
				return false;
			}
			if(operand == 0) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"cannot divide by zero"
				);
				return false;
			}
			*result %= operand;
		} else {
			break;
		}
	}

	return true;
}

static bool parse_integer_addition(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
) {
	if(!parse_integer_multiplication(
		function_name,
		current_char,
		result,
		error_message
	)) {
		return false;
	}

	while(true) {
		if(consume_token(current_char, "+")) {
			unsigned long operand;
			if(!parse_integer_multiplication(
				NULL,
				current_char,
				&operand,
				error_message
			)) {
				return false;
			}
			if(operand > ~0ul - *result) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"cannot add %lu and %lu",
					*result,
					operand
				);
				return false;
			}
			*result += operand;
		} else if(consume_token(current_char, "-")) {
			unsigned long operand;
			if(!parse_integer_multiplication(
				NULL,
				current_char,
				&operand,
				error_message
			)) {
				return false;
			}
			if(operand > *result) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"cannot subtract %lu from %lu",
					operand,
					*result
				);
				return false;
			}
			*result -= operand;
		} else {
			break;
		}
	}

	return true;
}

static bool parse_integer_shift_expression(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
) {
	if(!parse_integer_addition(
		function_name,
		current_char,
		result,
		error_message
	)) {
		return false;
	}

	while(true) {
		if(consume_token(current_char, "<<")) {
			unsigned long operand;
			if(!parse_integer_addition(
				NULL,
				current_char,
				&operand,
				error_message
			)) {
				return false;
			}
			/* TODO check for overflow */
			*result <<= operand;
		} else if(consume_token(current_char, ">>")) {
			unsigned long operand;
			if(!parse_integer_addition(
				NULL,
				current_char,
				&operand,
				error_message
			)) {
				return false;
			}
			*result >>= operand;
		} else {
			break;
		}
	}

	return true;
}

static bool parse_integer_and_expression(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
) {
	if(!parse_integer_shift_expression(
		function_name,
		current_char,
		result,
		error_message
	)) {
		return false;
	}

	while(consume_token(current_char, "&")) {
		unsigned long operand;
		if(!parse_integer_shift_expression(
			NULL,
			current_char,
			&operand,
			error_message
		)) {
			return false;
		}
		*result &= operand;
	}

	return true;
}

static bool parse_integer_xor_expression(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
) {
	if(!parse_integer_and_expression(
		function_name,
		current_char,
		result,
		error_message
	)) {
		return false;
	}

	while(consume_token(current_char, "^")) {
		unsigned long operand;
		if(!parse_integer_and_expression(
			NULL,
			current_char,
			&operand,
			error_message
		)) {
			return false;
		}
		*result ^= operand;
	}

	return true;
}

static bool parse_integer_or_expression(
	const char *const function_name,
	const char **const current_char,
	unsigned long *const result,
	char error_message[]
) {
	if(!parse_integer_xor_expression(
		function_name,
		current_char,
		result,
		error_message
	)) {
		return false;
	}

	while(consume_token(current_char, "|")) {
		unsigned long operand;
		if(!parse_integer_xor_expression(
			NULL,
			current_char,
			&operand,
			error_message
		)) {
			return false;
		}
		*result |= operand;
	}

	return true;
}

static bool append_byte(
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[],
	const uint8_t byte
) {
	if(*result_size >= *result_capacity) {
		*result_capacity += BLOCK_SIZE;
		uint8_t *const new_result_buffer = realloc(
			*result_buffer,
			*result_capacity
		);
		if(new_result_buffer == NULL) {
			snprintf(
				error_message,
				ERROR_MESSAGE_CAPACITY,
				"failed to allocate memory"
			);
			return false;
		}
		*result_buffer = new_result_buffer;
	}

	(*result_buffer)[*result_size] = byte;
	++*result_size;
	return true;
}

static bool parse_integer_range(
	const char *const function_name,
	const char **const current_char,
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[]
) {
	unsigned long start_value;
	if(!parse_integer_or_expression(
		function_name,
		current_char,
		&start_value,
		error_message
	)) {
		return false;
	}
	if(start_value > 0xFF) {
		snprintf(
			error_message,
			ERROR_MESSAGE_CAPACITY,
			"start value is too large to fit in a byte: %lu",
			start_value
		);
		return false;
	}

	unsigned long end_value = start_value;
	if(consume_token(current_char, "..")) {
		if(!parse_integer_or_expression(
			NULL,
			current_char,
			&end_value,
			error_message
		)) {
			return false;
		}
		if(end_value > 0xFF) {
			snprintf(
				error_message,
				ERROR_MESSAGE_CAPACITY,
				"end value is too large to fit in a byte: %lu",
				end_value
			);
			return false;
		}
	}

	while(true) {
		if(!append_byte(
			result_buffer,
			result_capacity,
			result_size,
			error_message,
			start_value
		)) {
			return false;
		}
		if(start_value < end_value) {
			++start_value;
		} else if(start_value > end_value) {
			--start_value;
		} else {
			break;
		}
	}

	return true;
}

static bool append_be_integer(
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[],
	const size_t integer_size,
	const unsigned long integer_value
) {
	if(integer_size % 8 != 0) {
		snprintf(
			error_message,
			ERROR_MESSAGE_CAPACITY,
			"integer size is not a multiple of 8: %zd",
			integer_size
		);
		return false;
	}
	if(integer_value >> integer_size != 0) {
		snprintf(
			error_message,
			ERROR_MESSAGE_CAPACITY,
			"value is too large to fit in %zd bits: %lu",
			integer_size,
			integer_value
		);
		return false;
	}
	for(size_t bit_offset = 0; bit_offset < integer_size; bit_offset += 8) {
		if(!append_byte(
			result_buffer,
			result_capacity,
			result_size,
			error_message,
			integer_value >> integer_size - bit_offset - 8 & 0xFF
		)) {
			return false;
		}
	}
	return true;
}

static bool append_le_integer(
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[],
	const size_t integer_size,
	const unsigned long integer_value
) {
	if(integer_size % 8 != 0) {
		snprintf(
			error_message,
			ERROR_MESSAGE_CAPACITY,
			"integer size is not a multiple of 8: %zd",
			integer_size
		);
		return false;
	}
	if(integer_value >> integer_size != 0) {
		snprintf(
			error_message,
			ERROR_MESSAGE_CAPACITY,
			"value is too large to fit in %zd bits: %lu",
			integer_size,
			integer_value
		);
		return false;
	}
	for(size_t bit_offset = 0; bit_offset < integer_size; bit_offset += 8) {
		if(!append_byte(
			result_buffer,
			result_capacity,
			result_size,
			error_message,
			integer_value >> bit_offset & 0xFF
		)) {
			return false;
		}
	}
	return true;
}

static bool load_data_from_file(
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[],
	const char *const action,
	const char *const description,
	FILE *const input_file,
	const unsigned long start_offset,
	const unsigned long size_limit
) {
	bool success = true;

	if(input_file != NULL) {
		for(unsigned long offset = 0; offset < start_offset; ++offset) {
			if(fgetc(input_file) == EOF) {
				break;
			}
		}
		for(unsigned long size = 0; success && size < size_limit; ++size) {
			const int byte = fgetc(input_file);
			if(byte == EOF) {
				break;
			}
			success = append_byte(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				byte
			);
		}

		fclose(input_file);
	} else {
		snprintf(
			error_message,
			ERROR_MESSAGE_CAPACITY,
			"unable to %s: %s",
			action,
			description
		);
		success = false;
	}

	return success;
}

static bool parse_bytes_primary(
	const char **const current_char,
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[]
) {
	if(consume_token(current_char, "{")) {
		return parse_bytes_concatenation(
			current_char,
			result_buffer,
			result_capacity,
			result_size,
			error_message
		) && consume_token(
			current_char,
			"}"
		);
	}

	if(**current_char == '\"') {
		++*current_char;

		while(!consume_token(current_char, "\"")) {
			uint8_t parsed_char;
			if(!parse_string_char(
				current_char,
				'\"',
				&parsed_char,
				error_message
			) || !append_byte(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				parsed_char
			)) {
				return false;
			}
		}

		return true;
	}

	if(consume_token(current_char, "`")) {
		while(!consume_token(current_char, "`")) {
			uint8_t value = 0;
			for(size_t digit_count = 0; digit_count < 2; ++digit_count) {
				if('0' <= **current_char && **current_char <= '9') {
					value = value * 0x10 + (**current_char - '0');
				} else if('A' <= **current_char && **current_char <= 'F') {
					value = value * 0x10 + (**current_char - 'A' + 0xA);
				} else if('a' <= **current_char && **current_char <= 'f') {
					value = value * 0x10 + (**current_char - 'a' + 0xA);
				} else {
					generate_unexpected_char_message(
						current_char,
						error_message,
						"hexadecimal digit"
					);
					return false;
				}
				++*current_char;
				skip_whitespace(current_char);
			}
			if(!append_byte(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				value
			)) {
				return false;
			}
		}
		return true;
	}

	if(isalpha(**current_char)) {
		char name[NAME_CAPACITY];
		size_t name_size = 0;
		while(isalnum(**current_char)) {
			const size_t new_size = name_size + 1;
			if(new_size >= NAME_CAPACITY) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"name too long"
				);
				return false;
			}
			name[name_size++] = tolower(*(*current_char)++);
		}
		name[name_size] = '\0';
		skip_whitespace(current_char);

		if(strcmp(name, "be16") == 0) {
			unsigned long argument;
			return parse_arguments(
				current_char,
				error_message,
				"I",
				&argument
			) && append_be_integer(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				16,
				argument
			);
		}
		if(strcmp(name, "le16") == 0) {
			unsigned long argument;
			return parse_arguments(
				current_char,
				error_message,
				"I",
				&argument
			) && append_le_integer(result_buffer,
				result_capacity,
				result_size,
				error_message,
				16,
				argument
			);
		}
		if(strcmp(name, "be32") == 0) {
			unsigned long argument;
			return parse_arguments(
				current_char,
				error_message,
				"I",
				&argument
			) && append_be_integer(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				32,
				argument
			);
		}
		if(strcmp(name, "le32") == 0) {
			unsigned long argument;
			return parse_arguments(
				current_char,
				error_message,
				"I",
				&argument
			) && append_le_integer(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				32,
				argument
			);
		}
		if(strcmp(name, "be64") == 0) {
			unsigned long argument;
			return parse_arguments(
				current_char,
				error_message,
				"I",
				&argument
			) && append_be_integer(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				64,
				argument
			);
		}
		if(strcmp(name, "le64") == 0) {
			unsigned long argument;
			return parse_arguments(
				current_char,
				error_message,
				"I",
				&argument
			) && append_le_integer(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				64,
				argument
			);
		}
		if(strcmp(name, "be") == 0) {
			unsigned long size, argument;
			return parse_arguments(
				current_char,
				error_message,
				"II",
				&size,
				&argument
			) && append_be_integer(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				size,
				argument
			);
		}
		if(strcmp(name, "le") == 0) {
			unsigned long size, argument;
			return parse_arguments(
				current_char,
				error_message,
				"II",
				&size,
				&argument
			) && append_le_integer(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				size,
				argument
			);
		}
		if(strcmp(name, "read") == 0) {
			char file_path[FILE_PATH_CAPACITY];
			unsigned long size_limit = ~0ul;
			unsigned long start_offset = 0;
			return parse_arguments(
				current_char,
				error_message,
				"Sii",
				file_path,
				FILE_PATH_CAPACITY,
				&size_limit,
				&start_offset
			) && load_data_from_file(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				"open file",
				file_path,
				fopen(file_path, "rb"),
				start_offset,
				size_limit
			);
		}
		if(strcmp(name, "exec") == 0) {
			char command[COMMAND_CAPACITY];
			unsigned long size_limit = ~0ul;
			unsigned long start_offset = 0;
			return parse_arguments(
				current_char,
				error_message,
				"Sii",
				command,
				COMMAND_CAPACITY,
				&size_limit,
				&start_offset
			) && load_data_from_file(
				result_buffer,
				result_capacity,
				result_size,
				error_message,
				"execute command",
				command,
				popen(command, "r"),
				start_offset,
				size_limit
			);
		}

		return parse_integer_range(
			name,
			current_char,
			result_buffer,
			result_capacity,
			result_size,
			error_message
		);
	}

	return parse_integer_range(
		NULL,
		current_char,
		result_buffer,
		result_capacity,
		result_size,
		error_message
	);
}

static bool parse_bytes_repetition(
	const char **const current_char,
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[]
) {
	/* Remember the current position; this is where the repeated string starts. */
	const size_t repetition_start = *result_size;

	/* Parse the string that is repeated. */
	if(!parse_bytes_primary(
		current_char,
		result_buffer,
		result_capacity,
		result_size,
		error_message
	)) {
		return false;
	}

	while(consume_token(current_char, "#")) {
		unsigned long repeat_count;
		if(!parse_integer_or_expression(
			NULL,
			current_char,
			&repeat_count,
			error_message
		)) {
			return false;
		}

		/* Make sure there is enough room in the buffer to store the repeated string. */
		const size_t repeated_size = *result_size - repetition_start;
		const size_t new_size = repetition_start + repeated_size * repeat_count;
		const size_t required_capacity = (new_size + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
		if(required_capacity > *result_capacity) {
			*result_capacity = required_capacity;
			uint8_t *const new_result_buffer = realloc(
				*result_buffer,
				*result_capacity
			);
			if(new_result_buffer == NULL) {
				snprintf(
					error_message,
					ERROR_MESSAGE_CAPACITY,
					"failed to allocate memory"
				);
				return false;
			}
			*result_buffer = new_result_buffer;
		}

		/* Make copies of the repeated string. */
		for(unsigned long iteration = 1; iteration < repeat_count; ++iteration) {
			memcpy(
				*result_buffer + repetition_start + iteration * repeated_size,
				*result_buffer + repetition_start,
				repeated_size
			);
		}

		*result_size = new_size;
	}

	return true;
}

static bool parse_bytes_concatenation(
	const char **const current_char,
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[]
) {
	while(consume_token(current_char, ",")
		|| consume_token(current_char, ";")
		|| (**current_char != '\0' && **current_char != '}' && **current_char != ')')
	) {
		if(!parse_bytes_repetition(
			current_char,
			result_buffer,
			result_capacity,
			result_size,
			error_message
		)) {
			return false;
		}
	}

	return true;
}

bool parse_byte_string(
	const char *input_string,
	uint8_t **const result_buffer,
	size_t *const result_capacity,
	size_t *const result_size,
	char error_message[]
) {
	skip_whitespace(&input_string);
	if(!parse_bytes_concatenation(
		&input_string,
		result_buffer,
		result_capacity,
		result_size,
		error_message
	)) {
		return false;
	}
	if(*input_string != '\0') {
		generate_unexpected_char_message(
			&input_string,
			error_message,
			"end-of-file"
		);
		return false;
	}
	return true;
}
