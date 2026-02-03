#include "input_parser.h"

#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <poll.h>
#include <unistd.h>

#include <readline/history.h>
#include <readline/readline.h>

#include <sys/types.h>
#include <sys/wait.h>

enum {
	PIPE_READ_END,
	PIPE_WRITE_END,
	NUM_PIPE_ENDS
};

static void print_bytes(
	const int text_colour,
	const uint8_t data_buffer[],
	const size_t data_size,
	const size_t line_length
) {
	rl_save_prompt();
	rl_clear_visible_line();
	printf("\x1B[3%dm", text_colour);

	for(size_t line_start = 0; line_start < data_size; line_start += line_length) {
		const size_t line_end = line_start + line_length;
		for(size_t byte_offset = line_start; byte_offset < line_end && byte_offset < data_size; ++byte_offset) {
			printf("%02X ", (unsigned)data_buffer[byte_offset]);
		}
		for(size_t count = data_size; count < line_end; ++count) {
			printf("   ");
		}
		printf("       ");
		for(size_t byte_offset = line_start; byte_offset < line_end && byte_offset < data_size; ++byte_offset) {
			if(isprint(data_buffer[byte_offset])) {
				printf("%c", (char)data_buffer[byte_offset]);
			} else {
				printf(".");
			}
		}
		printf("\n");
	}

	printf("\x1B[0m");
	rl_on_new_line();
	rl_restore_prompt();
	rl_redisplay();
}

static pid_t spawn_child_process(
	char *const command[],
	int *const stdin_fileno,
	int *const stdout_fileno,
	int *const stderr_fileno
) {
	int stdin_pipe[NUM_PIPE_ENDS];
	if(pipe(stdin_pipe) == 0) {
		int stdout_pipe[NUM_PIPE_ENDS];
		if(pipe(stdout_pipe) == 0) {
			int stderr_pipe[NUM_PIPE_ENDS];
			if(pipe(stderr_pipe) == 0) {
				const pid_t child_process = fork();
				if(child_process == 0) {
					dup2(stdin_pipe[PIPE_READ_END], STDIN_FILENO);
					close(stdin_pipe[PIPE_READ_END]);
					close(stdin_pipe[PIPE_WRITE_END]);

					dup2(stdout_pipe[PIPE_WRITE_END], STDOUT_FILENO);
					close(stdout_pipe[PIPE_READ_END]);
					close(stdout_pipe[PIPE_WRITE_END]);

					dup2(stderr_pipe[PIPE_WRITE_END], STDERR_FILENO);
					close(stderr_pipe[PIPE_READ_END]);
					close(stderr_pipe[PIPE_WRITE_END]);

					execvp(command[0], command);
					exit(1);
				} else if(child_process > 0) {
					close(stdin_pipe[PIPE_READ_END]);
					*stdin_fileno = stdin_pipe[PIPE_WRITE_END];

					close(stdout_pipe[PIPE_WRITE_END]);
					*stdout_fileno = stdout_pipe[PIPE_READ_END];

					close(stderr_pipe[PIPE_WRITE_END]);
					*stderr_fileno = stderr_pipe[PIPE_READ_END];

					return child_process;
				}

				close(stderr_pipe[PIPE_READ_END]);
				close(stderr_pipe[PIPE_WRITE_END]);
			}

			close(stdout_pipe[PIPE_READ_END]);
			close(stdout_pipe[PIPE_WRITE_END]);
		}

		close(stdin_pipe[PIPE_READ_END]);
		close(stdin_pipe[PIPE_WRITE_END]);
	}

	return -1;
}

static uint8_t *input_buffer = NULL;
static size_t input_capacity = 0;
static size_t input_size = 0;
static bool eof_received = false;

static void handle_readline_input(
	char *const command
) {
	if(command == NULL) {
		eof_received = true;
		rl_callback_handler_remove();
	} else {
		size_t new_input_size = input_size;
		char error_message[ERROR_MESSAGE_CAPACITY];
		if(parse_byte_string(
			command,
			&input_buffer,
			&input_capacity,
			&new_input_size,
			error_message
		)) {
			input_size = new_input_size;
		} else {
			printf("Error: %s\n", error_message);
		}

		add_history(command);
		free(command);
	}
}

int main(
	const int num_arguments,
	char *const arguments[]
) {
	int exit_status = 0;

	size_t line_length = 16;
	int output_colour = 5;
	int input_colour = 6;

	if(num_arguments > 1) {
		enum {
			READLINE_POLLFD_INDEX,
			STDIN_POLLFD_INDEX,
			STDOUT_POLLFD_INDEX,
			STDERR_POLLFD_INDEX,
			POLLFD_COUNT
		};

		struct pollfd pollfds[POLLFD_COUNT];

		struct pollfd *const readline_pollfd = &pollfds[READLINE_POLLFD_INDEX];
		readline_pollfd->fd = STDIN_FILENO;
		readline_pollfd->events = POLLIN;

		struct pollfd *const stdin_pollfd = &pollfds[STDIN_POLLFD_INDEX];

		struct pollfd *const stdout_pollfd = &pollfds[STDOUT_POLLFD_INDEX];
		stdout_pollfd->events = POLLIN;

		struct pollfd *const stderr_pollfd = &pollfds[STDERR_POLLFD_INDEX];
		stderr_pollfd->events = POLLIN;

		const pid_t child_process = spawn_child_process(
			arguments + 1,
			&stdin_pollfd->fd,
			&stdout_pollfd->fd,
			&stderr_pollfd->fd
		);
		if(child_process > 0) {
			char stderr_buffer[1024U];
			size_t stderr_size = 0U;

			rl_callback_handler_install(">>> ", handle_readline_input);

			while(!eof_received && stdin_pollfd->fd >= 0 && stdout_pollfd->fd >= 0 && stderr_pollfd->fd >= 0) {
				stdin_pollfd->events = input_size > 0 ? POLLOUT : 0;

				const int poll_result = poll(pollfds, POLLFD_COUNT, -1);
				if(poll_result < 0) {
					if(errno != EINTR) {
						fprintf(stderr, "Error: failed to poll\n");
						exit_status = 1;
						break;
					}
				} else if(poll_result > 0) {
					if((readline_pollfd->revents & POLLIN) != 0) {
						rl_callback_read_char();
					} else if((readline_pollfd->revents & POLLHUP) != 0) {
						break;
					}

					if((stdin_pollfd->revents & POLLOUT) != 0) {
						const ssize_t bytes_written = write(
							stdin_pollfd->fd,
							input_buffer,
							input_size
						);
						if(bytes_written > 0) {
							print_bytes(
								output_colour,
								input_buffer,
								bytes_written,
								line_length
							);
							input_size -= bytes_written;
							memmove(
								input_buffer,
								input_buffer + bytes_written,
								input_size
							);
						} else if(bytes_written == 0 || errno != EINTR) {
							close(stdin_pollfd->fd);
							stdin_pollfd->fd = -1;
						}
					} else if((stdin_pollfd->revents & POLLHUP) != 0) {
						close(stdin_pollfd->fd);
						stdin_pollfd->fd = -1;
					}

					if((stdout_pollfd->revents & POLLIN) != 0) {
						uint8_t buffer[1024];
						const ssize_t bytes_read = read(
							stdout_pollfd->fd,
							buffer,
							sizeof buffer
						);
						if(bytes_read > 0) {
							print_bytes(
								input_colour,
								buffer,
								bytes_read,
								line_length
							);
						} else if(bytes_read == 0 || errno != EINTR) {
							close(stdout_pollfd->fd);
							stdout_pollfd->fd = -1;
						}
					} else if((stdout_pollfd->revents & POLLHUP) != 0) {
						close(stdout_pollfd->fd);
						stdout_pollfd->fd = -1;
					}

					if((stderr_pollfd->revents & POLLIN) != 0) {
						const ssize_t characters_read = read(
							stderr_pollfd->fd,
							&stderr_buffer[stderr_size],
							sizeof stderr_buffer - stderr_size
						);
						if(characters_read > 0) {
							rl_save_prompt();
							rl_clear_visible_line();

							size_t line_start_offset = 0U;

							const size_t new_stderr_size = stderr_size + characters_read;
							while(stderr_size < new_stderr_size) {
								if(stderr_buffer[stderr_size] == '\n') {
									printf(
										"\x1B[31m%.*s\x1B[0m\n",
										(int)(stderr_size - line_start_offset),
										&stderr_buffer[line_start_offset]
									);
									++stderr_size;
									line_start_offset = stderr_size;
								} else {
									++stderr_size;
								}
							}

							stderr_size -= line_start_offset;
							memmove(
								stderr_buffer,
								&stderr_buffer[line_start_offset],
								stderr_size
							);

							if(stderr_size >= sizeof stderr_buffer) {
								stderr_size = snprintf(
									stderr_buffer,
									sizeof stderr_buffer,
									"<...>"
								);
								stderr_size = 0U;
							}

							rl_on_new_line();
							rl_restore_prompt();
							rl_redisplay();
						} else if(characters_read == 0 || errno != EINTR) {
							close(stderr_pollfd->fd);
							stderr_pollfd->fd = -1;
						}
					} else if((stderr_pollfd->revents & POLLHUP) != 0) {
						close(stderr_pollfd->fd);
						stderr_pollfd->fd = -1;
					}
				}
			}

			rl_callback_handler_remove();
			free(input_buffer);

			if(stdin_pollfd->fd >= 0) {
				close(stdin_pollfd->fd);
			}
			if(stdout_pollfd->fd >= 0) {
				close(stdout_pollfd->fd);
			}
			if(stderr_pollfd->fd >= 0) {
				close(stderr_pollfd->fd);
			}

			kill(child_process, SIGTERM);
			waitpid(child_process, NULL, 0);
		} else {
			fprintf(stderr, "Error: failed to spawn child process\n");
			exit_status = 1;
		}
	} else {
		fprintf(stderr, "Error: no command specified\n");
		exit_status = 1;
	}

	return exit_status;
}
