/**
 * Operating Sytems 2013 - Assignment 1
 *
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(char *dir)
{
	/* TODO execute cd */
	chdir(dir);

	return 0;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit()
{
	/* TODO execute exit/quit */	
	exit(0);

}

/**
* Redirect filedes in fisierul cu numele filename
*/
static int redirect(int filedes, const char *filename, int flag){
	int fd;
	int rc;
	if(flag !=0)
		fd = open(filename, O_CREAT | O_RDWR | O_APPEND , 0644);
	else{
		if(filedes == 0)
			fd = open(filename, O_CREAT | O_RDWR, 0644);
		else
			fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, 0644);
	}
		
	if(fd < 0)
		return -1;

	rc = dup2(fd,filedes);
	if(rc < 0)
		return -2;

	return 0;
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL) {
			return NULL;
		}

		if (s->expand == true) {
			char *aux = substring;
			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL) {
				substring = calloc(1, sizeof(char));
				if (substring == NULL) {
					free(aux);
					return NULL;
				}
			}

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (substring != NULL)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false) {
			free(substring);
		}

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;
	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO sanity checks */
	char **argv, *aux;
	argv = get_argv(s,&level);
	// comanda nula
	if(s==NULL)
		return 0;

	/* TODO if builtin command, execute the command */
	if(strcmp(s->verb->string,"exit") == 0 || strcmp(s->verb->string,"quit") == 0 )
		shell_exit();
	else if(strcmp(s->verb->string,"cd") == 0){
		argv = get_argv(s,&level);
		if(s->out != NULL){
			aux = get_word(s->out);
			open(aux, O_CREAT | O_RDWR | O_TRUNC, 0644);
		}
		shell_cd(argv[1]);
	}
		
	/* TODO if variable assignment, execute the assignment and return
         * the exit status */
	else if(s->verb->next_part!=NULL){
		argv = get_argv(s,&level);
		putenv(argv[0]);
		return 0;
	}

	/* TODO if external command:
         *   1. fork new process
	 *     2c. perform redirections in child
         *     3c. load executable in child
         *   2. wait for child
         *   3. return exit status
	 */
    else{
    	pid_t pid;
		int status;
		argv = get_argv(s,&level);
	 	
		pid = fork();
		switch (pid) {
		case -1:
			/* error forking */
			return -1;
	 
		case 0:
			/* child process */
			if(s->in != NULL){
				aux = get_word(s->in);
				redirect(STDIN_FILENO,aux,s->io_flags);
			}
			if(s->out != NULL && s->err != NULL){
				aux = get_word(s->err);
				redirect(STDERR_FILENO,aux,0);
				aux = get_word(s->out);
				redirect(STDOUT_FILENO,aux,1);
				
			}
			else{
				if(s->out != NULL){
					aux = get_word(s->out);
					printf("%s\n", aux);
					redirect(STDOUT_FILENO,aux,s->io_flags);
				}
				if(s->err != NULL){
					aux = get_word(s->err);
					redirect(STDERR_FILENO,aux,s->io_flags);
				}
			}
				execvp(s->verb->string, argv);

	 		fprintf(stderr,"Execution failed for '%s'\n",s->verb->string);
			exit(-1);
	 
		default:
			/* parent process */
			break;
		}
		/* only parent process gets here */
		waitpid(pid, &status, 0);
	 	
	 	if(status == 0)
			return 0;
		else
			return -1;

    }

	return 0; /* TODO replace with actual exit status */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	pid_t pid;
	int status;

	pid = fork();
	switch (pid) {
		case -1:
			/* error forking */
			return -1;
	 
		case 0:
			/* child process */

	 		parse_command(cmd1, level + 1, father);
			/* only if exec failed */
			exit(-1);
	 
		default:
			/* parent process */
			parse_command(cmd2, level + 1, father);

			break;
		}
		/* only parent process gets here */
		waitpid(pid, &status, 0);

	return true; /* TODO replace with actual exit status */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* TODO redirect the output of cmd1 to the input of cmd2 */
	int myPipe[2],rc;
	rc = pipe(myPipe);
	if(rc < 0)
		return false;
	pid_t pid, pid2;
	int status;

	// fac un nou proces care scrie intr-un pipe (pipe = STDOUT)
	pid = fork();
	switch (pid) {
		case -1:
			/* error forking */
			return -1;
	 
		case 0:
			/* execut comanda care pune output in pipe
			setez capatul de intrare ai pipe-ului ca fiind STDOUT-ul primului proces*/
			close(myPipe[0]);
			rc = dup2(myPipe[1],STDOUT_FILENO);
			if (rc < 0)
			{
				return -1;
			}
			close(myPipe[1]);
	 		parse_command(cmd1, level + 1, father);
			/* only if exec failed */
			exit(-1);
	 
		default:
			// fac procesul care citeste din pipe (pipe=STDIN)
			pid2 = fork();

			switch (pid2) {
				case -1:
					/* error forking */
					return -1;
			 
				case 0:
					/* child process */
				/* execut comanda care primeste input de la pipe-ul creat anterior */
					close(myPipe[1]);
					rc = dup2(myPipe[0],STDIN_FILENO);
					if (rc < 0)
					{
						return -1;
					}
					close(myPipe[0]);

					parse_command(cmd2, level + 1, father);
					/* only if exec failed */
					exit(-1);
			 
				default:
					break;
				}

			break;
		}

		close(myPipe[1]);
		close(myPipe[0]);
		waitpid(pid2, &status, 0);

	return true; /* TODO replace with actual exit status */

}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO sanity checks */
	int i = 0;
	if (c->op == OP_NONE) {
		/* TODO execute a simple command */
		i = parse_simple(c->scmd,level,father);

		return i; /* TODO replace with actual exit code of command */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO execute the commands one after the other */
		//parse_simple(c->scmd,level,father);
		parse_command(c->cmd1, level + 1, c);
		parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/* TODO execute the commands simultaneously */
		do_in_parallel(c->cmd1,c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_NZERO:
		i = 0;
		/* TODO execute the second command only if the first one
                 * returns non zero */
		i += parse_command(c->cmd1, level + 1, c);

		if (i != 0)
		{
			parse_command(c->cmd2, level + 1, c);
			
		}
		break;

	case OP_CONDITIONAL_ZERO:
		i = 0;
		/* TODO execute the second command only if the first one
                 * returns zero */
		i += parse_command(c->cmd1, level + 1, c);
		if (i == 0){

			i += parse_command(c->cmd2, level + 1, c);

		}
		break;

	case OP_PIPE:
		/* TODO redirect the output of the first command to the
		 * input of the second */
		do_on_pipe(c->cmd1,c->cmd2, level+1, c);
		break;

	default:
		assert(false);
	}

	return i; /* TODO replace with actual exit code of command */
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL) {
			break;
		}

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		ret = instr;
		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL) {
			free(ret);
			return instr;
		}
		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}

