#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <udis86.h>
#include <errno.h>

struct user_regs_struct regs;
struct saved_regs {
	long int eip;
	long int esp;
	long int ebp;
} prev_regs;

struct sym_def_func {
	long addr;
	char name[64];
	char type;
	int instruction_arr[128];
	int current_instruction;
	int num_instructions;
	unsigned trap_reset_data;
	struct sym_def_func *prev;
	struct sym_def_func *next;
}*sym_def_func_arr[128];

struct stack_frame_vals {
	long int addr;
	char ebp_offset[32];
	char esp_offset[32];
	long int value;
	int bytes[4];
	struct stack_frame_vals *prev;
	struct stack_frame_vals *next;
	struct sym_def_func *function;
}*frame_vals[128];

pid_t child;
char * progName;
int wait_status;
int break_addr;
int break_addr_end;
int break_num;
unsigned break_data;
int num_def_funcs;
char prompt[6];
struct sym_def_func *current_func;

void sig_handler(int);
int set_breakpoint();
int restore_breakpoint();
int get_instruction_addrs();
void disas();
int get_instruction();
int search_funcs();

int clean_breakpoints(struct sym_def_func *func)
{
	unsigned addr;
	unsigned check_data;
	unsigned break_data;

	while(func->prev != NULL)
	{
		addr = func->addr;
		if(func->trap_reset_data != 0)
		{
			break_data = func->trap_reset_data;
			ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)break_data, 0);
			check_data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
			//regs.eip = addr;
			ptrace(PTRACE_SETREGS, child, 0, &regs);

			printf("Data @ 0x%08x after restore: 0x%08x\n", addr, check_data);
		}
		func = func->prev;
	}
	return(0);

}

int init_breakpoints(struct sym_def_func *func)
{
	unsigned addr;
	unsigned data;
	unsigned trap;
	unsigned check_data;

	while(func->prev != NULL)
	{
		addr = func->addr;
		printf("Function Name %s\n", func->name);
		data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
		func->trap_reset_data = data;
		trap = (data & 0xffffff00) | 0xf4;

		printf("Data @ 0x%08x before trap: 0x%08x\n", addr, data);

		ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)trap, 0);

		check_data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
		printf("Data @ 0x%08x after trap address: 0x%08x\n", addr, check_data);
		func = func->prev;

	}
	return(0);

}

int set_breakpoint(unsigned addr)
{
	unsigned data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
	break_data = data;
	unsigned trap = (data & 0xffffff00) | 0xf4;

	printf("Data @ 0x%08x before trap: 0x%08x\n", addr, data);

	ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)trap, 0);

	unsigned check_data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
	printf("Data @ 0x%08x after trap address: 0x%08x\n", addr, check_data);

	return(0);

}

int restore_breakpoint(unsigned addr)
{
	ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)break_data, 0);
	unsigned check_data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
	regs.eip = addr;
	ptrace(PTRACE_SETREGS, child, 0, &regs);

	printf("Data @ 0x%08x after restore: 0x%08x\n", addr, check_data);

	return(0);
}

void disas_func(char * name)
{
	int i;
	int index = search_funcs(name);

	if((sym_def_func_arr[index]->num_instructions) == 0)
	{
		get_instruction_addrs(index);
	}

	if((sym_def_func_arr[index]->num_instructions) > 0)
	{
		for(i=0; i < sym_def_func_arr[index]->num_instructions; i++)
			disas(sym_def_func_arr[index]->instruction_arr[i], NULL);
	}
}

int get_instruction_addrs(int index)
{
	FILE *pipe;
        int i=0;
	unsigned start_addr = sym_def_func_arr[index]->addr;
	unsigned stop_addr = sym_def_func_arr[index+1]->addr;
	printf("progName: %s\nstart_addr: %08x\nstop_addr: %08x\n", progName, start_addr, stop_addr);
        char command[256];

        snprintf(command, 255, 
	"objdump -M intel -D --prefix-addresses --start-address=0x%08x --stop-address=0x%08x %s | grep 08048", start_addr, stop_addr, progName);

        pipe = popen(command, "r");

        while(1)
        {
		if(feof(pipe))
			break;

		if((fscanf(pipe, "%x%*[^\n]", &sym_def_func_arr[index]->instruction_arr[i])) == EOF)
			break;

		i++;
	}
	sym_def_func_arr[index]->num_instructions = i-1;
	pclose(pipe);
	return(0);
}

int memcpy_from_target(unsigned long src, struct sym_def_func *func, int n)
{
	int i,j;
	n /= sizeof(long);

	printf("\n\t< STACK FRAME >\n\n");
	for(i=0; i < n; i++)
	{
		frame_vals[i] = (struct stack_frame_vals *) malloc(sizeof(struct stack_frame_vals));
		frame_vals[i]->addr = src;
		frame_vals[i]->function = func;
		frame_vals[i]->value = ptrace(PTRACE_PEEKDATA, child, src, NULL);

		for(j=0; j < 4; j++)
			frame_vals[i]->bytes[j] = (frame_vals[i]->value >> (8*j)) & 0xff;

		if(regs.ebp < src)
			snprintf(frame_vals[i]->ebp_offset, 31, "RET ADDR\t\t", regs.ebp-src);

		if(regs.ebp == src)
			snprintf(frame_vals[i]->ebp_offset, 31, "BASE ==>\t\t", regs.ebp-src);

		if(regs.ebp > src)
			snprintf(frame_vals[i]->ebp_offset, 31, "EBP-%d\t\t", regs.ebp-src);

		if(src > regs.esp)
			snprintf(frame_vals[i]->esp_offset, 31, "\tESP+%d", src-regs.esp);
		else
			snprintf(frame_vals[i]->esp_offset, 31, "\t<== TOP", src-regs.esp);

		printf("0x%08x: %s %08x %s\n", 
		frame_vals[i]->addr, 
		frame_vals[i]->ebp_offset, 
		frame_vals[i]->value, 
		frame_vals[i]->esp_offset);

		src=src-4;

		if(errno) {
			perror("ptrace(PTRACE_PEEKTEXT)");
			for(i=0; i != n; i++)
				free(frame_vals[i]);
			return(0);
		}
	}
	for(i=0; i != n; i++)
		free(frame_vals[i]);
	return(1);
}

int read_data(unsigned long addr, unsigned char *mem, int size)
{
	int i;
	unsigned long *out = (unsigned long *)mem;

	for(i=0; i <= size; i=i+4)
	{
		errno = 0;

		unsigned data = ptrace(PTRACE_PEEKTEXT, child, addr+i, NULL);

		if(errno != 0)
			return(-1);

		*out++ = data;
	}
	return(0);
}

void disas(unsigned long addr, unsigned char *buffer)
{

	ud_t ud_obj;
	ud_init(&ud_obj);
	unsigned char local_buff[4];

	if(buffer != NULL)
	{
        	ud_set_input_buffer(&ud_obj, buffer, 32);
        	ud_set_mode(&ud_obj, 32);
        	ud_set_syntax(&ud_obj, UD_SYN_INTEL);

		while(ud_disassemble(&ud_obj))
                	printf("\t%s\n", ud_insn_asm(&ud_obj));

	}else{

		if(read_data(addr, local_buff, 4) == -1)
		{
			printf("Could not read data\n");
			return;
		}

        	ud_set_input_buffer(&ud_obj, local_buff, 32);
        	ud_set_mode(&ud_obj, 32);
        	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
		if(ud_disassemble(&ud_obj) != 0)
        		printf("\t%s\n", ud_insn_asm(&ud_obj));
	}

}

int usr_prompt()
{
	printf("\nPrompt$: ");
	fflush(stdout);
	scanf("%5s",prompt);

	if(strcmp("si",prompt) == 0)
		return(0);
	else
		return(1);
}

int search_funcs(char* name)
{
	int i;

	for(i=0; i < num_def_funcs; i++)
	{
		if(strcmp(sym_def_func_arr[i]->name, name) == 0)
		{
			printf("search_funcs: found %s: 0x%08x\n", name, sym_def_func_arr[i]->addr);
			if(break_addr == 0)
			{
				break_addr = sym_def_func_arr[i]->addr;
				break_addr_end = sym_def_func_arr[i+1]->addr;
				break_num = i;
			}
			//if(sym_def_func_arr[i]->num_instructions == 0)
				//get_instruction_addrs(i);
			return(i);
		}
	}
	return(-1);
}

void calculate_regs()
{
/* Only called by the get_data() function,
 this function prints the last instruction's reg values,
 then prints the current instruction reg values,
 and compares them by subtracting new from old and
 storing the difference in the respective reg_offset vars,
 the if-statements look to see if the regs were initialized
 from 0 */

	long int eip_offset = 0;
	long int esp_offset = 0;
	long long int ebp_offset = 0;

	printf("\nPrev Values:\t");
	printf("eip: 0x%08x\tesp: 0x%08x\tebp: 0x%08x\n", prev_regs.eip, prev_regs.esp, prev_regs.ebp);

	printf("Cur Values:\t");
	printf("eip: 0x%08x\tesp: 0x%08x\tebp: 0x%08x\n", regs.eip, regs.esp, regs.ebp);

	printf("\nDifference:\t\t");
	if(prev_regs.eip == 0 && regs.eip != 0)
	{
		eip_offset = regs.eip;
		printf("eip: 0x%08x\t", eip_offset);
	}else{
		eip_offset = regs.eip - prev_regs.eip;
		printf("eip: %d\t", eip_offset);
	}

	if(prev_regs.esp == 0 && regs.esp != 0)
	{
		esp_offset = regs.esp;
		printf("esp: 0x%08x\t", esp_offset);
	}else{
		esp_offset = regs.esp - prev_regs.esp;
		printf("esp: %d\t", esp_offset);
	}

	if(prev_regs.ebp == 0 && regs.ebp != 0)
	{
		ebp_offset = regs.ebp;
		printf("ebp: 0x%08x\t", ebp_offset);
	}else{
		ebp_offset = regs.ebp - prev_regs.ebp;
		printf("ebp: %d\t", ebp_offset);
	}
	printf("\n\n");
}

void save_regs()
{
/* Store current reg values of child in prev_regs struct
 so the values can be used after the child executes it's
 next instruction,
 currently only called by run_parent() after usr_prompt() is called */

	prev_regs.eip = regs.eip;
        prev_regs.esp = regs.esp;
        prev_regs.ebp = regs.ebp;
}

int get_data(struct sym_def_func *current_frame)
{
/*Only called by run_parent(),
 stores the child's gen reg values in the regs struct,
 stores the opcodes that eip points at in the <data> var,
 moves the opcodes to a global variable <data_buff>,
 so the function disas() can use the buffer to disassemble
 the opcodes, the calculate_regs() function is then called,
 which compares the previous gen reg values to the current
 gen reg values */

	unsigned long data;
	long addr;
	int prev_index;
	long prev_addr;
	int next_index;
	long next_addr;

	ptrace(PTRACE_GETREGS, child, NULL, &regs);
	addr = regs.eip;
	calculate_regs();
	printf("\n======================\n");
	if((prev_index = current_frame->current_instruction-1) >= 0)
        {
               	prev_addr = current_frame->instruction_arr[prev_index];
		printf("\t\t");
                disas(prev_addr, NULL);
        }

	printf("Next Instruction => ");
	disas(addr, NULL);
	if((next_index = current_frame->current_instruction+1) < current_frame->num_instructions+1)
	{
		next_addr = current_frame->instruction_arr[next_index];
		printf("\t\t");
		disas(next_addr, NULL);
	}
	printf("\n======================\n");
	return(0);
}

void sig_handler(int signo)
{

	write(1, "SIG_HANDLER\n", 14);
	if(signo == SIGSEGV)
	{
		//printf("recieved SIGINT\n");
		//get_data();
		write(1, "SIGSEGV\n", 10);
		//restore_breakpoint(break_addr);
	}
	else if(signo == SIGSTOP)
	{
		//printf("recieved SIGSTOP\n");
		write(1, "SIGSTOP\n", 10);
	}
}

int init_break(char * prog_name)
{
/* This function is called by run_parent(),
 it waits for the child to change state,
 enters a while loop that ensures the child's state is STOPPED,
 then uses PTRACE_GETREGS macro to get the child's
 gen reg values and stores them in the regs struct,
 if the instruction ptr value is the address of the
 break point requested by the user, the function returns,
 else the child steps one instruction and the parent waits
 for the child to change state */

	int i=0;
	int j=0;
	int last_sig = 0;
	int diff = break_addr_end - break_addr;

	wait(&wait_status);

	if(WIFSTOPPED(wait_status))
	{
		ptrace(PTRACE_GETREGS, child, NULL, &regs);

		set_breakpoint(break_addr);
		//init_breakpoints(sym_def_func_arr[break_num]);
		printf("returned from set_breakpoint\n");
		ptrace(PTRACE_CONT, child, 0, 0);
		wait(&wait_status);

		if(WIFSTOPPED(wait_status))
		{
			last_sig = WSTOPSIG(wait_status);
			printf("last_sig is: 0x%x\n", last_sig);
			if(last_sig == SIGSEGV)
				printf("Last SIG was a HALT\n");
			printf("found initial break\n");
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			restore_breakpoint(break_addr);
			save_regs();

			current_func = sym_def_func_arr[break_num];
			disas_func(current_func->name);
			current_func->current_instruction = 0;
			set_breakpoint(current_func->prev->addr);
			return(0);
		}

		/*if(regs.eip == break_addr)
		{
			printf("found initial break\n");
			save_regs();

			current_func = sym_def_func_arr[break_num];
			disas_func(current_func->name);
			current_func->current_instruction = 0;
			
			return(0);
		}else{
			ptrace(PT_STEP, child, 0, 0);
			wait(&wait_status);
		}*/
	}
	return(1);
}

void run_parent(char * prog_name)
{
/* Only parent calls this function,
 this function calls init_break, which looks for the
 break point specified by the user in main,
 once init_break returns, the parent waits for the
 child's state to change to STOPPED,
 this should be at the initial break point,
 this enters into a loop that stores gen reg values and,
 prints current instruction
 with get_data(), requests user input with usr_prompt(),
 saves the reg values with save_regs(),
 then tells the child to execute it's next instruction,
 with PT_STEP macro, then waits until the child's state changes*/

	int inst_count = 0;
	int step_main = 0;
	int last_sig = 0;
	unsigned stack_frame;
	unsigned prologue_size = 8;

	signal(SIGSEGV, sig_handler);
	//signal(SIGSTOP, sig_handler);

	if((init_break(prog_name)) != 0)
	{
		printf("ERROR: initial break not found\n");
		return;
	}

	//get_instruction_addrs(prog_name);

	//struct sym_def_func *current_frame = sym_def_func_arr[break_num];

	while(WIFSTOPPED(wait_status))
	{
		last_sig = WSTOPSIG(wait_status);
		if(last_sig == SIGSEGV)
		{
			printf("<<<< NEW FUNCTION >>>>\n");
			if(regs.eip == current_func->prev->addr)
			{
				restore_breakpoint(current_func->prev->addr);
				//current_func = current_func->prev;
			}
		}
		inst_count++;

		struct sym_def_func *current_frame = sym_def_func_arr[break_num];

		get_data(current_frame);
		save_regs();

		stack_frame = (regs.ebp + prologue_size) - regs.esp;
		//printf("stack frame size is: %d\n", stack_frame);

		if(stack_frame >= 0 && regs.ebp != 0)
			memcpy_from_target(regs.ebp+4, current_frame, stack_frame);

		if((usr_prompt()) != 0)
		{
			//clean_breakpoints(current_frame);
			return;
		}

		ptrace(PT_STEP, child, 0, 0);
		wait(&wait_status);
		sym_def_func_arr[break_num]->current_instruction++;

	}

	printf("The child executed %d instructions\n", inst_count);
}

void run_child(const char * prog_name)
{
/* Only the child calls this function,
 child tells parent to trace it,
 then exec's itself with the program arg */

	printf("child started. Running <%s>\n", prog_name);

	ptrace(PT_TRACE_ME, 0, 0, 0);

	execl(prog_name, prog_name, 0, NULL);
}

int get_sym_tbl(char * prog_name)
{
/* get_sym_tbl is called by main,
 it attempts to print and store the child process's
 defined functions using the <nm> command output,
 the functions and associated addresses are stored in
 sym_def_func_arr, which is an array of pointers to structs,
 the functions are stored in order of their address's from
 lowest to highest address */

	FILE *pipe;
	int i = 0;
	char command[64];

	snprintf(command, 63, "nm -n --defined-only %s", prog_name);

	pipe = popen(command, "r");

	while(1)
	{
		if(feof(pipe))
			break;

		sym_def_func_arr[i] = (struct sym_def_func *) malloc(sizeof(struct sym_def_func));
		sym_def_func_arr[i]->num_instructions = 0;

		if(fscanf(pipe, "%x %c %s",
		&sym_def_func_arr[i]->addr, &sym_def_func_arr[i]->type, sym_def_func_arr[i]->name) == EOF)
			break;

		if(i > 0)
		{
			sym_def_func_arr[i]->prev = sym_def_func_arr[i-1];
			sym_def_func_arr[i-1]->next = sym_def_func_arr[i];
		}else{
			sym_def_func_arr[i]->prev = NULL;
		}
		printf("0x%08x %c %s\n", 
		sym_def_func_arr[i]->addr, sym_def_func_arr[i]->type, sym_def_func_arr[i]->name);
		i++;
	}
	num_def_funcs = i+1;
	sym_def_func_arr[i]->next = NULL;

	pclose(pipe);

	return(0);

}

int main(int argc, char **argv)
{
/* main takes a program name as an arg
 passes it to get_sym_tbl to store symbol table info,
 requests the user to specify a function to break at,
 forks this process and runs the program arg as the child */
	char func[64];
	int i;

	if(argc < 2)
		return(-1);

	//signal(SIGINT, sig_handler);

	progName = argv[1];
	get_sym_tbl(argv[1]);
	printf("Break at function:\n");
	scanf("%63s",func);
	if((search_funcs(func)) == -1)
	{
		printf("Function %s not found\n", func);
		return(0);
	}

	printf("progName: %s\n", progName);
	prev_regs.eip = 0;
	prev_regs.esp = 0;
	prev_regs.eip = 0;

	child = fork();

	if(child == 0)
		run_child(argv[1]);
	else
		run_parent(argv[1]);

	//for(i=0; i < num_def_funcs+1; i++)
		//free(sym_def_func_arr[i]);

	return(0);
}
