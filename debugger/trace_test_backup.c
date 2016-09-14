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
	struct Stack *stack_frame;
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
	int ebp_off;
	int esp_off;
	int isRet;
	int isBase;
	int isTop;
	long int value;
	int bytes[4];
	struct stack_frame_vals *prev;
	struct stack_frame_vals *next;
	struct sym_def_func *function;
}*frame_vals[256];

typedef struct Stack
{
	int capacity;
	int size;
	struct stack_frame_vals *elements[256];
	struct sym_def_func *call_elements[256];
}Stack;

pid_t child;
char * progName;
int wait_status;
int break_addr;
int break_addr_end;
int break_num;
unsigned break_data;
unsigned long previous_instruction;
int num_def_funcs;
char prompt[6];
struct sym_def_func *current_func;
struct Stack * call_stack;

void sig_handler(int);
int set_breakpoint();
int restore_breakpoint();
int get_instruction_addrs();
int disas();
int get_instruction();
int print_stack_frame();
struct stack_frame_vals * stack_element();
struct sym_def_func * search_funcs();

int print_stack(Stack *S)
{
	int i=0;
	int j=0;
	struct sym_def_func *func;
	//Stack *func_stack;
	struct stack_frame_vals *frame_data;

	for(i=0; i < S->size; i++)
	{
		func = S->call_elements[i];
		Stack *func_stack = S->call_elements[i]->stack_frame;
		printf("\n%s stack frame Has size %d\n\n", func->name, func_stack->size);
		print_stack_frame(func_stack, func);
	}
	return(0);
}

Stack * createStack(int maxElements)
{
	int i;
	Stack *S;
	S = (Stack *)malloc(sizeof(Stack));

	S->size = 0;
	S->capacity = maxElements;

	return(S);
}

int pop(Stack *S)
{
	if(S->size == 0)
	{
		//printf("Stack is Empty\n");
		return(0);
	}else{
		S->size--;
		free(S->elements[S->size]);
	}
	return(1);
}


int pop_func(Stack *S)
{
	if(S->size == 0)
        {
                //printf("Call Stack is Empty\n");
                return(0);
        }else{
                S->size--;
		//printf("Freeing Func: %s\n", S->call_elements[S->size]->name);
                free(S->call_elements[S->size]);
        }
        return(1);
}

int print_stack_frame(Stack *S, struct sym_def_func *func)
{
	int i=0;
	struct stack_frame_vals *frame_data;
	if(S->size == 0)
	{
		//printf("Stack is Empty\n");
		return(0);
	}else{
		if(func == current_func)
		{
			for(i=0; i < S->size; i++)
			{
				frame_data = S->elements[i];
				if(frame_data->isRet == 1)
				{
					printf("0x%08x: RET=>\t%08x\tESP%d\n",
					frame_data->addr,
					frame_data->value,
					frame_data->esp_off);
				}else{	
					printf("0x%08x: EBP%d\t%08x\tESP%d\n",
					frame_data->addr, 
					frame_data->ebp_off,
					frame_data->value,
					frame_data->esp_off);
				}
			}
		}else{

			for(i=0; i < S->size; i++)
			{
				frame_data = S->elements[i];
				printf("0x%08x: %08x\n", frame_data->addr, frame_data->value);
			}
		}
	}
	return(1);
}

long int pop_ret(Stack *S)
{
	//printf("IN POP_RET\n\n");
	struct stack_frame_vals * ret_struct = S->elements[S->size-1];
	//printf("Got Ret Addr: 0x%08x\n", ret_struct->value);
	if(ret_struct->isTop == 1)
	{
		ret_struct->isRet = 1;
		pop(S);
		long int ret_addr = ret_struct->value;
		return(ret_addr);
	}else{
		printf("pop_ret: NOT RET ADDR\n");
		return(-1);
	}
}

struct stack_frame_vals * stack_element(Stack *S, int offset)
{
	if(S->size == 0)
	{
		//printf("Element: Stack is Empty\n");
		return(NULL);
	}
	if(offset <= S->size)
	{
		return(S->elements[S->size]);
	}else{
		//printf("Offset is greater than number of elements\n");
		return(NULL);
	}
}

void push_frame_vals(Stack *S, struct stack_frame_vals * frame_vals)
{
	if(S->size == S->capacity)
		printf("Stack is Full\n");
	else{
		//S->elements[S->size] = (struct stack_frame_vals *)malloc(sizeof(struct stack_frame_vals));
		S->elements[S->size] = frame_vals;
		S->size++;
		//printf("SIZE IS NOW: %d\n", S->size);
	}
	return;
}

int push_func(Stack *S, struct sym_def_func * func)
{
	if(S->size == S->capacity)
	{
		//printf("push_func: Stack is Full\n");
		return(-1);
	}else{
		//S->call_elements[S->size] = (struct sym_def_func *)malloc(sizeof(struct sym_def_func));
		S->call_elements[S->size] = func;
		//printf("push_func: %s has frame size %d\n", func->name, func->stack_frame->size);
		S->size++;
	}
	return(0);
}

int clean_stack(Stack *S)
{
	int i;
	while(1)
	{
		if((pop(S)) == 0)
			break;
	}

	free(S);
	return(0);
}

int clean_call_stack(Stack *S)
{
	int i;
	while(1)
	{
		if((pop_func(S)) == 0)
			break;
	}

	free(S);
	return(0);
}

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

			//printf("Data @ 0x%08x after restore: 0x%08x\n", addr, check_data);
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
		//printf("Function Name %s\n", func->name);
		data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
		func->trap_reset_data = data;
		trap = (data & 0xffffff00) | 0xf4;

		//printf("Data @ 0x%08x before trap: 0x%08x\n", addr, data);

		ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)trap, 0);

		check_data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
		//printf("Data @ 0x%08x after trap address: 0x%08x\n", addr, check_data);
		func = func->prev;

	}
	return(0);

}

int set_breakpoint(unsigned addr)
{
	unsigned data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
	break_data = data;
	unsigned trap = (data & 0xffffff00) | 0xf4;

	//printf("Data @ 0x%08x before trap: 0x%08x\n", addr, data);

	ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)trap, 0);

	unsigned check_data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
	//printf("Data @ 0x%08x after trap address: 0x%08x\n", addr, check_data);

	return(0);

}

int restore_breakpoint(unsigned addr)
{
	ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)break_data, 0);
	unsigned check_data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
	regs.eip = addr;
	ptrace(PTRACE_SETREGS, child, 0, &regs);

	//printf("Data @ 0x%08x after restore: 0x%08x\n", addr, check_data);

	return(0);
}

void disas_func(struct sym_def_func * func)
{
	int i;
	//struct sym_def_func * func = search_funcs(name);

	if((func->num_instructions) == 0)
	{
		get_instruction_addrs(func);
	}

	if((func->num_instructions) > 0)
	{
		for(i=0; i < func->num_instructions; i++)
			disas(func->instruction_arr[i], NULL);
	}
}

int get_instruction_addrs(struct sym_def_func * func)
{
	FILE *pipe;
        int i=0;
	unsigned stop_addr;
	unsigned start_addr = func->addr;
	if(func->next != NULL)
		stop_addr = func->next->addr;
	else
	{
		printf("Error in get_instruction_addrs: next function is NULL\n");
		return(0);
	}
	//printf("progName: %s\nstart_addr: %08x\nstop_addr: %08x\n", progName, start_addr, stop_addr);
        char command[256];

        snprintf(command, 255, 
	"objdump -M intel -D --prefix-addresses --start-address=0x%08x --stop-address=0x%08x %s | grep 08048", start_addr, stop_addr, progName);

        pipe = popen(command, "r");

        while(1)
        {
		if(feof(pipe))
			break;

		if((fscanf(pipe, "%x%*[^\n]", &func->instruction_arr[i])) == EOF)
			break;

		i++;
	}
	func->num_instructions = i-1;
	pclose(pipe);
	return(0);
}

int memcpy_prologue(unsigned long src, struct sym_def_func *func, int n)
{
	int i=0;
	int j;
	unsigned long ret = src;

	struct stack_frame_vals *frame_data;

	n /= sizeof(long);

	printf("\n\t< STACK FRAME >\n\n");
	for(i=0; i < n; i++)
	{
		if(i >= func->stack_frame->size)
		{
			frame_data = (struct stack_frame_vals *) malloc(sizeof(struct stack_frame_vals));
			push_frame_vals(func->stack_frame, frame_data);
		}else{
			frame_data = func->stack_frame->elements[i];
		}

		frame_data->addr = src;
		frame_data->function = func;

		frame_data->value = ptrace(PTRACE_PEEKDATA, child, src, NULL);
		if(errno)
		{
			perror("ptrace: PEEKDATA");
			return(-1);
		}

		for(j=0; j < 4; j++)
			frame_data->bytes[j] = (frame_data->value >> (8*j)) & 0xff;

		if(ret == src)
		{
			frame_data->isRet = 1;
		}else{
			frame_data->isBase = 1;
			frame_data->isRet = 0;
		}
		frame_data->esp_off = src-regs.esp;
		src=src-4;
	}
	return(0);
}

int memcpy_from_target(unsigned long src, struct sym_def_func *func, int n)
{
	int i = 0;
	int j;

	struct stack_frame_vals *frame_data;

	n /= sizeof(long);

	printf("\n\t< STACK FRAME >\n\n");
	for(i=0; i < n; i++)
	{
		if(i >= func->stack_frame->size)
		{
			frame_data = (struct stack_frame_vals *) malloc(sizeof(struct stack_frame_vals));
			push_frame_vals(func->stack_frame, frame_data);
		}
		else{
			frame_data = func->stack_frame->elements[i];
		}
		frame_data->addr = src;
		frame_data->function = func;


		frame_data->value = ptrace(PTRACE_PEEKDATA, child, src, NULL);

		for(j=0; j < 4; j++)
			frame_data->bytes[j] = (frame_data->value >> (8*j)) & 0xff;

		if(regs.ebp < src)
		{
			snprintf(frame_data->ebp_offset, 31, "RET ADDR\t\t", regs.ebp-src);
			frame_data->ebp_off = src-regs.ebp;
			frame_data->isRet = 1;

		}
		if(regs.ebp == src)
		{
			snprintf(frame_data->ebp_offset, 31, "BASE ==>\t\t", regs.ebp-src);
			frame_data->ebp_off = 0;
			frame_data->isBase = 1;
		}
		if(regs.ebp > src)
		{
			snprintf(frame_data->ebp_offset, 31, "EBP-%d\t\t", regs.ebp-src);
			frame_data->ebp_off = regs.ebp - src;
		}
		if(src > regs.esp)
		{
			snprintf(frame_data->esp_offset, 31, "\tESP+%d", src-regs.esp);
			frame_data->esp_off = src-regs.esp;
		}
		else{
			snprintf(frame_data->esp_offset, 31, "\t<== TOP", src-regs.esp);
			frame_data->esp_off = 0;
			frame_data->isTop = 1;
		}

		/*printf("0x%08x: %s %08x %s\n", 
		frame_data->addr, 
		frame_data->ebp_offset, 
		frame_data->value, 
		frame_data->esp_offset);*/

		src=src-4;

		if(errno) {
			perror("ptrace(PTRACE_PEEKTEXT)");
			return(0);
		}

	}

	//for(i=0; i != n; i++)
		//free(frame_vals[i]);
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

int disas(unsigned long addr, unsigned char *buffer)
{

	int i;
	ud_t ud_obj;
	ud_init(&ud_obj);
	unsigned char local_buff[4];
	char instruction_str[64];

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
			return(-1);
		}

        	ud_set_input_buffer(&ud_obj, local_buff, 32);
        	ud_set_mode(&ud_obj, 32);
        	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
		if(ud_disassemble(&ud_obj) != 0)
		{
        		snprintf(instruction_str, 63, "%s", ud_insn_asm(&ud_obj));
			printf("\t%s\n", instruction_str);
		}
		if(strcmp(instruction_str, "leave") == 0)
		{
			//printf("=========== FOUND LEAVE INSTRUCTION =========\n");
			return(2);
		}
		if(strcmp(instruction_str, "ret") == 0)
		{
			//printf("========= FOUND RET INSTRUCTION ============\n");
			return(1);
		}
	}
	return(0);

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

struct sym_def_func * search_funcs(char* name)
{
	int i;

	for(i=0; i < num_def_funcs; i++)
	{
		if(strcmp(sym_def_func_arr[i]->name, name) == 0)
		{
			//printf("search_funcs: found %s: 0x%08x\n", name, sym_def_func_arr[i]->addr);
			if(break_addr == 0)
			{
				break_addr = sym_def_func_arr[i]->addr;
				break_addr_end = sym_def_func_arr[i+1]->addr;
				break_num = i;
			}
			return(sym_def_func_arr[i]);
		}
	}
	return(NULL);
}

struct sym_def_func * search_addresses(unsigned addr)
{
	int i;

	//printf("IN SEARCH_ADDRS\n");
	struct sym_def_func * func = sym_def_func_arr[0];
	while(func != NULL)
	{
		if(func->addr == addr)
		{
			//printf("FOUND FUNCTION w/ ADDR: 0x%08x\n", func->addr);
			return(func);
		}else{
			func = func->next;
		}
	}
	return(NULL);
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

	int i;
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
	/*if((prev_index = current_frame->current_instruction-1) >= 0)
        {
               	prev_addr = current_frame->instruction_arr[prev_index];
		printf("\t\t");
                i = disas(prev_addr, NULL);
        }*/
	if((previous_instruction) != 0)
	{
		printf("\t\t");
		disas(previous_instruction, NULL);
	}
	if((prev_regs.eip) != regs.eip)
	{
		printf("\t\t");
		i = disas(prev_regs.eip, NULL);
		previous_instruction = prev_regs.eip;
	}
	printf("Next Instruction => ");
	disas(addr, NULL);
	printf("\n======================\n");
	return(i);
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
		//stack_data = createStack(255);
		current_func->stack_frame = createStack(255);
		ptrace(PTRACE_GETREGS, child, NULL, &regs);

		set_breakpoint(current_func->addr);
		//printf("returned from set_breakpoint\n");

		ptrace(PTRACE_CONT, child, 0, 0);
		wait(&wait_status);

		if(WIFSTOPPED(wait_status))
		{
			last_sig = WSTOPSIG(wait_status);
			//printf("last_sig is: 0x%x\n", last_sig);
			if(last_sig == SIGSEGV)
				//printf("Last SIG was a HALT\n");

			printf("found initial break\n");

			call_stack = createStack(255);
			push_func(call_stack, current_func);

			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			restore_breakpoint(current_func->addr);
			save_regs();

			disas_func(current_func);
			current_func->current_instruction = 0;
			init_breakpoints(current_func->prev);

			return(0);
		}else{
			printf("Error in init_breakpoint: last_sig = %d\n", last_sig);
			return(last_sig);
		}

	}
	return(1);
}

int function_call(struct sym_def_func * new_func)
{
	int prologue=4;
	struct sym_def_func * prev_func = current_func;

	//current_func = current_func->prev;
	current_func = new_func;
	restore_breakpoint(current_func->addr);
	current_func->stack_frame = createStack(255);
	push_func(call_stack, current_func);
	disas_func(current_func);

	get_data(current_func);
	save_regs();

	memcpy_prologue(regs.esp, current_func, prologue);
	//printf("prev function: %s\n", prev_func->name);
	long int ret_address = pop_ret(prev_func->stack_frame);
	//printf("\nGot Ret Addr: 0x%08x\n\n", ret_address);
	print_stack(call_stack);

	if((usr_prompt()) != 0)
	{
		clean_stack(current_func->stack_frame);
		clean_call_stack(call_stack);
		return(1);
	}
	ptrace(PT_STEP, child, 0, 0);
	wait(&wait_status);
	current_func->current_instruction++;

	if(WIFSTOPPED(wait_status))
	{
		get_data(current_func);
		save_regs();

		memcpy_prologue(regs.esp+4, current_func, 8);
		print_stack(call_stack);
		ptrace(PT_STEP, child, 0, 0);
		wait(&wait_status);
		current_func->current_instruction++;
		if(WIFSTOPPED(wait_status))
			return(0);
	}
	return(-1);
}

int function_epilogue()
{
	//clean_stack(current_func->stack_frame);
	while(current_func->stack_frame->size > 0)
		pop(current_func->stack_frame);
	memcpy_from_target(regs.esp, current_func, 4);

	save_regs();
	print_stack(call_stack);

	if((usr_prompt()) != 0)
	{
		clean_stack(current_func->stack_frame);
		clean_call_stack(call_stack);
		return(1);
	}
	ptrace(PT_STEP, child, 0, 0);
	wait(&wait_status);
	current_func->current_instruction++;

	if(WIFSTOPPED(wait_status))
	{
		if((get_data(current_func)) == 1)
		{
			pop_func(call_stack);
			if((call_stack->size) < 1)
			{
				clean_stack(current_func->stack_frame);
				clean_call_stack(call_stack);
				return(1);
			}
			//current_func = current_func->next;
			clean_stack(current_func->stack_frame);
			current_func = call_stack->call_elements[call_stack->size-1];
			save_regs();
			return(0);
		}
	}
	return(-1);
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
	int epilogue;
	int init_error;
	int func_call_error;
	unsigned stack_frame;
	int prologue = 4;
	int prologue_offset = 0;
	unsigned prologue_size = 8;
	struct sym_def_func * func_place_holder;

	previous_instruction = 0;
	if((init_error = init_break(prog_name)) != 0)
	{
		printf("ERROR: initial break not found\n");
		printf("Returned Value: %d\n", init_error);
		return;
	}

	while(WIFSTOPPED(wait_status))
	{
		last_sig = WSTOPSIG(wait_status);
		if(last_sig == SIGSEGV)
		{
			//if(regs.eip == current_func->prev->addr)
			func_place_holder = search_addresses(regs.eip);
			if(func_place_holder != NULL && func_place_holder != current_func)
			{
				printf("<<<< NEW FUNCTION >>>>\nname: %s\n", func_place_holder->name);
				func_call_error = function_call(func_place_holder);
				if(func_call_error == 1)
					return;
				if(func_call_error == -1)
				{
					printf("ERROR: In function_call()\n");
					exit(1);
				}
			}
		}

		inst_count++;
		epilogue = get_data(current_func);
		save_regs();
		if(epilogue == 2)
			if((function_epilogue()) == 1)
				return;

		stack_frame = (regs.ebp + prologue_size) - regs.esp;

		//printf("stack frame size is: %d\n", stack_frame);
		if(epilogue != 2)
		{
			if(stack_frame >= 0 && regs.ebp != 0)
				memcpy_from_target(regs.ebp+4, current_func, stack_frame);
			else{
				memcpy_prologue(regs.esp+prologue_offset, current_func, prologue);
				prologue_offset = 4;
				prologue = 8;
			}
		}
		print_stack(call_stack);

		if((usr_prompt()) != 0)
		{
			//clean_breakpoints(current_frame);
			clean_stack(current_func->stack_frame);
			clean_call_stack(call_stack);
			return;
		}

		ptrace(PT_STEP, child, 0, 0);
		wait(&wait_status);
		current_func->current_instruction++;

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
		sym_def_func_arr[i]->current_instruction = 0;

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

	progName = argv[1];

	get_sym_tbl(argv[1]);
	printf("Break at function:\n");
	scanf("%63s",func);
	if((current_func = search_funcs(func)) == NULL)
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

	//printf("MAIN\n");
	
	/*i=0;
	while(sym_def_func_arr[i]->next != NULL)
	{
		free(sym_def_func_arr[i]);
		i++;
	}*/

	return(0);
}
