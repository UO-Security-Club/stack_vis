struct defined_function {
	unsigned long addr;			//starting address of function
	char name[32];
	char type;
	struct defined_function *next;		//ptr to next defined function
	struct defined_function *prev;
	unsigned trap_reset_data;		//data for restoring breakpoint
	struct Stack *stack_frame;		//ptr to the function's stack frame struct
	struct instruction *current_instr;	//ptr to struct of current instruction
	int num_instrs;
	int instr_arr[128];

}*def_funcs[256];

struct instruction {
	unsigned long addr;
	struct instr_list *next;
	struct instr_list *prev;
	char disasm[32];

} instr_list;

int get_sym_tbl(char * prog_name)
{
	/*This function calls the nm linux command on the program to trace,
	which outputs all defined functions in the executable from smallest
	to largest address. A defined_function struct is then initialized for
	each outputed function.*/

	FILE *pipe;
	int i = 0;
	char command[64];	//buffer to store nm command output

	snprintf(command, 63, "nm -n --defined-only %s", prog_name);

	pipe = popen(command, "r");

	/*Iterate through each defined function*/
	while(1)
	{
		if(feof(pipe))
			break;

		def_funcs[i] = (struct defined_function *) malloc(sizeof(struct defined_function));	//allocate and init the struct
		def_funcs[i]->current_instr = 0;
		def_funcs[i]->num_instrs = 0;

		//set starting address, type, and name of function 
		if(fscanf(pipe, "%x %c %s", &def_funcs[i]->addr, &def_funcs[i]->type, &def_funcs[i]->name)==EOF)
			break;
		//set linked-list pointers for current function struct
		if(i > 0)
		{
			def_funcs[i]->prev = def_funcs[i-1];
			def_funcs[i-1]->next = def_funcs[i];
		}else{
			def_funcs[i]->prev = NULL;
		}

		printf("0x%08x %c %s\n", def_funcs[i]->addr, def_funcs[i]->type, def_funcs[i]->name);
		i++;
	}
	def_funcs[i]->next = NULL;
	pclose(pipe);

	return(0);
}

int get_instruction_addrs(struct defined_function * func)
{
	/*This function in-line's execution of the objdump command,
	to print out all of the instructions addresses of a defined function.
	Since we dont have a built-in disassembler we have no way to preemptively 
	calculate the size of each instruction, which is why the function exists.*/

	char command[256];	//stores output of the objdump command. Probably needs to be larger or dynamically alloc'd
	FILE *pipe;
	int i = 0;
	unsigned stop_addr;	
	unsigned start_addr = func->addr; //set starting address to start address of function

	if(func->next != NULL){
		stop_addr = func->next->addr; //set stopping address to starting address of next function
	}else{
		printf("Error: Can't retrieve instruction addresses since next function is NULL\n");
		return(-1);
	}

	snprintf(command, 255,
	"objdump -M intel -D --prefix-addresses --start-address=0x%08x --stop-address=0x%08x %s | grep 08048", 
	start_addr, stop_addr, progName);

	pipe = popen(command, "r");	//read objdump output into command buffer

	/*parse buffer and save instruction addresses to double-linked list of structs*/

	while(1)
	{
		if(feof(pipe))
			break;

		if((fscanf(pipe, "%x%*[^\n]", &func->instr_arr[i]))==EOF)
			break;
		i++;
	}
	func->num_instrs = i;
	pclose(pipe);

	return(0);
}




