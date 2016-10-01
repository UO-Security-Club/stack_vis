struct defined_function {
	unsigned long addr;
	char name[32];
	char type;
	struct defined_function *next;
	struct defined_function *prev;
	unsigned trap_reset_data;
	struct Stack *stack_frame;
	struct instruction *current_instr;
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
	FILE *pipe;
	int i = 0;
	char command[64];

	snprintf(command, 63, "nm -n --defined-only %s", prog_name);

	pipe = popen(command, "r");

	while(1)
	{
		if(feof(pipe))
			break;

		def_funcs[i] = (struct defined_function *) malloc(sizeof(struct defined_function));
		def_funcs[i]->current_instr = 0;
		def_funcs[i]->num_instrs = 0;

		if(fscanf(pipe, "%x %c %s", &def_funcs[i]->addr, &def_funcs[i]->type, &def_funcs[i]->name)==EOF)
			break;

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
	char command[256];
	FILE *pipe;
	int i = 0;
	unsigned stop_addr;
	unsigned start_addr = func->addr;

	if(func->next != NULL){
		stop_addr = func->next->addr;
	}else{
		printf("Error: Can't retrieve instruction addresses since next function is NULL\n");
		return(-1);
	}

	snprintf(command, 255,
	"objdump -M intel -D --prefix-addresses --start-address=0x%08x --stop-address=0x%08x %s | grep 08048", 
	start_addr, stop_addr, progName);

	pipe = popen(command, "r");

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




