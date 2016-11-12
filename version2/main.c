#include "global_defs.h"

int main(int argc, char **argv)
{
	char func[64];
	int i;

	if(argc != 2)
		return(1);

	prog_name = argv[1];
	get_sym_tbl(prog_name);

	printf("Break at function: \n");
	scanf("%63s", func);
	if((search_funcs(func)) == -1)
	{
		printf("Function %s not found\n", func);
		return(-1);
	}

	return(0);
}
