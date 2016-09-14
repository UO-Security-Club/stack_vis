#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>

int main()
{
	//kill(getppid(), SIGINT);
	write(1, "hello\n", 7);
	return(0);
}
