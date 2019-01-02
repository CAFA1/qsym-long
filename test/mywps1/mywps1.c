#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char*argv[])
{
	char x[20];
	//char magic[20];
	read(0,x,10);
	//read(0,magic,10);
	if(x[0]=='d' && x[1]=='i' && x[2]=='r' && x[3]=='\n' && x[4]=='\x0')
	{
	    printf("%s\n","dir");
	}
	else
	{
		printf("%s\n","nodir");
	}
	
	return 0;
}