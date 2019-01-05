#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char*argv[])
{
	char x[20];
	//char magic[20];
	read(0,x,10);
	//read(0,magic,10);
	if(x[5]=='d' && x[6]=='i' && x[7]=='r' && x[8]=='\n' && x[9]=='\x0')
	{
	    printf("%s\n","dir");
	}
	else
	{
		printf("%s\n","nodir");
	}
	
	return 0;
}