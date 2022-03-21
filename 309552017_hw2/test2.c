#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int infile = open("Makefile", O_RDONLY);
    printf("open for reading OK\n");
    close(infile);

    return 0;
}
