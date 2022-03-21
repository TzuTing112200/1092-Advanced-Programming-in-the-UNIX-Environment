#include <stdio.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
    //open("Makefile", O_RDONLY);
    if(64&(O_WRONLY | O_CREAT | O_TRUNC))
    printf("||t||\n");else printf("||f||\n");
    open("Makefile", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    printf("open for reading OK\n");

    return 0;
}
