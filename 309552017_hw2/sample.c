#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

int main(){
	fclose(stderr);
    char buf[32];
    creat("aaaa", 0600);
    chmod("aaaa", 0666);
    chown("aaaa", 65534, 65534);
    rename("aaaa", "bbbb");
    int fd = open("bbbb", 1101, 0666);
    write(fd, "cccc.", 5);
    close(fd);
    fd = open("bbbb", 0, 0);
    read(fd, buf, 100);
    close(fd);
    FILE* fp1 = tmpfile();
    fwrite("cccc.", 1, 5, fp1);
    fclose(fp1);
    FILE* fp2 = fopen("bbbb", "r");
    fread(buf, 1, 100, fp2);
    fclose(fp2);
    remove("bbbb");
    write(2, "sample done.\r\n", 14);
    return 0;
}

