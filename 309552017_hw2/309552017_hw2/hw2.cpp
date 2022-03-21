#include <iostream>
#include <string>

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

struct Argument{
    bool isOutfile = false;

    std::string outfile;
    std::string sopath = "./logger.so";
};


void usage(std::string progname);
int get_argument(int argc, char *argv[], Argument &argument);


/*
extern "C"
{
    void load_so(std::string the_sopath);

    typedef int (*OPEN)(const char *name, int flags, mode_t mode);

    static OPEN open = NULL;
}
//*/


int main(int argc, char *argv[])
{
    //for(int i = 0; i < argc; i++)
        //printf("|%d\t%s\n", i, argv[i]);

    // get argument
    Argument argument;
    int index = get_argument(argc, argv, argument);

    /*
    printf("cmd\t%s\n", argument.cmd.c_str());
    printf("p\t%s\n", argument.sopath.c_str());
    if(argument.isOutfile) printf("o\t%s\n", argument.outfile.c_str());
    //*/

    // set env
    setenv("LD_PRELOAD", argument.sopath.c_str(), 1);
    // setenv("OUTFILE_FIRST", "T", 1);
    if(argument.isOutfile)
    {    
        FILE* fp = fopen((char *)argument.outfile.c_str(), "w");
        if(fp)
            remove((char *)argument.outfile.c_str());
        
        setenv("isOutfile", "T", 1);
        static char buf[1024];
        char *the_realpath = realpath((char *)argument.outfile.c_str(), buf);

        if(the_realpath)
            setenv("OUTFILE", the_realpath, 1);
        else
        {
            char cwd[1024];
            getcwd(cwd, sizeof(cwd));
            std::string c = cwd;
            argument.outfile = c + "/" + argument.outfile;
            setenv("OUTFILE", (char *)argument.outfile.c_str(), 1);
        }
    }
    else
        setenv("isOutfile", "F", 1);

    // printf("|%s|\n", getenv("OUTFILE"));
    std::string p = "LD_PRELOAD=" + argument.sopath;
    environ[0] = (char *)p.c_str();

    char **arg = &argv[index];
    execvp(arg[0], arg);

    return 0;
}


void usage(std::string progname)
{
  printf("Usage: %s [-o file] [-p sopath] [--] cmd [cmd args ...]\n", progname.c_str());
  printf("    -p: set the path to logger.so, default = ./logger.so\n");
  printf("    -o: print output to file, print to \"stderr\" if no file specified\n");
  printf("    --: separate the arguments for logger and for the command\n");
}

int get_argument(int argc, char *argv[], Argument &argument)
{
    int opt;
    const char *optstring = "p:o:";

    while((opt = getopt(argc, argv, optstring)) != -1)
    {
        switch(opt)
        {
            case 'p':
                if(optarg[0] != '-')
                {
                    argument.sopath = optarg;
                    break;
                }
            case 'o':
                if(optarg[0] != '-')
                {
                    argument.isOutfile = true;
                    argument.outfile = optarg;
                    break;
                }
            case '?':
            default:
                usage(argv[0]);
                exit(1);
        }
    }

    // check if it included cmd
    if(optind >= argc)
    {
        printf("no command given.\n");
        exit(1);
    }
    else
        return optind;

    // concat cmd
    /*
    argument.cmd = "LD_PRELOAD=" + argument.sopath;
    for(int index = optind; index < argc; index++)
    {
        argument.cmd += " ";
        argument.cmd += argv[index];
        //printf("||%s\n", argument.cmd.c_str());
    }
    //*/
}


/*
extern "C"
{
    void load_so(std::string the_sopath)
    {
        void *handle = NULL;

        if(!handle)
        {
            handle = dlopen(the_sopath.c_str(), RTLD_LAZY);
            open = (OPEN)dlsym(handle, "open");
        }
    }
}
//*/
