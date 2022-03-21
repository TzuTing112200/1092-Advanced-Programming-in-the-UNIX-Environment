#include <iostream>
#include <getopt.h>
#include <string>
#include <vector>
#include <set>
#include <regex>

#include <sstream>
#include <fstream>

#include <dirent.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>


struct Argument{
    bool c_filter = false;
    bool t_filter = false;
    bool f_filter = false;

    std::string c_arg;
    std::string t_arg;
    std::string f_arg;
};

struct Data{
    std::string command;
    std::string pid;
    std::string user;
    std::string fd;
    std::string type;
    std::string node;
    std::string name;

    Data(std::string the_command, std::string the_pid, std::string the_user)
    {
        command = the_command;
        pid = the_pid;
        user = the_user;
    };
};


void usage(std::string progname);
void get_argument(int argc, char *argv[], Argument &argument);
bool is_match_regex(Argument argument, char item, std::string command);
void print_row(std::string the_command, std::string the_pid, std::string the_user,
               std::string the_fd, std::string the_type, std::string the_node, std::string the_name);
void print_data(Data data);

DIR *open_dir(std::string path, bool cont);
std::fstream open_file(std::string path, std::string mode);

void get_processes(std::vector<std::string> &processes);
void get_datas_by_process(Argument argument, std::string pid);
std::string get_link_name_by_path(std::string path);
std::string get_file_type(std::string path);
void find_data_by_readlink(Argument argument, Data data, std::string path, std::string fd, std::string type);
void find_data_by_maps(Argument argument, Data data, std::string path);
void find_fd_data(Argument argument, Data data, std::string path);
std::string get_fd_string(std::string path, std::string file);


int main(int argc, char *argv[])
{
    /*
    printf("euid:%ld\n", (long) geteuid());
    //*/

    // get argument
    Argument argument;
    get_argument(argc, argv, argument);
    /*
    if(argument.c_filter) printf("c\t%s\n", argument.c_arg.c_str());
    if(argument.t_filter) printf("t\t%s\n", argument.t_arg.c_str());
    if(argument.f_filter) printf("f\t%s\n", argument.f_arg.c_str());
    //*/

    // print column names
    print_row("COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");

    // get all processes' id
    std::vector<std::string> processes;
    get_processes(processes);

    // get columns by process and print result
    for(auto pid : processes)
        get_datas_by_process(argument, pid);

    return 0;
}


void usage(std::string progname)
{
  printf("Usage: %s [options]\n", progname.c_str());
  printf("Program Options:\n");
  printf("  -c  --command <REGEX>    Regular expression (REGEX) filter for filtering command line.\n");
  printf("  -t  --type               TYPE filter. (Valid TYPE includes REG, CHR, DIR, FIFO, SOCK, and unknown)\n");
  printf("  -f  --filename <REGEX>   Regular expression (REGEX) filter for filtering filenames.\n");
  printf("  -?  --help               This message\n");
}

void get_argument(int argc, char *argv[], Argument &argument)
{
    int opt;
    const char *optstring = "c:t:f:?";
    static struct option options[] = {
        {"command", 1, NULL, 'c'},
        {"type", 1, NULL, 't'},
        {"filename", 1, NULL, 'f'},
        {"help", 0, NULL, '?'}
    };

    while((opt = getopt_long(argc, argv, optstring, options, NULL)) != -1)
    {
        switch(opt)
        {
            case 'c':
                argument.c_filter = true;
                argument.c_arg = optarg;
                break;
            case 't':
                argument.t_filter = true;
                argument.t_arg = optarg;

                if(argument.t_arg.compare("REG") != 0)
                if(argument.t_arg.compare("CHR") != 0)
                if(argument.t_arg.compare("DIR") != 0)
                if(argument.t_arg.compare("FIFO") != 0)
                if(argument.t_arg.compare("SOCK") != 0)
                if(argument.t_arg.compare("unknown") != 0)
                {
                    printf("Invalid TYPE option.\n");
                    exit(1);
                }

                break;
            case 'f':
                argument.f_filter = true;
                argument.f_arg = optarg;
                break;
            case '?':
            default:
                usage(argv[0]);
                exit(1);
        }
    }
}

bool is_match_regex(Argument argument, char item, std::string arg_regex)
{
    if(item == 'c')
    {
        if(!argument.c_filter)
            return true;

        std::regex reg(argument.c_arg);
        if(std::regex_search(arg_regex, reg)) return true;
        else return false;
    }
    if(item == 't')
    {
        if(!argument.t_filter)
            return true;

        std::regex reg(argument.t_arg);
        if(std::regex_search(arg_regex, reg)) return true;
        else return false;
    }
    if(item == 'f')
    {
        if(!argument.f_filter)
            return true;

        arg_regex = arg_regex.substr(0, arg_regex.find(" "));

        std::regex reg(argument.f_arg);
        if(std::regex_search(arg_regex, reg)) return true;
        else return false;
    }
    if(item == 'd')
    {
        std::regex reg("deleted");
        if(std::regex_search(arg_regex, reg)) return true;
        else return false;
    }
    if(item == 'p')
    {
        std::regex reg(" Permission denied");
        if(std::regex_search(arg_regex, reg)) return true;
        else return false;
    }
    return true;
}

void print_row(std::string the_command, std::string the_pid, std::string the_user,
               std::string the_fd, std::string the_type, std::string the_node, std::string the_name)
{
    printf("%-40s %-7s %-30s %-5s %-9s %-9s %s\n",
           the_command.c_str(), the_pid.c_str(), the_user.c_str(),
           the_fd.c_str(), the_type.c_str(), the_node.c_str(), the_name.c_str());
}

void print_data(Data data)
{
    print_row(data.command, data.pid, data.user,
               data.fd, data.type, data.node, data.name);
}


DIR *open_dir(std::string path, bool cont = false)
{
    DIR *dir;
    if((dir = opendir(path.c_str())) == nullptr)
    {
        if(!cont)
        {
            printf("[open_dir]Can not open \"%s\".\n", path.c_str());
            exit(1);
        }
    }

    return dir;
}

std::fstream open_file(std::string path)
{
    std::fstream file(path, std::ios::in);
    return file;
}


void get_processes(std::vector<std::string> &processes)
{
    DIR *dir;
    struct dirent *diread;
    std::vector<std::string> filelist;

    dir = open_dir("/proc");
    while((diread = readdir(dir)) != nullptr)
        filelist.push_back(diread->d_name);
    closedir(dir);

    long ret;
    char *ptr;
    for(auto file : filelist)
    {
        ret = strtol(file.c_str(), &ptr, 10);
        if(*ptr == '\0')
            processes.push_back(file);
    }
}

void get_datas_by_process(Argument argument, std::string pid)
{
    struct stat st;
    struct passwd *pw;

    std::string path = "/proc/" + pid + "/";
    std::fstream infile;
    std::vector<Data> datas;

    // get command
    std::string command;
    infile = open_file(path + "comm");
    if(!infile)
        return;
    getline(infile, command);
    infile.close();

    // check if command is mached
    if(!is_match_regex(argument, 'c', command))
        return;

    // get user
    int uid;
    std::string user;
    stat(path.c_str(), &st);
    uid = st.st_uid;
    pw = getpwuid(uid);
    user = pw->pw_name;

    // data template
    Data data = Data(command, pid, user);

    // find cwd
    find_data_by_readlink(argument, data, path + "cwd", "cwd", "DIR");

    // find root
    find_data_by_readlink(argument, data, path + "root", "root", "DIR");

    // find exe
    find_data_by_readlink(argument, data, path + "exe", "exe", "REG");

    // find mem
    find_data_by_maps(argument, data, path);

    // find fd files
    find_fd_data(argument, data, path);

}

std::string get_link_name_by_path(std::string path)
{
    char buff[1024];

    ssize_t len = ::readlink(path.c_str(), buff, 1023);
    if (len != -1)
    {
      buff[len] = '\0';
      return std::string(buff);
    }
    return path + " (readlink: Permission denied)";
}

std::string get_file_type(std::string path)
{
    struct stat st;
    stat(path.c_str(), &st);

    switch (st.st_mode & S_IFMT)
    {
        case S_IFDIR:
            return "DIR";
        case S_IFREG:
            return "REG";
        case S_IFCHR:
            return "CHR";
        case S_IFIFO:
            return "FIFO";
        case S_IFSOCK:
            return "SOCK";
    }

    return "unknown";
}

void find_data_by_readlink(Argument argument, Data data, std::string path, std::string fd, std::string type)
{
    if(fd == "")
        return;

    long int ino;
    struct stat st;
    stat(path.c_str(), &st);
    ino = st.st_ino;

    data.fd = fd;
    data.type = type;
    data.name = get_link_name_by_path(path);

    if(is_match_regex(argument, 'd', data.name))
        data.type = "unknown";

    if(data.type == "")
        data.type = get_file_type(path);

    if(!is_match_regex(argument, 'p', data.name))
        data.node = std::to_string(ino);
    else
        data.type = "unknown";

    if(!is_match_regex(argument, 't', data.type))
        return;

    if(!is_match_regex(argument, 'f', data.name))
        return;

    print_data(data);
}

void find_data_by_maps(Argument argument, Data data, std::string path)
{
    std::set<std::string> nodeSet;
    std::string line;
    std::ifstream infile(path + "maps");

    while(getline(infile, line))
    {
        data.fd = "mem";

        std::string temp;
        std::stringstream ss(line);

        while(ss >> temp >> temp >> temp >> temp)
        {
            ss >> data.node;
            if(data.node == "0")
                break;
            if(nodeSet.count(data.node))
                break;
            else
                nodeSet.insert(data.node);

            data.name = ss.str().substr(ss.str().find("/"));
            if(!is_match_regex(argument, 'f', data.name))
                break;

            data.type = get_file_type(data.name);
            if(!is_match_regex(argument, 't', data.type))
                break;

            if(is_match_regex(argument, 'd', data.name))
            {
                data.fd = "del";
                data.type = "unknown";
            }

            print_data(data);
        }
    }
}

void find_fd_data(Argument argument, Data data, std::string path)
{
    DIR *dir;
    struct dirent *diread;
    std::vector<std::string> filelist;

    dir = open_dir(path + "fd", true);
    if(dir == nullptr)
    {
        data.fd = "NOFD";
        data.name = path + "fd (opendir: Permission denied)";

        if(is_match_regex(argument, 'f', data.name))
            if(is_match_regex(argument, 't', data.name))
                print_data(data);

        closedir(dir);
        return;
    }

    while((diread = readdir(dir)) != nullptr)
            filelist.push_back(diread->d_name);

    long ret;
    char *ptr;
    for(auto file : filelist)
    {
        ret = strtol(file.c_str(), &ptr, 10);
        if(*ptr == '\0')
            find_data_by_readlink(argument, data, path + "fd/" + file, get_fd_string(path + "fdinfo/" + file, file), "");
    }

    closedir(dir);
}

std::string get_fd_string(std::string path, std::string file)
{
    int accmode, val;
    std::string temp, mode;
    std::fstream infile;

    infile = open_file(path);
    if(!infile)
        return file;

    infile >> temp >> temp >> temp;
    infile >> mode;

    infile.close();

    val = std::stoi(mode, 0, 16);
    accmode = val & O_ACCMODE;

    if(accmode == O_RDONLY)
        return file + "r";
    if(accmode == O_WRONLY)
        return file + "w";
    if(accmode == O_RDWR)
        return file + "u";

    return file;
}
