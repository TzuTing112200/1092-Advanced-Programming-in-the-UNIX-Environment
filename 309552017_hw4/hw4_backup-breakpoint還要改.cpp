#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>
#include <algorithm>

#include <stdio.h>
#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <capstone/capstone.h>
#include "ptools.h"


#define    PEEKSIZE    8


// state
bool LOADED = false;
bool RUNNING = false;


class instruction1
{
public:
    unsigned char bytes[16];
    int size;
    std::string opr, opnd;
};


struct Argument
{
    bool is_script_path = false;
    bool is_program_path = false;

    std::string script_path;
    std::string program_path;
};

struct SDB
{
    // program
    std::string program_path;
    std::vector<char *> program_args;
    unsigned long long entry_point;
    unsigned long long text_segment_begin;
    unsigned long long text_segment_end;

    // disasm
    csh cshandle;
    std::map<long long, instruction1> instructions;
    
    std::map<range_t, map_entry_t> m;
    std::map<range_t, map_entry_t>::iterator mi;
    
    // child
    pid_t child;
    int status;
    
    // break
    std::vector<unsigned long long> break_addrs;
    std::vector<unsigned long long> break_code;
    int re_break_index;
    
    // next disasm rip
    unsigned long long next_disasm_rip;
    
    // next dump rip
    unsigned long long next_dump_rip;
};


struct Elf64_Ehdr
{
    unsigned char   e_ident[16];
    uint16_t        e_type;
    uint16_t        e_machine;
    uint32_t        e_version;
    uint64_t        e_entry;
    uint64_t        e_phoff;
    uint64_t        e_shoff;
    uint32_t        e_flags;
    uint16_t        e_ehsize;
    uint16_t        e_phentsize;
    uint16_t        e_phnum;
    uint16_t        e_shentsize;
    uint16_t        e_shnum;
    uint16_t        e_shstrndx;
};

struct Elf64_Shdr
{
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    uint64_t   sh_addr;
    uint64_t   sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
};


void usage(std::string progname);
void get_argument(int argc, char *argv[], Argument &argument);
void clear_sdb(SDB &sdb, bool load);


void trim(std::string &s);
void to_lowercase(std::string &s);
unsigned long long get_reg_by_string(struct user_regs_struct regs, std::string reg);
void set_reg_by_string(struct user_regs_struct &regs, std::string reg, unsigned long long val);
int string_to_int(std::string s);
int hex_char_to_int(char c);
unsigned long long hex_string_to_unsigned_long_long(std::string address);
unsigned long long dec_string_to_unsigned_long_long(std::string address);


void get_script_from_path(SDB &sdb, std::string path);
void get_next_script(SDB &sdb);
void implement_script(SDB &sdb, std::string script);


void implement_break(SDB &sdb, unsigned long long instruction_address);
void implement_cont(SDB &sdb);
void implement_delete(SDB &sdb, int break_point_id);
void implement_disasm(SDB &sdb, unsigned long long addr);
void implement_dump(SDB &sdb, unsigned long long addr, int length);
void implement_exit(SDB &sdb);
void implement_get(SDB &sdb, std::string reg);
void implement_getregs(SDB &sdb);
void implement_help(SDB &sdb);
void implement_list(SDB &sdb);
void implement_load(SDB &sdb, std::string path);
// void implement_run(SDB &sdb);
void implement_vmmap(SDB &sdb);
void implement_set(SDB &sdb, std::string reg, unsigned long long val);
bool implement_si(SDB &sdb);
void implement_start(SDB &sdb);

int print_instruction(SDB &sdb, long long addr, instruction1 *in, bool first);
int disassemble(SDB &sdb, unsigned long long rip, bool first);


int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    // get argument
    Argument argument;
    get_argument(argc, argv, argument);
    
    /*
    if(argument.is_script_path) fprintf(stderr, "s\t%s\n", argument.script_path.c_str());
    if(argument.is_program_path) fprintf(stderr, "p\t%s\n", argument.program_path.c_str());
    //*/
    
    SDB sdb;
    
    // if program path is given by arg
    if(argument.is_program_path)
    {
        std::string s = "load ";
        implement_script(sdb, s + argument.program_path);
    }
    
    // if script is given by arg
    if(argument.is_script_path)
    {
        get_script_from_path(sdb, argument.script_path);
    }
    
    while(true)
    {
        // get and deal with next script
        get_next_script(sdb);
    }
    

    return 0;
}


void usage(std::string progname)
{
  fprintf(stderr, "usage: %s [-s script] [program]\n", progname.c_str());
  fprintf(stderr, "Program Options:\n");
  fprintf(stderr, "  -s <script>   Read user command from either user inputs (by default) or from a predefined script.\n");
  fprintf(stderr, "  -?            This message\n");
}

void get_argument(int argc, char *argv[], Argument &argument)
{
    int opt;
    const char *optstring = "s:?";

    while((opt = getopt(argc, argv, optstring)) != -1)
    {
        switch(opt)
        {
            case 's':
                argument.is_script_path = true;
                argument.script_path = optarg;
                break;
            case '?':
            default:
                usage(argv[0]);
                exit(1);
        }
    }

    // check if it included program path
    if(optind < argc)
    {
        argument.is_program_path = true;
        argument.program_path = argv[optind];
        for(int i = optind + 1; i < argc; i++)
        {
            argument.program_path += " ";
            argument.program_path += argv[i];
        }
    }
}
void clear_sdb(SDB &sdb, bool load)
{
    if(load)
    {
        // program
        sdb.program_path = "";
        sdb.program_args.clear();
        sdb.entry_point = 0;
        sdb.text_segment_begin = 0;
        sdb.text_segment_end = 0;

        // disasm
        sdb.cshandle = 0;
        sdb.instructions.clear();
        
        sdb.m.clear();
        sdb.mi = sdb.m.end();
    }
    
    // child
    sdb.child = -1;
    sdb.status = 0;
    
    // break
    sdb.break_addrs.clear();
    sdb.break_code.clear();
    sdb.re_break_index = -1;
    
    // next disasm rip
    sdb.next_disasm_rip = 0;
    
    // next dump rip
    sdb.next_dump_rip = 0;
}


void trim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

void to_lowercase(std::string &s)
{
    for(char &c : s)
        if(c >= 'A' && c <= 'Z')
            c += 32;
}

unsigned long long get_reg_by_string(struct user_regs_struct regs, std::string reg)
{
    if(reg == "rax") return regs.rax;
    else if(reg == "rbx") return regs.rbx;
    else if(reg == "rcx") return regs.rcx;
    else if(reg == "rdx") return regs.rdx;
    else if(reg == "r8") return regs.r8;
    else if(reg == "r9") return regs.r9;
    else if(reg == "r10") return regs.r10;
    else if(reg == "r11") return regs.r11;
    else if(reg == "r12") return regs.r12;
    else if(reg == "r13") return regs.r13;
    else if(reg == "r14") return regs.r14;
    else if(reg == "r15") return regs.r15;
    else if(reg == "rdi") return regs.rdi;
    else if(reg == "rsi") return regs.rsi;
    else if(reg == "rbp") return regs.rbp;
    else if(reg == "rsp") return regs.rsp;
    else if(reg == "rip") return regs.rip;
    else if(reg == "flags") return regs.eflags;
    
    return -1;
}    

void set_reg_by_string(struct user_regs_struct &regs, std::string reg, unsigned long long val)
{    
    if(reg == "rax") regs.rax = val;
    else if(reg == "rbx") regs.rbx = val;
    else if(reg == "rcx") regs.rcx = val;
    else if(reg == "rdx") regs.rdx = val;
    else if(reg == "r8") regs.r8 = val;
    else if(reg == "r9") regs.r9 = val;
    else if(reg == "r10") regs.r10 = val;
    else if(reg == "r11") regs.r11 = val;
    else if(reg == "r12") regs.r12 = val;
    else if(reg == "r13") regs.r13 = val;
    else if(reg == "r14") regs.r14 = val;
    else if(reg == "r15") regs.r15 = val;
    else if(reg == "rdi") regs.rdi = val;
    else if(reg == "rsi") regs.rsi = val;
    else if(reg == "rbp") regs.rbp = val;
    else if(reg == "rsp") regs.rsp = val;
    else if(reg == "rip") regs.rip = val;
    else if(reg == "flags") regs.eflags = val;
}

int string_to_int(std::string s)
{
    int result = 0;
    
    for(char c : s)
    {
        int temp = c - '0';
        if(temp > 9 || temp < 0)
            return -1;
        
        result *= 10;
        result += temp;
    }
    
    return result;
}

int hex_char_to_int(char c)
{
    switch(c)
    {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'a': return 10;
        case 'b': return 11;
        case 'c': return 12;
        case 'd': return 13;
        case 'e': return 14;
        case 'f': return 15;
        default: return -1;
    }
}

unsigned long long hex_string_to_unsigned_long_long(std::string address)
{
    unsigned long long result = 0;
    
    for(char c : address)
    {
        int temp = hex_char_to_int(c);
        if(temp == -1)
            return -1;
        
        result *= 16;
        result += temp;
    }
    
    return result;
}    

unsigned long long dec_string_to_unsigned_long_long(std::string address)
{
    unsigned long long result = 0;
    
    for(char c : address)
    {
        int temp = c - '0';
        if(temp > 9 || temp < 0)
            return -1;
        
        result *= 10;
        result += temp;
    }
    
    return result;
}


void get_script_from_path(SDB &sdb, std::string path)
{   
    std::string s;
    
    std::ifstream inFile(path);
    if(!inFile.is_open())
    {
        fprintf(stdout, "** Can not open file \"%s\"\n", path.c_str());
    }
    else
    {
        while(std::getline(inFile, s))
        {
            implement_script(sdb, s);
        }
    }
    inFile.close();
    
    implement_script(sdb, "exit");
}    

void get_next_script(SDB &sdb)
{
    std::string s;
    
    fprintf(stderr, "sdb> "); 
    getline(std::cin, s);
    
    implement_script(sdb, s);
}

void implement_script(SDB &sdb, std::string script)
{    
    trim(script);
    
    if(script == "")
    {
        return ;
    }
    if(script == "exit" || script == "q")
    { // any
        implement_exit(sdb);
    }
    else if(script == "help" || script == "h")
    { // any
        implement_help(sdb);
    }
    else if(script == "run" || script == "r")
    { // loaded and running
        if(!LOADED)
        {
            fprintf(stdout, "** The program is not loaded.\n");
            return ;
        }
        
        if(RUNNING)
        {
            fprintf(stdout, "** program %s is already running.\n", sdb.program_path.c_str());
        }
        else
        {
            implement_start(sdb);
        }
        
        implement_cont(sdb);
    }
    else if(script == "start")
    { // loaded
        if(!LOADED)
        {
            fprintf(stdout, "** The program is not loaded.\n");
            return ;
        }
        
        implement_start(sdb);
    }
    else if(script == "cont" || script == "c")
    { // running
        if(!RUNNING)
        {
            fprintf(stdout, "** The program is not running.\n");
            return ;
        }
        
        implement_cont(sdb);
    }
    else if(script == "si")
    { // running
        if(!RUNNING)
        {
            fprintf(stdout, "** The program is not running.\n");
            return ;
        }
        
        implement_si(sdb);
    }
    else if(script == "list" || script == "l")
    { // any
        implement_list(sdb);
    }
    else if(script == "getregs")
    { // running
        if(!RUNNING)
        {
            fprintf(stdout, "** The program is not running.\n");
            return ;
        }
        
        implement_getregs(sdb);
    }
    else if(script == "vmmap" || script == "m")
    { // running
        if(!RUNNING)
        {
            fprintf(stdout, "** The program is not running.\n");
            return ;
        }
        
        implement_vmmap(sdb);
    }
    else
    {
        std::istringstream iss(script);
        std::vector<std::string> script_vector;
        std::string temp;
        while(iss >> temp) 
            script_vector.push_back(temp);
        
        /*
        for(size_t i = 0; i < script_vector.size(); i++)
        {
            fprintf(stdout, "** [%s]\n", script_vector[i].c_str());
        }
        //*/
        
        if(script_vector[0] == "load" || script_vector[0] == "l")
        { // not loaded
            if(LOADED)
            {
                fprintf(stdout, "** program '%s' has been loaded. entry point 0x%llx\n", sdb.program_path.c_str(), sdb.entry_point);
                return ;
            }
            
            if(script_vector.size() < 2)
            {
                fprintf(stdout, "** The command \'%s\' need %s.\n", "load", "path to a program");
                // implement_help(sdb);
                return ;
            }
            // clear sdb
            clear_sdb(sdb, true);
            
            // combin args
            for(size_t i = 1; i < script_vector.size(); i++)
                sdb.program_args.push_back(const_cast<char *>(script_vector[i].c_str()));
            sdb.program_args.push_back(nullptr);
            
            /*
            for(size_t i = 0; i < script_vector.size(); i++)
            {
                fprintf(stdout, "** |%ld|\t|%s|\n", i, sdb.program_args[i]);
            }
            //*/
            
            implement_load(sdb, script_vector[1]);
        }
        else if(script_vector[0] == "break" || script_vector[0] == "b")
        { // running
            if(!RUNNING)
            {
                fprintf(stdout, "** The program is not running.\n");
                return ;
            }
            
            if(script_vector.size() != 2)
            {
                fprintf(stdout, "** The command \'%s\' need %s.\n", "break", "instruction-address");
                // implement_help(sdb);
                return ;
            }
            
            if(script_vector[1].find("0x") == 0)
                implement_break(sdb, hex_string_to_unsigned_long_long(script_vector[1].substr(2)));
            else
                implement_break(sdb, dec_string_to_unsigned_long_long(script_vector[1]));
        }
        else if(script_vector[0] == "delete")
        { // running
            if(!RUNNING)
            {
                fprintf(stdout, "** The program is not running.\n");
                return ;
            }
            
            if(script_vector.size() != 2)
            {
                fprintf(stdout, "** The command \'%s\' need %s.\n", "delete", "break-point-id");
                // implement_help(sdb);
                return ;
            }
            
            implement_delete(sdb, string_to_int(script_vector[1]));
        }
        else if(script_vector[0] == "get" || script_vector[0] == "g")
        { // running
            if(!RUNNING)
            {
                fprintf(stdout, "** The program is not running.\n");
                return ;
            }
            
            if(script_vector.size() != 2)
            {
                fprintf(stdout, "** The command \'%s\' need %s.\n", "get", "register");
                // implement_help(sdb);
                return ;
            }
            
            implement_get(sdb, script_vector[1]);
        }
        else if(script_vector[0] == "set" || script_vector[0] == "s")
        { // running
            if(!RUNNING)
            {
                fprintf(stdout, "** The program is not running.\n");
                return ;
            }
            
            if(script_vector.size() != 3)
            {
                fprintf(stdout, "** The command \'%s\' need %s.\n", "set", "register and value");
                // implement_help(sdb);
                return ;
            }
            
            if(script_vector[2].find("0x") == 0)
                implement_set(sdb, script_vector[1], 
                    hex_string_to_unsigned_long_long(script_vector[2].substr(2)));
            else
                implement_set(sdb, script_vector[1], 
                    dec_string_to_unsigned_long_long(script_vector[2]));
        }
        else if(script_vector[0] == "disasm" || script_vector[0] == "d")
        { // running
            if(!RUNNING)
            {
                fprintf(stdout, "** The program is not running.\n");
                return ;
            }
            
            if(script_vector.size() == 1 && sdb.next_disasm_rip != 0)
            {
                fprintf(stdout, "** no addr is given.\n");
                implement_disasm(sdb, sdb.next_disasm_rip);
            }
            else if(script_vector.size() != 2)
            {
                fprintf(stdout, "** no addr is given.\n");
                // implement_help(sdb);
                return ;
            }
            else
            {
                if(script_vector[1].find("0x") == 0)
                    implement_disasm(sdb, hex_string_to_unsigned_long_long(script_vector[1].substr(2)));
                else
                    implement_disasm(sdb, dec_string_to_unsigned_long_long(script_vector[1]));
            }
        }
        else if(script_vector[0] == "dump" || script_vector[0] == "x")
        { // running
            if(!RUNNING)
            {
                fprintf(stdout, "** The program is not running.\n");
                return ;
            }
            
            int length = 80;
            if(script_vector.size() == 3)
                length = string_to_int(script_vector[2]);
            
            if(script_vector.size() == 1 && sdb.next_dump_rip != 0)
            {
                fprintf(stdout, "** no addr is given.\n");
                implement_dump(sdb, sdb.next_dump_rip, length);
            }
            else if(script_vector.size() < 2)
            {
                fprintf(stdout, "** no addr is given.\n");
                // implement_help(sdb);
                return ;
            }
            else
            {
                if(script_vector[1].find("0x") == 0)
                    implement_dump(sdb, hex_string_to_unsigned_long_long(script_vector[1].substr(2)), length);
                else
                    implement_dump(sdb, dec_string_to_unsigned_long_long(script_vector[1]), length);
            }
        }
        else
        {
            fprintf(stdout, "** There are no command named \'%s\'.\n", script_vector[0].c_str());
        }
    }
}


void implement_break(SDB &sdb, unsigned long long instruction_address)
{
    // fprintf(stdout, "** [break]\t0x%llx\n", instruction_address);
    
    // get code in specify address
    unsigned long long code;
    if((code = ptrace(PTRACE_PEEKTEXT, sdb.child, instruction_address, 0)) < 0)
    {
        fprintf(stdout, "** [break] PTRACE_PEEKTEXT error.\n");
        implement_exit(sdb);
    }
    
    unsigned long long temp = code & 0xff;
        
    // replace code by 0xcc
    if(ptrace(PTRACE_POKETEXT, sdb.child, instruction_address, (code ^ temp) | 0xcc) != 0)
    {
        fprintf(stdout, "** [break] PTRACE_POKETEXT error.\n");
        implement_exit(sdb);
    }
    
    // save break point
    auto it = std::find(sdb.break_addrs.begin(), sdb.break_addrs.end(), instruction_address);
    if(it != sdb.break_addrs.end())
    {
        int index = it - sdb.break_addrs.begin();
        sdb.break_code[index] = temp;
    }
    else
    {
        sdb.break_addrs.push_back(instruction_address);
        sdb.break_code.push_back(temp);
    }
}

void implement_cont(SDB &sdb)
{
    // fprintf(stdout, "** [cont]\n");
            
    // if next step is break point, call si
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, sdb.child, 0, &regs) != 0)
    {
        fprintf(stdout, "** [cont] PTRACE_GETREGS error.\n");
        implement_exit(sdb);
    }
    
    if(implement_si(sdb))
        return ;
    
    // continue execute program
    if(ptrace(PTRACE_CONT, sdb.child, 0, 0) < 0)
    {
        fprintf(stdout, "** [cont] cont error.\n");
        implement_exit(sdb);
    }
    
    if(waitpid(sdb.child, &sdb.status, 0) < 0)
    {
        fprintf(stdout, "** [cont] waitpid error.\n");
        implement_exit(sdb);
    }
    
    if(WIFEXITED(sdb.status))
    {
        fprintf(stdout, "** child process %d terminated normally (code %d)\n", sdb.child, WEXITSTATUS(sdb.status));
        LOADED = false;
        RUNNING = false;
    }
    else
    {
        if(ptrace(PTRACE_GETREGS, sdb.child, 0, &regs) != 0)
        {
            fprintf(stdout, "** [cont] PTRACE_GETREGS error.\n");
            implement_exit(sdb);
        }
        regs.rip --;
        
        unsigned long long code;
        if((code = ptrace(PTRACE_PEEKTEXT, sdb.child, regs.rip, 0)) < 0)
        {
            fprintf(stdout, "** [cont] PTRACE_PEEKTEXT error.\n");
            implement_exit(sdb);
        }
        
        
        // restore code
        auto it = std::find(sdb.break_addrs.begin(), sdb.break_addrs.end(), regs.rip);
        
        if(it != sdb.break_addrs.end())
        {
            int index = it - sdb.break_addrs.begin();
            
            if(ptrace(PTRACE_POKETEXT, sdb.child, regs.rip, code ^ 0xcc | sdb.break_code[index]) < 0)
            {
                fprintf(stdout, "** [cont] PTRACE_POKETEXT error.\n");
                implement_exit(sdb);
            }
            
            if(ptrace(PTRACE_SETREGS, sdb.child, 0, &regs))
            {
                fprintf(stdout, "** [cont] PTRACE_SETREGS error.\n");
                implement_exit(sdb);
            } 
            
            // print break point message
            fprintf(stdout, "** breakpoint @ ");
            disassemble(sdb, regs.rip, false);
            
            sdb.re_break_index = index;
        }
    }
}

void implement_delete(SDB &sdb, int break_point_id)
{
    // fprintf(stdout, "** [delete]\t%d\n", break_point_id);
    
    if(break_point_id >= sdb.break_addrs.size() || break_point_id < 0)
    {
        fprintf(stdout, "** breakpoint %d is not exist.\n", break_point_id);
    }
    else if(sdb.break_code[break_point_id] == -1)
    {
        fprintf(stdout, "** breakpoint %d is not exist.\n", break_point_id);
    }
    else
    {
        if(sdb.re_break_index == -1)
        {
            // get code in specify address
            unsigned long long code;
            if((code = ptrace(PTRACE_PEEKTEXT, sdb.child, sdb.break_addrs[break_point_id], 0)) < 0)
            {
                fprintf(stdout, "** [delete] PTRACE_PEEKTEXT error.\n");
                implement_exit(sdb);
            }
        
            // restore code
            if(ptrace(PTRACE_POKETEXT, sdb.child, sdb.break_addrs[break_point_id], (code ^ 0xcc) | sdb.break_code[break_point_id]) != 0)
            {
                fprintf(stdout, "** [delete] PTRACE_POKETEXT error.\n");
                implement_exit(sdb);
            }
        }
        
        // delete break point
        sdb.break_code[break_point_id] = -1;
        sdb.re_break_index = -1;
        fprintf(stdout, "** breakpoint %d deleted.\n", break_point_id);
    }
}

void implement_disasm(SDB &sdb, unsigned long long addr)
{
    // fprintf(stdout, "** [disasm]\t0x%llx\n", addr);
    
    // print 10 instruction
    unsigned long long rip = addr;
    int step = 0;
    for(int i = 0; i < 10; i ++)
    {
        rip += step;
        if(rip < sdb.text_segment_begin || rip > sdb.text_segment_end)
            break;
        
        step = disassemble(sdb, rip, false);
        if(step == -1)
            break;
    }
    
    // save next disasm rip
    if(step == -1)
        rip ++;
    else
        rip += step;
    sdb.next_disasm_rip = rip;
}

void implement_dump(SDB &sdb, unsigned long long addr, int length)
{
    // fprintf(stdout, "** [dump]\t0x%llx\t%d\n", addr, length);
    
    // print {length} bytes
    unsigned long long rip = addr;
    long ret_1, ret_2;
    unsigned char *ptr_1 = (unsigned char *) &ret_1;
    unsigned char *ptr_2 = (unsigned char *) &ret_2;
    
    int i = 0;
    while(true)
    {
        std::string temp = "................";
        /*
        if((ret_1 = ptrace(PTRACE_PEEKTEXT, sdb.child, rip, 0)) < 0)
        {
            fprintf(stdout, "** [dump] PTRACE_PEEKTEXT error.\n");
            implement_exit(sdb);
        }
        
        if((ret_2 = ptrace(PTRACE_PEEKTEXT, sdb.child, rip + 0x8, 0)) < 0)
        {
            fprintf(stdout, "** [dump] PTRACE_PEEKTEXT error.\n");
            implement_exit(sdb);
        }
        */
        ret_1 = ptrace(PTRACE_PEEKTEXT, sdb.child, rip, 0);
        ret_2 = ptrace(PTRACE_PEEKTEXT, sdb.child, rip + 0x8, 0);
        
        fprintf(stderr, "%12llx: ", rip);
        rip += 0x10;

        for(int j = 0; j < 8; j++)
            if(i + j < length)
            {
                if(isprint(ptr_1[j]))
                    temp[j] = ptr_1[j];
                fprintf(stderr, "%2.2x ", ptr_1[j]);
            }
            else
            {
                temp[j] = ' ';
                fprintf(stderr, "   ");
            }
            
        i += 8;
        
        for(int j = 0; j < 8; j++)
            if(i + j < length)
            {
                if(isprint(ptr_2[j]))
                    temp[8 + j] = ptr_2[j];
                fprintf(stderr, "%2.2x ", ptr_2[j]);
            }
            else
            {
                temp[8 + j] = ' ';
                fprintf(stderr, "   ");
            }
            
        i += 8;
            
        fprintf(stderr, " |%s|\n", temp.c_str());
        
        if(i >= length)
            break;
    }
    
    // save next dump rip
    sdb.next_dump_rip = addr + length;
}

void implement_exit(SDB &sdb)
{
    // fprintf(stdout, "** [exit]\n");
    
    if(sdb.child > 0)
        kill(sdb.child, SIGKILL);
    
    fprintf(stderr, "Bye.\n"); 
    exit(0);
}

void implement_get(SDB &sdb, std::string reg)
{
    // fprintf(stdout, "** [get]\t%s\n", reg.c_str());
    
    if(WIFSTOPPED(sdb.status))
    {
        struct user_regs_struct regs;
        
        // get regs and print out specify reg
        if(ptrace(PTRACE_GETREGS, sdb.child, 0, &regs) != 0)
        {
            fprintf(stdout, "** [get] PTRACE_GETREGS error.\n");
            implement_exit(sdb);
        }
        else
        {
            trim(reg);
            to_lowercase(reg);
            unsigned long long val = get_reg_by_string(regs, reg);
            
            if(val == -1)
                fprintf(stdout, "** There are no reg named \'%s\'.\n", reg.c_str());
            else
                fprintf(stderr, "%s = %lld (0x%llx)\n", reg.c_str(), val, val);
        }
    }
}

void implement_getregs(SDB &sdb)
{
    // fprintf(stdout, "** [getregs]\n");
    
    if(WIFSTOPPED(sdb.status))
    {
        struct user_regs_struct regs;
        
        // get regs and print out
        if(ptrace(PTRACE_GETREGS, sdb.child, 0, &regs) != 0)
        {
            fprintf(stdout, "** [getregs] PTRACE_GETREGS error.\n");
            implement_exit(sdb);
        }
        else
        {
            fprintf(stderr, "RAX %-18llxRBX %-18llxRCX %-18llxRDX %-18llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
            fprintf(stderr, "R8  %-18llxR9  %-18llxR10 %-18llxR11 %-18llx\n", regs.r8,  regs.r9,  regs.r10, regs.r11);           
            fprintf(stderr, "R12 %-18llxR13 %-18llxR14 %-18llxR15 %-18llx\n", regs.r12, regs.r13, regs.r14, regs.r15);         
            fprintf(stderr, "RDI %-18llxRSI %-18llxRBP %-18llxRSP %-18llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);  
            fprintf(stderr, "RIP %-18llxFLAGS %016llx\n", regs.rip, regs.eflags);
        }
    }
}

void implement_help(SDB &sdb)
{
    // fprintf(stdout, "** [help]\n");
    
    fprintf(stderr, "- break {instruction-address}: add a break point\n");
    fprintf(stderr, "- cont: continue execution\n");
    fprintf(stderr, "- delete {break-point-id}: remove a break point\n");
    fprintf(stderr, "- disasm addr: disassemble instructions in a file or a memory region\n");
    fprintf(stderr, "- dump addr [length]: dump memory content\n");
    fprintf(stderr, "- exit: terminate the debugger\n");
    fprintf(stderr, "- get reg: get a single value from a register\n");
    fprintf(stderr, "- getregs: show registers\n");
    fprintf(stderr, "- help: show this message\n");
    fprintf(stderr, "- list: list break points\n");
    fprintf(stderr, "- load {path/to/a/program}: load a program\n");
    fprintf(stderr, "- run: run the program\n");
    fprintf(stderr, "- vmmap: show memory layout\n");
    fprintf(stderr, "- set reg val: get a single value to a register\n");
    fprintf(stderr, "- si: step into instruction\n");
    fprintf(stderr, "- start: start the program and stop at the first instruction\n");
}

void implement_list(SDB &sdb)
{
    // fprintf(stdout, "** [list]\n");
    
    // list break points that have not been deleted
    for(int i = 0; i < sdb.break_addrs.size(); i++)
    {
        if(sdb.break_code[i] != -1)
            fprintf(stderr, "%3d:   %llx\n", i, sdb.break_addrs[i]);
    }
}

void implement_load(SDB &sdb, std::string path)
{
    // fprintf(stdout, "** [load]\t%s\n", path.c_str());
    
    // file must be executable, and then get entry point
    if(access(path.c_str(), X_OK | R_OK) != 0)
    {
        fprintf(stdout, "** Can not load file \'%s\'\n", path.c_str());
    }
    else
    {
        sdb.program_path = path;
        
        std::ifstream inFile(path);
        Elf64_Ehdr elf_e;
        
        // read entry point
        inFile.read((char*)&elf_e, sizeof(elf_e));
        sdb.entry_point = elf_e.e_entry;
        
        /*
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_type);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_machine);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_version);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_entry);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_phoff);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_shoff);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_flags);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_ehsize);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_phentsize);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_phnum);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_shentsize);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_shnum);
        fprintf(stderr, "[elf_e] %llx.\n", elf_e.e_shstrndx);
        //*/
        
        // read .text segment range    
        Elf64_Shdr elf_s;
        
        inFile.seekg(elf_e.e_shoff + elf_e.e_shstrndx * sizeof(elf_s), std::ios::beg);
        inFile.read((char*)&elf_s, sizeof(elf_s));
        
        std::string name;
        char *SectNames = (char *)malloc(elf_s.sh_size);
        inFile.seekg(elf_s.sh_offset, std::ios::beg);
        inFile.read(SectNames, elf_s.sh_size);
        
        for(int i = 0; i < elf_e.e_shnum; i++)
        {
            inFile.seekg(elf_e.e_shoff + i * elf_e.e_shentsize, std::ios::beg);
            inFile.read((char*)&elf_s, sizeof(elf_s));
            
            name = SectNames + elf_s.sh_name;
            if(name == ".text")
            {
                //fprintf(stderr, "[name] %s", name.c_str());
                sdb.text_segment_begin = elf_s.sh_addr;
                sdb.text_segment_end = elf_s.sh_addr + elf_s.sh_size - 1;
                break;
            }
            
            /*
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_name);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_type);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_flags);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_addr);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_offset);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_size);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_link);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_info);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_addralign);
            fprintf(stderr, "[elf_s] %llx.\n", elf_s.sh_entsize);
            //*/
        }
        
        inFile.close();

        if(cs_open(CS_ARCH_X86, CS_MODE_64, &sdb.cshandle) != CS_ERR_OK)
        {
            fprintf(stdout, "** [load] cs_open error.\n");
            implement_exit(sdb);
        }
        
        LOADED = true;
        
        fprintf(stdout, "** program '%s' loaded. entry point 0x%llx\n", sdb.program_path.c_str(), sdb.entry_point);
    }
}

/*
void implement_run(SDB &sdb)
{
    fprintf(stdout, "** [run]\n");
}
//*/

void implement_vmmap(SDB &sdb)
{
    // fprintf(stdout, "** [vmmap]\n");
    
    // get data from /proc/{child}/maps
    char path[1024];
    sprintf(path, "/proc/%d/maps", sdb.child);
    
    std::ifstream inFile(path);
    std::string line;
    
    if (!inFile.is_open())
    {
        fprintf(stdout, "** Can not open file \"%s\"\n", path);
    }
    else
    {
        while(std::getline(inFile, line))
        {
            std::string temp;
            std::stringstream ss;
            ss << line;
            
            ss >> temp;
            std::string b = temp.substr(0, temp.find("-"));
            std::string e = temp.substr(temp.find("-") + 1);
            
            fprintf(stderr, "%016llx-%016llx"
                , hex_string_to_unsigned_long_long(b)
                , hex_string_to_unsigned_long_long(e));
            
            ss >> temp;
            fprintf(stderr, " %s", temp.substr(0, 3).c_str());
            ss >> temp;
            ss >> temp;
            ss >> temp;
            fprintf(stderr, " %-8s", temp.c_str());
            ss >> temp;
            fprintf(stderr, "\t%s\n", temp.c_str());
        }
    }
}

void implement_set(SDB &sdb, std::string reg, unsigned long long val)
{
    // fprintf(stdout, "** [set]\t%s\t0x%llx\n", reg.c_str(), val);
    
    if(WIFSTOPPED(sdb.status))
    {
        struct user_regs_struct regs;
        
        // get specify reg val, if it's difference then update
        if(ptrace(PTRACE_GETREGS, sdb.child, 0, &regs) != 0)
        {
            fprintf(stdout, "** [set] PTRACE_GETREGS error.\n");
            implement_exit(sdb);
        }
        else
        {
            trim(reg);
            to_lowercase(reg);
            unsigned long long old_val = get_reg_by_string(regs, reg);
            
            if(old_val == -1)
                fprintf(stdout, "** There are no reg named \'%s\'.\n", reg.c_str());
            else if(old_val != val)
            {
                set_reg_by_string(regs, reg, val);
                if(ptrace(PTRACE_SETREGS, sdb.child, 0, &regs) != 0)
                {
                    fprintf(stdout, "** [set] PTRACE_POKETEXT error.\n");
                    implement_exit(sdb);
                }
            }
            
            // if there are break index need to reset
            if(sdb.re_break_index != -1 && sdb.break_code[sdb.re_break_index] != -1)
            {
                implement_break(sdb, sdb.break_addrs[sdb.re_break_index]);
                sdb.re_break_index = -1;
            }
        }
    }
}

bool implement_si(SDB &sdb)
{
    // fprintf(stdout, "** [si]\n");
    
    // get rip
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, sdb.child, 0, &regs) != 0)
    {
        fprintf(stdout, "** [si] PTRACE_GETREGS error.\n");
        implement_exit(sdb);
    }
    
    // execute program step by step 
    if(ptrace(PTRACE_SINGLESTEP, sdb.child, 0, 0) < 0)
    {
        fprintf(stdout, "** [si] PTRACE_SINGLESTEP error.\n");
        implement_exit(sdb);
    }
    
    if(waitpid(sdb.child, &sdb.status, 0) < 0)
    {
        fprintf(stdout, "** [si] waitpid error.\n");
        implement_exit(sdb);
    }
    
    if(WIFEXITED(sdb.status))
    {
        fprintf(stdout, "** child process %d terminated normally (code %d)\n", sdb.child, WEXITSTATUS(sdb.status));
        LOADED = false;
        RUNNING = false;
    }
    else
    {
        // if there are break index need to reset
        if(sdb.re_break_index != -1 && sdb.break_code[sdb.re_break_index] != -1)
        {
            implement_break(sdb, sdb.break_addrs[sdb.re_break_index]);
            sdb.re_break_index = -1;
        }
        
        // if next step is break point, then restore code
        if(ptrace(PTRACE_GETREGS, sdb.child, 0, &regs) != 0)
        {
            fprintf(stdout, "** [si] PTRACE_GETREGS error.\n");
            implement_exit(sdb);
        }
        
        auto it = std::find(sdb.break_addrs.begin(), sdb.break_addrs.end(), regs.rip);
        if(it != sdb.break_addrs.end() && sdb.re_break_index == -1)
        {
            // restore code
            unsigned long long code;
            if((code = ptrace(PTRACE_PEEKTEXT, sdb.child, regs.rip, 0)) < 0)
            {
                fprintf(stdout, "** [si] PTRACE_PEEKTEXT error.\n");
                implement_exit(sdb);
            }
            
            int index = it - sdb.break_addrs.begin();
            
            if(ptrace(PTRACE_POKETEXT, sdb.child, regs.rip, code ^ 0xcc | sdb.break_code[index]) < 0)
            {
                fprintf(stdout, "** [si] PTRACE_POKETEXT error.\n");
                implement_exit(sdb);
            }
            
            if(ptrace(PTRACE_SETREGS, sdb.child, 0, &regs))
            {
                fprintf(stdout, "** [si] PTRACE_SETREGS error.\n");
                implement_exit(sdb);
            } 
            
            // print break point message
            fprintf(stdout, "** breakpoint @ ");
            disassemble(sdb, regs.rip, false);
            
            sdb.re_break_index = index;
            return true;
        }
    }
    return false;
}

void implement_start(SDB &sdb)
{
    // fprintf(stdout, "** [start]\n");
    
    // if there are child execute, kill it
    if(sdb.child > 0)
    {
        kill(sdb.child, SIGKILL);
        clear_sdb(sdb, false);
    }
    
    sdb.child = fork();
    
    // error
    if(sdb.child < 0){
        fprintf(stdout, "** [start] fork error.\n");
        implement_exit(sdb);
    }

    // child -> execute program, parent -> wait child in first instruction
    if(sdb.child == 0)
    {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
        {
            fprintf(stdout, "** [start] PTRACE_TRACEME error.\n");
            implement_exit(sdb);
        }
        
        execvp(sdb.program_path.c_str(), sdb.program_args.data());
        fprintf(stdout, "** [start] \'%s\' execute error.\n", sdb.program_path.c_str());
        implement_exit(sdb);
    }
    else
    {
        if(waitpid(sdb.child, &sdb.status, 0) < 0)
        {
            fprintf(stdout, "** [start] waitpid error.\n");
            implement_exit(sdb);
        }
        
        fprintf(stdout, "** pid %d\n", sdb.child);
        assert(WIFSTOPPED(sdb.status));
        ptrace(PTRACE_SETOPTIONS, sdb.child, 0, PTRACE_O_EXITKILL);
        
        disassemble(sdb, sdb.entry_point, true);
        
        RUNNING = true;
    }
}


int print_instruction(SDB &sdb, long long addr, instruction1 *in, bool first)
{
    int i;
    char bytes[128] = "";
    if(in == NULL)
    {
        if(!first)
            fprintf(stderr, "%12llx: <cannot disassemble>\n", addr);
        return -1;
    }
    else
    {
        if(!first)
        {
            for(i = 0; i < in->size; i++)
                snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
            fprintf(stderr, "%12llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
        }
        
        return in->size;
    }
}

int disassemble(SDB &sdb, unsigned long long rip, bool first)
{
    int count;
    char buf[64] = { 0 };
    unsigned long long ptr = rip;
    cs_insn *insn;
    std::map<long long, instruction1>::iterator mi;

    if((mi = sdb.instructions.find(rip)) != sdb.instructions.end())
    {
        return print_instruction(sdb, rip, &mi->second, first);
    }

    for(ptr = rip; ptr < rip + sizeof(buf); ptr += PEEKSIZE)
    {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, sdb.child, ptr, NULL);
        if(errno != 0) break;
        memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
    }

    if(ptr == rip)
    {
        return print_instruction(sdb, rip, NULL, first);
    }

    if((count = cs_disasm(sdb.cshandle, (uint8_t*) buf, rip-ptr, rip, 0, &insn)) > 0)
    {
        int i;
        for(i = 0; i < count; i++)
        {
            instruction1 in;
            in.size = insn[i].size;
            in.opr  = insn[i].mnemonic;
            in.opnd = insn[i].op_str;
            memcpy(in.bytes, insn[i].bytes, insn[i].size);
            sdb.instructions[insn[i].address] = in;
        }
        cs_free(insn, count);
    }

    if((mi = sdb.instructions.find(rip)) != sdb.instructions.end())
        return print_instruction(sdb, rip, &mi->second, first);
    else
        return print_instruction(sdb, rip, NULL, first);
}













