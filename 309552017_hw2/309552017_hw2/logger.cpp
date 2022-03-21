#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>


extern "C"
{
    char *io = NULL;
    char *o = NULL;
    // char *f = NULL;
    
    void outFile(char *str);
    const char *get_realpath(const char *pathname);
    char *get_fd_filename(int fd);
    char *get_char_buff(char *ptr, int size);


    typedef int (*CHMOD)(const char *pathname, mode_t mode);
    typedef int (*CHOWN)(const char *pathname, uid_t owner, gid_t group);
    typedef int (*CLOSE)(int fd);
    typedef int (*CREAT)(const char *pathname, mode_t mode);
    typedef int (*FCLOSE)(FILE *stream);
    typedef FILE *(*FOPEN)(const char *pathname, const char *mode);
    typedef size_t (*FREAD)(void *ptr, size_t size, size_t nmemb, FILE *stream);
    typedef size_t (*FWRITE)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
    typedef int (*OPEN)(const char *pathname, int flags, ...);
    typedef ssize_t (*READ)(int fd, void *buf, size_t count);
    typedef int (*REMOVE)(const char *pathname);
    typedef int (*RENAME)(const char *oldpath, const char *newpath);
    typedef FILE *(*TMPFILE)(void);
    typedef ssize_t (*WRITE)(int fd, const void *buf, size_t count);


    int chmod(const char *pathname, mode_t mode)
    {
        // get origin function
        CHMOD old_chmod = NULL;
        old_chmod = (CHMOD)dlsym(RTLD_NEXT, "chmod");

        // get return value
        int result = old_chmod(pathname, mode);

        char str[1024];
        sprintf(str, "[logger] chmod(\"%s\", %o) = %d\n",
            get_realpath(pathname),
            mode,
            result
        );
        outFile(str);

        return result;
    }

    int chown(const char *pathname, uid_t owner, gid_t group)
    {
        // get origin function
        CHOWN old_chown = NULL;
        old_chown = (CHOWN)dlsym(RTLD_NEXT, "chown");

        // get return value
        int result = old_chown(pathname, owner, group);

        char str[1024];
        sprintf(str, "[logger] chown(\"%s\", %d, %d) = %d\n",
            get_realpath(pathname),
            owner,
            group,
            result
        );
        outFile(str);

        return result;
    }

    int close(int fd)
    {
        // get origin function
        CLOSE old_close = NULL;
        old_close = (CLOSE)dlsym(RTLD_NEXT, "close");

        // get return value
        char *filename = get_fd_filename(fd);

        int result;
        if(fd != 2)
            result = old_close(fd);

        char str[1024];
        sprintf(str, "[logger] close(\"%s\") = %d\n",
            filename,
            result
        );
        outFile(str);

        return result;
    }

    int creat(const char *pathname, mode_t mode)
    {
        // get origin function
        CREAT old_creat = NULL;
        old_creat = (CREAT)dlsym(RTLD_NEXT, "creat");

        // get return value
        int result = old_creat(pathname, mode);

        char str[1024];
        sprintf(str, "[logger] creat(\"%s\", %o) = %d\n",
            get_realpath(pathname),
            mode,
            result
        );
        outFile(str);

        return result;
    }

    int creat64(const char *pathname, mode_t mode)
    {
        // get origin function
        CREAT old_creat64 = NULL;
        old_creat64 = (CREAT)dlsym(RTLD_NEXT, "creat64");

        // get return value
        int result = old_creat64(pathname, mode);

        char str[1024];
        sprintf(str, "[logger] creat64(\"%s\", %o) = %d\n",
            get_realpath(pathname),
            mode,
            result
        );
        outFile(str);

        return result;
    }

    int fclose(FILE *stream)
    {
        // get origin function
        FCLOSE old_fclose = NULL;
        old_fclose = (FCLOSE)dlsym(RTLD_NEXT, "fclose");

        // get return value
        char *filename = get_fd_filename(fileno(stream));

        int result = 0;
        if(fileno(stream) != 2)
            result = old_fclose(stream);

        char str[1024];
        sprintf(str, "[logger] fclose(\"%s\") = %d\n",
            filename,
            result
        );
        outFile(str);

        return result;
    }

    FILE *fopen(const char *pathname, const char *mode)
    {
        // get origin function
        FOPEN old_fopen = NULL;
        old_fopen = (FOPEN)dlsym(RTLD_NEXT, "fopen");

        // get return value
        FILE *result = old_fopen(pathname, mode);

        char str[1024];
        sprintf(str, "[logger] fopen(\"%s\", \"%s\") = %p\n",
            get_realpath(pathname),
            mode,
            result
        );
        outFile(str);

        return result;
    }

    FILE *fopen64(const char *pathname, const char *mode)
    {
        // get origin function
        FOPEN old_fopen64 = NULL;
        old_fopen64 = (FOPEN)dlsym(RTLD_NEXT, "fopen64");

        // get return value
        FILE *result = old_fopen64(pathname, mode);

        char str[1024];
        sprintf(str, "[logger] fopen64(\"%s\", \"%s\") = %p\n",
            get_realpath(pathname),
            mode,
            result
        );
        outFile(str);

        return result;
    }

    size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
    {
        // get origin function
        FREAD old_fread = NULL;
        old_fread = (FREAD)dlsym(RTLD_NEXT, "fread");

        // get return value
        size_t result = old_fread(ptr, size, nmemb, stream);

        char str[1024];
        sprintf(str, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n",
            get_char_buff((char *)ptr, result * size),
            size,
            nmemb,
            get_fd_filename(fileno(stream)),
            result
        );
        outFile(str);

        return result;
    }

    size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
    {
        // get origin function
        FWRITE old_fwrite = NULL;
        old_fwrite = (FWRITE)dlsym(RTLD_NEXT, "fwrite");

        // get return value
        size_t result = old_fwrite(ptr, size, nmemb, stream);

        char str[1024];
        sprintf(str, "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n",
            get_char_buff((char *)ptr, result * size),
            size,
            nmemb,
            get_fd_filename(fileno(stream)),
            result
        );
        outFile(str);

        return result;
    }

    int open(const char *pathname, int flags, ...)
    {
        // get origin function
        OPEN old_open = NULL;
        old_open = (OPEN)dlsym(RTLD_NEXT, "open");

        // get mode
        mode_t mode = 0;
        if(flags & 64)
        {
            va_list sArgv;
            va_start(sArgv, flags);
            mode = va_arg(sArgv, mode_t);
            va_end(sArgv);
        }

        // get return value
        int result = old_open(pathname, flags, mode);

        char str[1024];
        sprintf(str, "[logger] open(\"%s\", %o, %o) = %d\n",
            get_realpath(pathname),
            flags,
            mode,
            result
        );
        outFile(str);

        return result;
    }

    int open64(const char *pathname, int flags, ...)
    {
        // get origin function
        OPEN old_open64 = NULL;
        old_open64 = (OPEN)dlsym(RTLD_NEXT, "open64");

        // get mode
        mode_t mode = 0;
        if(flags & 64)
        {
            va_list sArgv;
            va_start(sArgv, flags);
            mode = va_arg(sArgv, mode_t);
            va_end(sArgv);
        }

        // get return value
        int result = old_open64(pathname, flags, mode);

        char str[1024];
        sprintf(str, "[logger] open64(\"%s\", %o, %o) = %d\n",
            get_realpath(pathname),
            flags,
            mode,
            result
        );
        outFile(str);

        return result;
    }

    ssize_t read(int fd, void *buf, size_t count)
    {
        // get origin function
        READ old_read = NULL;
        old_read = (READ)dlsym(RTLD_NEXT, "read");

        // get return value
        ssize_t result = old_read(fd, buf, count);

        char str[1024];
        sprintf(str, "[logger] read(\"%s\", \"%s\", %ld) = %ld\n",
            get_fd_filename(fd),
            get_char_buff((char *)buf, result),
            count,
            result
        );
        outFile(str);

        return result;
    }

    int remove(const char *pathname)
    {
        // get origin function
        REMOVE old_remove = NULL;
        old_remove = (REMOVE)dlsym(RTLD_NEXT, "remove");

        // get return value
        const char *realpath = get_realpath(pathname);
        int result = old_remove(pathname);

        char str[1024];
        sprintf(str, "[logger] remove(\"%s\") = %d\n",
            realpath,
            result
        );
        outFile(str);

        return result;
    }

    int rename(const char *oldpath, const char *newpath)
    {
        // get origin function
        RENAME old_rename = NULL;
        old_rename = (RENAME)dlsym(RTLD_NEXT, "rename");

        // get return value
        char str[1024];
        sprintf(str, "[logger] rename(\"%s\",",
            get_realpath(oldpath)
        );
        outFile(str);

        int result = old_rename(oldpath, newpath);

        sprintf(str, " \"%s\") = %d\n",
            get_realpath(newpath),
            result
        );
        outFile(str);

        return result;
    }

    FILE *tmpfile(void)
    {
        // get origin function
        TMPFILE old_tmpfile = NULL;
        old_tmpfile = (TMPFILE)dlsym(RTLD_NEXT, "tmpfile");

        // get return value
        FILE *result = old_tmpfile();

        char str[1024];
        sprintf(str, "[logger] tmpfile() = %p\n",
            result
        );
        outFile(str);

        return result;
    }

    FILE *tmpfile64(void)
    {
        // get origin function
        TMPFILE old_tmpfile64 = NULL;
        old_tmpfile64 = (TMPFILE)dlsym(RTLD_NEXT, "tmpfile64");

        // get return value
        FILE *result = old_tmpfile64();

        char str[1024];
        sprintf(str, "[logger] tmpfile64() = %p\n",
            result
        );
        outFile(str);

        return result;
    }

    ssize_t write(int fd, const void *buf, size_t count)
    {
        // get origin function
        WRITE old_write = NULL;
        old_write = (WRITE)dlsym(RTLD_NEXT, "write");

        // get return value
        ssize_t result = old_write(fd, buf, count);

        char str[1024];
        sprintf(str, "[logger] write(\"%s\", \"%s\", %ld) = %ld\n",
            get_fd_filename(fd),
            get_char_buff((char *)buf, result),
            count,
            result
        );
        outFile(str);

        return result;
    }


    void outFile(char *str)
    {
        if(o == NULL)
            o = getenv("OUTFILE");
        if(io == NULL)
            io = getenv("isOutfile");
        // if(f == NULL)
            // f = getenv("OUTFILE_FIRST");
        
        // printf("|%s\n", str);
        FILE *outFile = NULL;
        
        // REMOVE old_remove = NULL;
        // old_remove = (REMOVE)dlsym(RTLD_NEXT, "remove");
        
        FOPEN old_fopen = NULL;
        old_fopen = (FOPEN)dlsym(RTLD_NEXT, "fopen");
        
        FCLOSE old_fclose = NULL;
        old_fclose = (FCLOSE)dlsym(RTLD_NEXT, "fclose");
        
        // printf("OUTFILE|%s|\n", o);
        // printf("isOutfile|%s||\n", io);
        // printf("OUTFILE_FIRST|%s|||\n", f);
        if(io[0] == 'F')
        {
            outFile = stderr;
            fprintf(outFile, "%s", str);
        }
        else
        {
            // if(f[0] == 'T')
            // {
                // old_remove(get_realpath(o));
                // f = (char *)"F";
            // }
            outFile = old_fopen(o, "a");
            fprintf(outFile, "%s", str);
            old_fclose(outFile);
        }
    }

    const char *get_realpath(const char *pathname)
    {
        static char buf[PATH_MAX + 1];
        char *the_realpath = realpath(pathname, buf);

        if(the_realpath)
            return buf;
        else
            return pathname;
    }

    char *get_fd_filename(int fd)
    {
        static char path[64], buff[1024];
        sprintf(path, "/proc/self/fd/%d", fd);

        int len = readlink(path, buff, 1023);

        if(len == -1)
            return NULL;

        buff[len] = '\0';
        return buff;
    }

    char *get_char_buff(char *ptr, int size)
    {
        static char buff[33];

        if(size > 32)
            size = 32;

        int i = 0;
        for(; i < size; i++)
        {
            if(!isprint(ptr[i]))
                buff[i] = '.';
            else
                buff[i] = ptr[i];
        }

        buff[i] = '\0';

        return buff;
    }
}
