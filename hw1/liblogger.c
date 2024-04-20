#include <stdio.h> // for fopen, fread, fwrite
#include <stdlib.h> // for system
#include <sys/socket.h> // for connect
#include <netdb.h> // for getaddrinfo
#include <arpa/inet.h> // for sockaddr

#include <errno.h> // for errno
#include <dlfcn.h> // for dlsym, dlopen

#include <string.h>

static FILE* (*org_fopen)(const char*, const char*) = NULL;
static size_t (*org_fwrite)(const void*, size_t, size_t, FILE*) = NULL;
static size_t (*org_fread)(void*, size_t, size_t, FILE*) = NULL;
static int (*org_connect)(int, const struct sockaddr*, socklen_t) = NULL;
static int (*org_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**) = NULL;
static int (*org_system)(const char*) = NULL;

FILE* outputStream;

void errquit(const char* msg)
{
    perror(msg);
    exit(1);
}

char* transformString(const char* str)
{
    if(str == NULL)
    {
        char* ret = (char*)malloc(6 * sizeof(char));
        strcpy(ret, "(nil)");
        return ret;
    }
    size_t len = strlen(str);
    char* newStr = (char*)malloc(len*2+1);
    newStr[0] = '"';
    newStr[1] = '\0';
    size_t curindex = 1;
    for(size_t i = 0; i < len; i++)
    {
        if(str[i] == '\n')
        {
            newStr[curindex] = '\\';
            newStr[curindex+1] = 'n';
            newStr[curindex+2] = '\0';
            curindex += 2;
        }
        else if(str[i] == '\t')
        {
            newStr[curindex] = '\\';
            newStr[curindex+1] = 't';
            newStr[curindex+2] = '\0';
            curindex += 2;
        }
        else if(str[i] == '\r')
        {
            newStr[curindex] = '\\';
            newStr[curindex+1] = 'r';
            newStr[curindex+2] = '\0';
            curindex += 2;
        }
        else if(str[i] == '\v')
        {
            newStr[curindex] = '\\';
            newStr[curindex+1] = 'v';
            newStr[curindex+2] = '\0';
            curindex += 2;
        }
        else if(str[i] == '\f')
        {
            newStr[curindex] = '\\';
            newStr[curindex+1] = 'f';
            newStr[curindex+2] = '\0';
            curindex += 2;
        }
        else if(str[i] == '\a')
        {
            newStr[curindex] = '\\';
            newStr[curindex+1] = 'a';
            newStr[curindex+2] = '\0';
            curindex += 2;
        }
        else
        {
            newStr[curindex] = str[i];
            newStr[curindex+1] = '\0';
            curindex++;
        }
    }
    newStr[curindex] = '"';
    newStr[curindex+1] = '\0';
    return newStr;
}

void getFunctionInStdio()
{
    void* handle = dlopen("libc.so.6", RTLD_LAZY);
    if (handle == NULL)
    {
        fprintf(stderr, "dlopen failed - %s\n", dlerror());
        errquit("dlopen failed");
    }
    // return type (*[function_name])(parameter_type)
    org_fopen = (FILE* (*)(const char*, const char*)) dlsym(handle, "fopen");
    org_fread = (size_t (*)(void*, size_t, size_t, FILE*)) dlsym(handle, "fread");
    org_fwrite = (size_t (*)(const void*, size_t, size_t, FILE*)) dlsym(handle, "fwrite");
    org_connect = (int (*)(int, const struct sockaddr*, socklen_t)) dlsym(handle, "connect");
    org_getaddrinfo = (int (*)(const char*, const char*, const struct addrinfo*, struct addrinfo**)) dlsym(handle, "getaddrinfo");
    org_system = (int (*)(const char*)) dlsym(handle, "system");
    if (org_fopen == NULL || org_fread == NULL || org_fwrite == NULL || org_connect == NULL || org_getaddrinfo == NULL || org_system == NULL)
    {
        fprintf(stderr, "dlsym failed - %s\n", dlerror());
        errquit("dlsym failed");
    }
}

void setOutputStream(FILE* stream)
{
    // outputStream = stream;
    outputStream = stderr;
}

FILE *fopen(const char *filename, const char *mode)
{
    setOutputStream(stderr);
    if (org_fopen == NULL)
    {
        getFunctionInStdio();
    }
    FILE* ret = org_fopen(filename, mode);
    {
        char* filenameStr = transformString(filename);
        char* modeStr = transformString(mode);
        fprintf(outputStream, "[logger] fopen:(%s, %s) = %p\n", filenameStr, modeStr, (void *)ret);
        free(filenameStr);
        free(modeStr);
    }
    return ret;
}
size_t fwrite(const void *ptr, size_t size, size_t count, FILE *stream)
{
    setOutputStream(stderr);

    if (org_fwrite == NULL)
    {
        getFunctionInStdio();
    }
    size_t ret = org_fwrite(ptr, size, count, stream);
    {
        char* inputStr = transformString((char*)ptr);
        fprintf(outputStream, "[logger] fwrite:(%s, %lu, %lu, %p) = %lu\n", inputStr, size, count, (void *)stream, ret);
        free(inputStr);
    }
    return ret;
}
size_t fread(void *ptr, size_t size, size_t count, FILE *stream)
{
    setOutputStream(stderr);

    if (org_fread == NULL)
    {
        getFunctionInStdio();
    }
    size_t ret = org_fread(ptr, size, count, stream);
    fprintf(outputStream, "[logger] fread:(%p, %lu, %lu, %p) = %lu\n", ptr, size, count, (void *)stream, ret);
    return ret;
}
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    setOutputStream(stderr);

    if(org_connect == NULL)
    {
        getFunctionInStdio();
    }
    int ret = org_connect(sockfd, addr, addrlen);
    char* ip = inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
    fprintf(outputStream, "[logger] connect:(%d, %s, %u) = %d\n", sockfd, ip, addrlen, ret);
    return ret;
}
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    setOutputStream(stderr);

    if(org_getaddrinfo == NULL)
    {
        getFunctionInStdio();
    }
    int ret = org_getaddrinfo(node, service, hints, res);
    {
        char* nodeStr = transformString(node);
        char* serviceStr = transformString(service);
        fprintf(outputStream, "[logger] getaddrinfo:(%s, %s, %p, %p) = %d\n", nodeStr, serviceStr, (void *)hints, (void *)res, ret);
        free(nodeStr);
        free(serviceStr);
    }
    return ret;
}
int system(const char *command)
{
    setOutputStream(stderr);

    if(org_system == NULL)
    {
        getFunctionInStdio();
    }
    int ret = org_system(command);
    {
        char* commandStr = transformString(command);
        fprintf(outputStream, "[logger] system:(%s) = %d\n", commandStr, ret);
        free(commandStr);
    }
    return ret;
}