#include <stdio.h> // for fopen, fread, fwrite
#include <stdlib.h> // for system
#include <sys/socket.h> // for connect
#include <netdb.h> // for getaddrinfo
#include <arpa/inet.h> // for sockaddr

#include <errno.h> // for errno
#include <dlfcn.h> // for dlsym, dlopen
#include <unistd.h> // for getcwd, readlink
#include <libgen.h> // for dirname
#include <string.h>
#include <fnmatch.h> // for fnmatch
#include <unistd.h> // for readlink

#define PATH_MAX 4096
#define _GNU_SOURCE // to prevent some weird version of function, like basename and dirname

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

char* transformString(const char* str, short withQuote)
{
    if(str == NULL)
    {
        char* ret = (char*)malloc(6 * sizeof(char));
        strcpy(ret, "(nil)");
        return ret;
    }
    size_t len = strlen(str);
    char* newStr = (char*)malloc(len*2+1);
    size_t curindex;
    if(withQuote)
    {
        newStr[0] = '"';
        newStr[1] = '\0';
        curindex = 1;
    }
    else
    {
        newStr[0] = '\0';
        curindex = 0;
    }
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
    if(withQuote)
    {
        newStr[curindex] = '"';
        newStr[curindex+1] = '\0';
    }
    else
    {
        newStr[curindex] = '\0';
    }
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
    outputStream = stream;
}

char* relativeToAbs(const char* filename, const char* dir)
{
    // fprintf(stderr, "filename: %s\n", filename);
    // fprintf(stderr, "dir: %s\n", dir);
    char* absFilename = (char*)malloc(PATH_MAX);
    if(filename[0] == '/')
    {
        strcpy(absFilename, filename);
    }
    else
    {
        char dirBuffer[PATH_MAX];
        strcpy(dirBuffer, dir);
        char filenameBuffer[PATH_MAX];
        strcpy(filenameBuffer, filename);
        char filenameList[120][PATH_MAX];
        int filenameCount = 0;
        // dir start from /
        filenameList[filenameCount][0] = '/';
        filenameList[filenameCount][1] = '\0';
        filenameCount++;
        char* token = strtok(dirBuffer, "/");
        while(token != NULL)
        {
            if(strcmp(token, "..") == 0)
            {
                filenameCount--;
            }
            else if(strcmp(token, ".") == 0)
            {
                // do nothing
            }
            else
            {
                memset(filenameList[filenameCount], 0, PATH_MAX);
                strcpy(filenameList[filenameCount], token);
                filenameCount++;
            }
            token = strtok(NULL, "/");
        }
        token = strtok(filenameBuffer, "/");
        while(token != NULL)
        {
            if(strcmp(token, "..") == 0)
            {
                filenameCount--;
            }
            else if(strcmp(token, ".") == 0)
            {
                // do nothing
            }
            else
            {
                memset(filenameList[filenameCount], 0, PATH_MAX);
                strcpy(filenameList[filenameCount], token);
                filenameCount++;
            }
            token = strtok(NULL, "/");
        }
        for(int i = 0; i < filenameCount; i++)
        {
            // fprintf(stderr, "filenameList[%d]: %s\n", i, filenameList[i]);
            absFilename = strcat(absFilename, filenameList[i]);
            if(i != 0 && i != filenameCount-1)
            {
                absFilename = strcat(absFilename, "/");
            }
        }

    }
    return absFilename;
}

char* resolveSymbolicLink(const char* filename)
{
    char* absFilenameLink;
    char* programDir = getenv("PROGRAM_DIR");
    if(programDir == NULL)
    {
        errquit("PROGRAM_DIR is not set");
    }
    absFilenameLink = relativeToAbs(filename, programDir);

    char absFilenameLinkCopy[PATH_MAX];
    char relFilename[PATH_MAX];
    char* absFilename = NULL;
    strcpy(absFilenameLinkCopy, absFilenameLink);
    // readlink, it will change the absFilenameLink also.
    int sizeInBuf = readlink(absFilenameLinkCopy, relFilename, PATH_MAX-1);
    relFilename[PATH_MAX-1] = '\0';
    if(sizeInBuf == -1)
    {
        if(errno == ENOENT || errno == EINVAL || errno == EACCES || errno == ENOTDIR)
        {
            // file not exist, or not a link, or not accessible, or prefix is not a directory
            absFilename = malloc(PATH_MAX);
            strcpy(absFilename, absFilenameLinkCopy);
        }
        else
        {
            errquit("readlink failed");
        }
    }
    else
    {
        absFilename = relativeToAbs(relFilename, programDir);
    }
    free(absFilenameLink);
    return absFilename;
}

short checkFilenameInBlacklist(const char* filename, const char* API)
{
    char* absFilename = resolveSymbolicLink(filename);
    // fprintf(stderr, "absFilename: %s\n", absFilename);

    char configPath[PATH_MAX];
    strcpy(configPath, getenv("LOGGER_CONFIG_PATH"));
    if(configPath == NULL)
    {
        errquit("LOGGER_CONFIG_PATH is not set");
    }
    FILE* config = org_fopen(configPath, "r");
    if(config == NULL)
    {
        errquit("config file not found");
    }
    char* configDir = dirname(configPath);
    if(configDir == NULL)
    {
        errquit("dirname failed");
    }
    char targetAPIstartString[100];
    sprintf(targetAPIstartString, "BEGIN %s-blacklist", API);
    char line[PATH_MAX];
    while(fgets(line, PATH_MAX, config) != NULL)
    {
        if(strncmp(line, targetAPIstartString, strlen(targetAPIstartString)) == 0)
        {
            break;
        }
    }
    while(fgets(line, PATH_MAX, config) != NULL)
    {
        // fprintf(stderr, "line: %s\n", line);
        if(strncmp(line, "END", 3) == 0)
        {
            break;
        }
        short asterisk = 0;
        for(size_t i = 0; i < strlen(line); i++)
        {
            if(line[i] == '*')
            {
                asterisk = 1;
                break;
            }
        }
        line[strlen(line)-1] = '\0'; // remove the last '\n'
        if(asterisk)
        {
            int flags = FNM_PATHNAME | FNM_PERIOD; 
            // FNM_PATHNAME: match explicitly '/' in the filename, not by * or other special characters
            // FNM_PERIOD: match explicitly '.' at the beginning of the 
            int ret = fnmatch(line, absFilename, flags);
            if(ret == 0)
            {
                // fprintf(stderr, "fnmatch success, match: %s\n", line);
                fclose(config);
                free(absFilename);
                return 1;
            }
            else if(ret == FNM_NOMATCH)
            {
                continue;
            }
            else
            {
                errquit("fnmatch failed");
            }
        }
        else if(line[0] != '/')
        {
            char* absLine = relativeToAbs(line, configDir);
            // fprintf(stderr, "absLine: %s\n", absLine);
            if(strncmp(absLine, absFilename, strlen(absFilename)) == 0)
            {
                // fprintf(stderr, "match success, match: %s\n", line);
                fclose(config);
                free(absFilename);
                free(absLine);
                return 1;
            }
        }
        else
        {
            if(strncmp(line, absFilename, strlen(line)) == 0)
            {
                // fprintf(stderr, "match success, match: %s\n", line);
                free(absFilename);
                fclose(config);
                return 1;
            }
        }
    }
    fclose(config);
    return 0;
}

short checkPatternInBlacklist(const char* pattern, const char* API, short fullMatch)
{
    // fprintf(stderr, "pattern: %s\n", pattern);
    char configPath[PATH_MAX];
    strcpy(configPath, getenv("LOGGER_CONFIG_PATH"));
    if(configPath == NULL)
    {
        errquit("LOGGER_CONFIG_PATH is not set");
    }
    FILE* config = org_fopen(configPath, "r");
    if(config == NULL)
    {
        errquit("config file not found");
    }
    char* configDir = dirname(configPath);
    if(configDir == NULL)
    {
        errquit("dirname failed");
    }
    char targetAPIstartString[100];
    sprintf(targetAPIstartString, "BEGIN %s-blacklist", API);
    char line[PATH_MAX];
    while(fgets(line, PATH_MAX, config) != NULL)
    {
        if(strncmp(line, targetAPIstartString, strlen(targetAPIstartString)) == 0)
        {
            break;
        }
    }
    while(fgets(line, PATH_MAX, config) != NULL)
    {
        // fprintf(stderr, "line: %s\n", line);
        if(strncmp(line, "END", 3) == 0)
        {
            break;
        }
        line[strlen(line)-1] = '\0'; // remove the last '\n'
        if(fullMatch)
        {
            if(strncmp(line, pattern, strlen(line)) == 0)
            {
                // fprintf(stderr, "match success, match: %s\n", line);
                fclose(config);
                return 1;
            }
            else continue;
        }
        else
        {
            if(strstr(pattern, line) != NULL)
            {
                // fprintf(stderr, "match success, match: %s\n", line);
                fclose(config);
                return 1;
            }
            else continue;
        }
        
    }
    fclose(config);
    return 0;

}

void getFilenameFromFILE(FILE* file, char* filename)
{
    int fd = fileno(file);
    if(fd == -1)
    {
        errquit("fileno failed");
    }
    char path[PATH_MAX];
    sprintf(path, "/proc/self/fd/%d", fd);
    memset(filename, 0, PATH_MAX);
    if(readlink(path, filename, PATH_MAX-1) == -1) // readlink do not append null-terminating character
    {
        errquit("readlink failed");
    }
}

void changeToProgramDir()
{
    char* programDir = getenv("PROGRAM_DIR");
    if(programDir == NULL)
    {
        errquit("PROGRAM_DIR is not set");
    }
    if(chdir(programDir) == -1)
    {
        errquit("chdir failed");
    }
}

void changeToConfigDir()
{
    char configPath[PATH_MAX];
    strcpy(configPath, getenv("LOGGER_CONFIG_PATH"));
    if(configPath == NULL)
    {
        errquit("LOGGER_CONFIG_PATH is not set");
    }
    char* configDir = dirname(configPath);
    if(configDir == NULL)
    {
        errquit("dirname failed");
    }
    if(chdir(configDir) == -1)
    {
        errquit("chdir failed");
    }
}

FILE* openLogFile(const char* filename, const char* mode)
{
    char nameBuf[PATH_MAX];
    strcpy(nameBuf, filename);
    char* baseFilename = basename(nameBuf);
    baseFilename = strtok(baseFilename, ".");
    changeToConfigDir();
    char logPath[PATH_MAX];
    pid_t pid = getpid();
    sprintf(logPath, "%d-%s-%s.log", pid, baseFilename, mode);
    FILE* logfile = org_fopen(logPath, "a");
    return logfile;
}

FILE *fopen(const char *filename, const char *mode)
{
    changeToProgramDir();
    setOutputStream(stderr);
    
    getFunctionInStdio();
    
    FILE* ret;
    if(checkFilenameInBlacklist(filename, "open"))
    {
        ret = NULL;
        errno = EACCES;
    }
    else
    {
        ret = org_fopen(filename, mode);
    }
    {
        char* filenameStr = transformString(filename, 1);
        char* modeStr = transformString(mode, 1);
        fprintf(outputStream, "[logger] fopen:(%s, %s) = 0x%llx\n", filenameStr, modeStr, (void *)ret);
        free(filenameStr);
        free(modeStr);
    }
    fflush(outputStream);
    return ret;
}
size_t fwrite(const void *ptr, size_t size, size_t count, FILE *stream)
{
    char filename[PATH_MAX];
    getFilenameFromFILE(stream, filename);
    FILE* logfile = openLogFile(filename, "write");

    changeToProgramDir();
    setOutputStream(stderr);
    
    getFunctionInStdio();
    
    size_t ret;
    if(checkFilenameInBlacklist(filename, "write"))
    {
        ret = 0;
        errno = EACCES;
    }
    else
    {
        ret = org_fwrite(ptr, size, count, stream);
        char writeContent[size*count+1];
        strncpy(writeContent, (char*)ptr, size*count);
        writeContent[size*count] = '\0';
        char* writeStr = transformString(writeContent, 0);
        org_fwrite(writeStr, 1, strlen(writeStr), logfile);
        free(writeStr);
    }
    {
        char* inputStr = transformString((char*)ptr, 1);
        fprintf(outputStream, "[logger] fwrite:(%s, %lu, %lu, %p) = %lu\n", inputStr, size, count, (void *)stream, ret);
        free(inputStr);
    }
    fclose(logfile);
    return ret;
}
size_t fread(void *ptr, size_t size, size_t count, FILE *stream)
{
    char filename[PATH_MAX];
    getFilenameFromFILE(stream, filename);
    FILE* logfile = openLogFile(filename, "read");

    changeToProgramDir();
    setOutputStream(stderr);

    
    getFunctionInStdio();
    
    char* readContent = (char*)malloc(size*count+1);
    long int offset = ftell(stream);
    size_t myRet = org_fread(readContent, size, count, stream);
    size_t ret;
    readContent[size*myRet] = '\0';
    // TODO: check if readContent contain any substring that is in blacklist
    if(checkPatternInBlacklist(readContent, "read", 0))
    {
        ret = 0;
        errno = EACCES;
        fseek(stream, offset, SEEK_SET); // reset the file pointer because read is blocked
    }
    else
    {
        // char* readStr = transformString(readContent, 0);
        org_fwrite(readContent, size, myRet, logfile);

        memcpy(ptr, readContent, size*myRet); // copy the content to the original ptr
        ret = myRet;
    }

    fprintf(outputStream, "[logger] fread:(%p, %lu, %lu, %p) = %lu\n", ptr, size, count, (void *)stream, ret);
    fclose(logfile);
    return ret;
}
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    changeToProgramDir();
    setOutputStream(stderr);

    
    getFunctionInStdio();
    
    int ret;
    char* ip = inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
    if(checkPatternInBlacklist(ip, "connect", 1))
    {
        ret = -1;
        errno = ECONNREFUSED;
    }
    else
    {
        ret = org_connect(sockfd, addr, addrlen);
    }
    fprintf(outputStream, "[logger] connect:(%d, %s, %u) = %d\n", sockfd, ip, addrlen, ret);
    return ret;
}
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    changeToProgramDir();
    setOutputStream(stderr);

    getFunctionInStdio();
    int ret;
    if(checkPatternInBlacklist(node, "getaddrinfo", 1) )
    {
        ret = EAI_NONAME;
        errno = -EAI_NONAME;
    }
    else
    {
        ret = org_getaddrinfo(node, service, hints, res);
    }
    {
        char* nodeStr = transformString(node, 1);
        char* serviceStr = transformString(service, 1);
        fprintf(outputStream, "[logger] getaddrinfo:(%s, %s, %p, %p) = %d\n", nodeStr, serviceStr, (void *)hints, (void *)res, ret);
        free(nodeStr);
        free(serviceStr);
    }
    return ret;
}
int system(const char *command)
{
    changeToProgramDir();
    setOutputStream(stderr);

    getFunctionInStdio();
    int ret = org_system(command);
    {
        char* commandStr = transformString(command, 1);
        fprintf(outputStream, "[logger] system:(%s) = %d\n", commandStr, ret);
        free(commandStr);
    }
    return ret;
}