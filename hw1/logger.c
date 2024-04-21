#include <stdio.h> 
#include <stdlib.h>
#include <libgen.h>

#include <errno.h>

#include <string.h>

const int debug = 0;

void errUsage()
{
    fprintf(stderr, "Usage: ./logger config.txt [-o file] [-p sopath] command [arg1 arg2 ...]\n");
    exit(1);
}

int main(int argc, char** argv)
{
    if(argc < 3)
    {
        errUsage();
    }
    char* config = argv[1];
    if(strcmp(config, "config.txt") != 0)
    {
        errUsage();
    }
    char* outputPath = NULL;
    char* soPath = NULL;
    char* command = NULL;
    char** commandArgs = NULL;
    int commandArgCount = 0;
    for(int i = 2; i < argc; i++)
    {
        if(strcmp(argv[i], "-o") == 0)
        {
            if(i+1 >= argc || outputPath != NULL)
            {
                errUsage();
            }
            i++;
            outputPath = argv[i];
        }
        else if(strcmp(argv[i], "-p") == 0)
        {
            if(i+1 >= argc || soPath != NULL)
            {
                errUsage();
            }
            i++;
            soPath = argv[i];
        }
        else
        {
            command = argv[i];
            if(i+1 >= argc)
            {
                commandArgs = NULL;
                commandArgCount = 0;
            }
            else
            {
                commandArgs = (argv + i + 1);
                commandArgCount = argc - i - 1; 
            }
            break;
        }
    }
    if(command == NULL)
    {
        errUsage();
    }
    // print out the arguments
    if(debug)
    {
        printf("config: %s\n", config);
        if(outputPath != NULL)
        {
            printf("outputPath: %s\n", outputPath);
        }
        else 
        {
            printf("outputPath: stderr\n");
        }
        if(soPath != NULL)
        {
            printf("soPath: %s\n", soPath);
        }
        else
        {
            printf("soPath: ./liblogger.so\n");
        }
        printf("command: %s\n", command);
        for(int i = 0; i < commandArgCount; i++)
        {
            printf("commandArgs[%d]: %s\n", i, commandArgs[i]);
        }
    }

    char commandStr[4096];
    char absoluteConfigPath[1024];
    char absoluteProgramPath[1024];
    char* absoluteProgramDir;
    realpath("./config.txt", absoluteConfigPath);
    realpath(command, absoluteProgramPath);
    absoluteProgramDir = dirname(absoluteProgramPath);
    
    sprintf(commandStr, "PROGRAM_DIR=\"%s\" LOGGER_CONFIG_PATH=\"%s\" LD_PRELOAD=\"%s\" %s", absoluteProgramDir, absoluteConfigPath ,soPath == NULL ? "./liblogger.so" : soPath, command);
    for(int i = 0; i < commandArgCount; i++)
    {
        strcat(commandStr, " ");
        strcat(commandStr, commandArgs[i]);
    }
    if(outputPath != NULL)
    {
        strcat(commandStr, " 2>\"");
        strcat(commandStr, outputPath);
        strcat(commandStr, "\"");
    }
    if(debug)
    {
        printf("commandStr: %s\n", commandStr);
    }
    system(commandStr);


}