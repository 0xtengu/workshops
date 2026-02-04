#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Target program that reads environment variables
// We'll inject and steal these values

int main()
{
    printf("Target process started (PID: %d)\n", getpid());
    printf("Waiting for injection...\n\n");
    
    // Simulate a program that uses environment variables
    for (int i = 0; i < 20; i++)
    {
        printf("Checking environment variables...\n");
        
        const char *api_key = getenv("API_KEY");
        const char *db_pass = getenv("DB_PASSWORD");
        const char *aws_secret = getenv("AWS_SECRET");
        
        if (api_key)
            printf("  API_KEY is set\n");
        if (db_pass)
            printf("  DB_PASSWORD is set\n");
        if (aws_secret)
            printf("  AWS_SECRET is set\n");
        
        sleep(2);
    }
    
    return 0;
}