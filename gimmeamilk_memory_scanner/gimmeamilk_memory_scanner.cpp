
    
#include <windows.h>
#include <stdio.h>
 
#define IS_IN_SEARCH(mb,offset) (mb->searchmask[(offset)/8] & (1<<((offset)%8)))
#define REMOVE_FROM_SEARCH(mb,offset) mb->searchmask[(offset)/8] &= ~(1<<((offset)%8));
 
typedef struct _MEMBLOCK
{
    HANDLE hProc;
    unsigned char *addr;
    int size;
    unsigned char *buffer;
 
    unsigned char *searchmask;
    int matches;
    int data_size;
 
    struct _MEMBLOCK *next;
} MEMBLOCK;
 
typedef enum
{
    COND_UNCONDITIONAL,
    COND_EQUALS,
 
    COND_INCREASED,
    COND_DECREASED,
} SEARCH_CONDITION;
 
 
// Enable or disable a privilege in an access token
// source: http://msdn.microsoft.com/en-us/library/aa446619(VS.85).aspx
BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    )
{
        TOKEN_PRIVILEGES tp;
        LUID luid;
 
        if ( !LookupPrivilegeValue(
                        NULL,            // lookup privilege on local system
                        lpszPrivilege,   // privilege to lookup
                        &luid ) )        // receives LUID of privilege
        {
                printf("LookupPrivilegeValue error: %u\n", GetLastError() );
                return FALSE;
        }
 
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        if (bEnablePrivilege)
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        else
                tp.Privileges[0].Attributes = 0;
 
        // Enable the privilege or disable all privileges.
 
        if ( !AdjustTokenPrivileges(
                   hToken,
                   FALSE,
                   &tp,
                   sizeof(TOKEN_PRIVILEGES),
                   (PTOKEN_PRIVILEGES) NULL,
                   (PDWORD) NULL) )
        {
                  printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
                  return FALSE;
        }
 
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
 
        {
                  printf("The token does not have the specified privilege. \n");
                  return FALSE;
        }
 
        return TRUE;
}
 
MEMBLOCK* create_memblock (HANDLE hProc, MEMORY_BASIC_INFORMATION *meminfo, int data_size)
{
    MEMBLOCK *mb = malloc (sizeof(MEMBLOCK));
 
    if (mb)
    {
        mb->hProc = hProc;
        mb->addr = (unsigned char*)meminfo->BaseAddress;
        mb->size = meminfo->RegionSize;
        mb->buffer = (unsigned char*)malloc (meminfo->RegionSize);
        mb->searchmask =(unsigned char*) malloc (meminfo->RegionSize/8);
        memset (mb->searchmask, 0xff, meminfo->RegionSize/8);
        mb->matches = meminfo->RegionSize;
        mb->data_size = data_size;
        mb->next = NULL;
    }
 
    return mb;
}
 
void free_memblock (MEMBLOCK *mb)
{
    if (mb)
    {
        if (mb->buffer)
        {
            free (mb->buffer);
        }
 
        if (mb->searchmask)
        {
            free (mb->searchmask);
        }
 
        free (mb);
    }
}
 
 
void update_memblock (MEMBLOCK *mb, SEARCH_CONDITION condition, unsigned int val)
{
    static unsigned char tempbuf[128*1024];
    unsigned int bytes_left;
    unsigned int total_read;
    unsigned int bytes_to_read;
    unsigned int bytes_read;
 
    if (mb->matches > 0)
    {
        bytes_left = mb->size;
        total_read = 0;
        mb->matches = 0;
   
        while (bytes_left)
        {	
            bytes_to_read = (bytes_left > sizeof(tempbuf)) ? sizeof(tempbuf) : bytes_left;
            ReadProcessMemory (mb->hProc, mb->addr + total_read, tempbuf, bytes_to_read, (DWORD*)&bytes_read);
            if (bytes_read != bytes_to_read) break;
   
            if (condition == COND_UNCONDITIONAL)
            {
                memset (mb->searchmask + (total_read/8), 0xff, bytes_read/8);
                mb->matches += bytes_read;	
            }
            else
            {
                unsigned int offset;
   
                for (offset = 0; offset < bytes_read; offset += mb->data_size)
                {
                    if (IS_IN_SEARCH(mb,(total_read+offset)))
                    {
                        BOOL is_match = FALSE;
                        unsigned int temp_val;
                        unsigned int prev_val = 0;
   
                        switch (mb->data_size)
                        {
                            case 1:
                                temp_val = tempbuf[offset];
                                prev_val = *((unsigned char*)&mb->buffer[total_read+offset]);
                                break;
                            case 2:
                                temp_val = *((unsigned short*)&tempbuf[offset]);
                                prev_val = *((unsigned short*)&mb->buffer[total_read+offset]);
                                break;
                            case 4:
						  temp_val = *((unsigned int*)&tempbuf[offset]);
                                prev_val = *((unsigned int*)&mb->buffer[total_read+offset]);						  
                            default:
                                break;
                        }
   
                        switch (condition)
                        {
                            case COND_EQUALS:
                                is_match = (temp_val == val);
                                break;
                            case COND_INCREASED:
                                is_match = (temp_val > prev_val);
                                break;
                            case COND_DECREASED:
                                is_match = (temp_val < prev_val);
                                break;
                            default:
                                break;
                        }
   
                        if (is_match)
                        {
                            mb->matches++;
                        }
                        else
                        {
                            REMOVE_FROM_SEARCH(mb,(total_read+offset));
                        }
                    }
                }
            }
   
            memcpy (mb->buffer + total_read, tempbuf, bytes_read);
   
            bytes_left -= bytes_read;
            total_read += bytes_read;
        }
   
        mb->size = total_read;
    }
}
 
 
 
MEMBLOCK* create_scan (unsigned int pid, int data_size)
{
    MEMBLOCK *mb_list = NULL;
    MEMORY_BASIC_INFORMATION meminfo;
    unsigned char *addr = 0;
 
    HANDLE hProc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD error  = GetLastError();	
 
    if (hProc)
    {
        while (1)
        {
            if (VirtualQueryEx (hProc, addr, &meminfo, sizeof(meminfo)) == 0)
            {
                break;
            }
#define WRITABLE (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            if ((meminfo.State & MEM_COMMIT) && (meminfo.Protect & WRITABLE))
            {
                MEMBLOCK *mb = create_memblock (hProc, &meminfo, data_size);
                if (mb)
                {
                    mb->next = mb_list;
                    mb_list = mb;
                }
            }
            addr = (unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
        }
    }
    else
        printf ("Failed to open process - error - %d\r\n", error);
 
    return mb_list;
}
 
 
void free_scan (MEMBLOCK *mb_list)
{
    CloseHandle (mb_list->hProc);
 
    while (mb_list)
    {
        MEMBLOCK *mb = mb_list;
        mb_list = mb_list->next;
        free_memblock (mb);
    }
}
 
void update_scan (MEMBLOCK *mb_list, SEARCH_CONDITION condition, unsigned int val)
{
    MEMBLOCK *mb = mb_list;
    while (mb)
    {
        update_memblock (mb, condition, val);
        mb = mb->next;
    }
}
 
 
void dump_scan_info (MEMBLOCK *mb_list)
{
    MEMBLOCK *mb = mb_list;
 
    while (mb)
    {
        int i;
        printf ("0x%08x %d\r\n", mb->addr, mb->size);
 
        for (i = 0; i < mb->size; i++)
        {
            printf ("%02x", mb->buffer[i]);
        }
        printf ("\r\n");
 
        mb = mb->next;
    }
}
 
 
void poke (HANDLE hProc, int data_size, unsigned int addr, unsigned int val)
{
    if (WriteProcessMemory (hProc, (void*)addr, &val, data_size, NULL) == 0)
    {
        printf ("poke failed\r\n");
    }
}
 
unsigned int peek (HANDLE hProc, int data_size, unsigned int addr)
{
    unsigned int val = 0;
 
    if (ReadProcessMemory (hProc, (void*)addr, &val, data_size, NULL) == 0)
    {
        printf ("peek failed\r\n");
    }
 
    return val;
}
 
 
void print_matches (MEMBLOCK *mb_list)
{
     int offset;
    MEMBLOCK *mb = mb_list;
 
    while (mb)
    {
        for (offset = 0; offset < mb->size; offset += mb->data_size)
        {
            if (IS_IN_SEARCH(mb,offset))
            {
                unsigned int val = peek (mb->hProc, mb->data_size, (unsigned int)mb->addr + offset);
                printf ("0x%08x: 0x%08x (%d) \r\n", mb->addr + offset, val, val);
            }
        }
 
        mb = mb->next;
    }
}
 
 
int get_match_count (MEMBLOCK *mb_list)
{
    MEMBLOCK *mb = mb_list;
    int count = 0;
 
    while (mb)
    {
        count += mb->matches;
        mb = mb->next;
    }
 
    return count;
}
 
 
 
unsigned int str2int (char *s)
{
    int base = 10;
 
    if (s[0] == '0' && s[1] == 'x')
    {
        base = 16;
        s += 2;
    }
 
    return strtoul (s, NULL, base);
}
 
 
MEMBLOCK* ui_new_scan(void)
{
    MEMBLOCK *scan = NULL;
    DWORD pid;
    int data_size;
    unsigned int start_val;
    SEARCH_CONDITION start_cond;
    char s[20];
 
    while(1)
    {
        printf ("\r\nEnter the pid: ");
        fgets (s,sizeof(s),stdin);
        pid = str2int (s);
        printf ("\r\nEnter the data size: ");
        fgets (s,sizeof(s),stdin);
        data_size = str2int (s);
        printf ("\r\nEnter the start value, or 'u' for unknown: ");
        fgets (s,sizeof(s),stdin);
        if (s[0] == 'u')
        {
            start_cond = COND_UNCONDITIONAL;
            start_val = 0;
        }
        else
        {
            start_cond = COND_EQUALS;
            start_val = str2int (s);
        }
 
        scan = create_scan (pid, data_size);
        if (scan) break;
        printf ("\r\nInvalid scan");
    }
 
    update_scan (scan, start_cond, start_val);
    printf ("\r\n%d matches found\r\n", get_match_count(scan));
 
    return scan;
}
 
 
void ui_poke (HANDLE hProc, int data_size)
{
    unsigned int addr;
    unsigned int val;
    char s[20];
 
    printf ("Enter the address: ");
    fgets (s,sizeof(s),stdin);
    addr = str2int (s);
 
    printf ("\r\nEnter the value: ");
    fgets (s,sizeof(s),stdin);
    val = str2int (s);
    printf ("\r\n");
 
    poke (hProc, data_size, addr, val);
}
 
 
void ui_run_scan(void)
{
    unsigned int val;
    char s[20];
    MEMBLOCK *scan;
 
    scan = ui_new_scan();
 
    while (1)
    {
        printf ("\r\nEnter the next value or");
        printf ("\r\n[i] increased");
        printf ("\r\n[d] decreased");
        printf ("\r\n[m] print matches");
        printf ("\r\n[p] poke address");
        printf ("\r\n[n] new scan");
        printf ("\r\n[q] quit\r\n");
 
        fgets(s,sizeof(s),stdin);
        printf ("\r\n");
 
        switch (s[0])
        {
            case 'i':
                update_scan (scan, COND_INCREASED, 0);
                printf ("%d matches found\r\n", get_match_count(scan));
                break;
            case 'd':
                update_scan (scan, COND_DECREASED, 0);
                printf ("%d matches found\r\n", get_match_count(scan));
                break;
            case 'm':
                print_matches (scan);
                break;
            case 'p':
                ui_poke (scan->hProc, scan->data_size);
                break;
            case 'n':
                free_scan (scan);
                scan = ui_new_scan();
                break;
            case 'q':
                free_scan (scan);
                return;
            default:
                val = str2int (s);
                update_scan (scan, COND_EQUALS, val);
                printf ("%d matches found\r\n", get_match_count(scan));
                break;
        }
    }
}
 
 
 
 
int main (int argc, char *argv[])
{
    // get process handle
    HANDLE hProc = GetCurrentProcess();
 
    // get access token of process
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken))
         printf ("Failed to open access token");
 
    // set token privileges to SE_DEBUG_NAME to able to access OpenProcess() with PROCESS_ALL_ACCESS
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
        printf ("Failed to set debug privilege");
 
    ui_run_scan();
    return 0;
}
