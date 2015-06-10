#include <Windows.h>
#include <Ntsecapi.h>
#include <sddl.h>
#include <stdio.h>
#include <tchar.h>

#pragma comment(lib, "secur32.lib")

#define STATUS_SUCCESS 0

HANDLE g_hHeap;

BOOL
GetLogonSID (
   _In_ HANDLE hToken,
   _Out_ PSID *pLogonSid
   )
{
   BOOL bSuccess = FALSE;
   DWORD dwIndex;
   DWORD dwLength = 0;
   PTOKEN_GROUPS pTokenGroups = NULL;

   //
   // Get required buffer size and allocate the TOKEN_GROUPS buffer.
   //
   if (!GetTokenInformation(
      hToken,
      TokenGroups,
      (LPVOID)pTokenGroups,
      0,
      &dwLength
      ))
   {
      if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
      {
         fprintf(stderr, "GetTokenInformation failed (error: %u).\n", GetLastError());
         goto Error;
      }

      pTokenGroups = (PTOKEN_GROUPS)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwLength);
      if (pTokenGroups == NULL)
         goto Error;
   }

   //
   // Get the token group information from the access token.
   //
   if (!GetTokenInformation(
      hToken,
      TokenGroups,
      (LPVOID)pTokenGroups,
      dwLength,
      &dwLength
      ))
   {
      fprintf(stderr, "GetTokenInformation failed (error: %u).\n", GetLastError());
      goto Error;
   }

   //
   // Loop through the groups to find the logon SID.
   //
   for (dwIndex = 0; dwIndex < pTokenGroups->GroupCount; dwIndex++)
      if ((pTokenGroups->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
      {
         //
         // Found the logon SID: make a copy of it.
         //
         dwLength = GetLengthSid(pTokenGroups->Groups[dwIndex].Sid);
         *pLogonSid = (PSID)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwLength);
         if (*pLogonSid == NULL)
            goto Error;
         if (!CopySid(dwLength, *pLogonSid, pTokenGroups->Groups[dwIndex].Sid))
         {
            goto Error;
         }
         break;
      }

   bSuccess = TRUE;

Error:
   if (bSuccess == FALSE)
   {
      if (*pLogonSid != NULL)
         HeapFree(g_hHeap, 0, *pLogonSid);
   }

   if (pTokenGroups != NULL)
      HeapFree(g_hHeap, 0, pTokenGroups);

   return bSuccess;
}

//
// Set/Unset privilege.
//
BOOL
SetPrivilege (
   _In_ HANDLE hToken,
   _In_z_ LPCTSTR lpszPrivilege,
   _In_ BOOL bEnablePrivilege
   )
{
   TOKEN_PRIVILEGES tp;
   LUID luid;

   if (!LookupPrivilegeValue(
      NULL,             // lookup privilege on local system
      lpszPrivilege,    // privilege to lookup 
      &luid))           // receives LUID of privilege
   {
      fprintf(stderr, "LookupPrivilegeValue failed (error: %u).\n", GetLastError());
      return FALSE;
   }

   tp.PrivilegeCount = 1;
   tp.Privileges[0].Luid = luid;
   if (bEnablePrivilege)
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
   else
      tp.Privileges[0].Attributes = 0;

   //
   // Enable the privilege or disable all privileges.
   //
   if (!AdjustTokenPrivileges(
      hToken,
      FALSE,
      &tp,
      sizeof(TOKEN_PRIVILEGES),
      (PTOKEN_PRIVILEGES)NULL,
      (PDWORD)NULL))
   {
      fprintf(stderr, "AdjustTokenPrivileges failed (error: %u).\n", GetLastError());
      return FALSE;
   }
   else
   {
      if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
      {
         fprintf(stderr, "The token does not have the specified privilege (%S).\n", lpszPrivilege);
         return FALSE;
      }
      else
      {
         printf("AdjustTokenPrivileges (%S): OK\n", lpszPrivilege);
      }
   }

   return TRUE;
}

VOID
InitLsaString (
   _Out_ PLSA_STRING DestinationString,
   _In_z_ LPSTR szSourceString
   )
{
   USHORT StringSize;

   StringSize = (USHORT)strlen(szSourceString);

   DestinationString->Length = StringSize;
   DestinationString->MaximumLength = StringSize + sizeof(CHAR);
   DestinationString->Buffer = (PCHAR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, DestinationString->MaximumLength);

   if (DestinationString->Buffer)
   {
      memcpy(DestinationString->Buffer, szSourceString, DestinationString->Length);
   }
   else
   {
      memset(DestinationString, 0, sizeof(LSA_STRING));
   }
}

PBYTE
InitUnicodeString (
   _Out_ PUNICODE_STRING DestinationString,
   _In_z_ LPWSTR szSourceString,
   _In_ PBYTE pbDestinationBuffer
   )
{
   USHORT StringSize;

   StringSize = (USHORT)wcslen(szSourceString) * sizeof(WCHAR);
   memcpy(pbDestinationBuffer, szSourceString, StringSize);

   DestinationString->Length = StringSize;
   DestinationString->MaximumLength = StringSize + sizeof(WCHAR);
   DestinationString->Buffer = (PWSTR)pbDestinationBuffer;

   return (PBYTE)pbDestinationBuffer + StringSize + sizeof(WCHAR);
}

int
_tmain (
   _In_ int argc,
   _In_ TCHAR *argv[]
   )
{
   BOOL bResult;
   NTSTATUS Status;
   NTSTATUS SubStatus;

   HANDLE hLsa = NULL;
   HANDLE hProcess = NULL;
   HANDLE hToken = NULL;
   HANDLE hTokenS4U = NULL;

   LSA_STRING Msv1_0Name = { 0 };
   LSA_STRING OriginName = { 0 };
   PMSV1_0_S4U_LOGON pS4uLogon = NULL;
   TOKEN_SOURCE TokenSource;
   ULONG ulAuthenticationPackage;
   DWORD dwMessageLength;

   PBYTE pbPosition;

   PROCESS_INFORMATION pi = { 0 };
   STARTUPINFO si = { 0 };

   PTOKEN_GROUPS pGroups = NULL;
   PSID pLogonSid = NULL;
   PSID pExtraSid = NULL;

   PVOID pvProfile = NULL;
   DWORD dwProfile = 0;
   LUID logonId = { 0 };
   QUOTA_LIMITS quotaLimits;

   LPTSTR szCommandLine = NULL;
   LPTSTR szSrcCommandLine = TEXT("%systemroot%\\system32\\cmd.exe");
   LPTSTR szDomain = NULL;
   LPTSTR szUsername = NULL;
   TCHAR seps[] = TEXT("\\");
   TCHAR *next_token = NULL;

   g_hHeap = GetProcessHeap();

   if (argc < 2)
   {
      fprintf(stderr, "Usage:\n   s4u.exe Domain\\Username [Extra SID]\n\n");
      goto End;
   }

   //
   // Get DOMAIN and USERNAME from command line.
   //
   szDomain = _tcstok_s(argv[1], seps, &next_token);
   if (szDomain == NULL)
   {
      fprintf(stderr, "Unable to parse command line.\n");
      goto End;
   }

   szUsername = _tcstok_s(NULL, seps, &next_token);
   if (szUsername == NULL)
   {
      fprintf(stderr, "Unable to parse command line.\n");
      goto End;
   }

   //
   // Activate the TCB privilege
   //
   hProcess = GetCurrentProcess();
   OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
   if (!SetPrivilege(hToken, SE_TCB_NAME, TRUE))
   {
      goto End;
   }

   //
   // Get logon SID
   //
   if (!GetLogonSID(hToken, &pLogonSid))
   {
      fprintf(stderr, "Unable to find logon SID.\n");
      goto End;
   }

   //
   // Connect (Untrusted) to LSA
   //
   Status = LsaConnectUntrusted(&hLsa);
   if (Status!=STATUS_SUCCESS)
   {
      fprintf(stderr, "LsaConnectUntrusted failed (error 0x%x).", Status);
      hLsa = NULL;
      goto End;
   }

   //
   // Lookup for the MSV1_0 authentication package (NTLMSSP)
   //
   InitLsaString(&Msv1_0Name, MSV1_0_PACKAGE_NAME);
   Status = LsaLookupAuthenticationPackage(hLsa, &Msv1_0Name, &ulAuthenticationPackage);
   if (Status!=STATUS_SUCCESS)
   {
      fprintf(stderr, "LsaLookupAuthenticationPackage failed (error 0x%x).", Status);
      hLsa = NULL;
      goto End;
   }

   //
   // Create MSV1_0_S4U_LOGON structure
   //
   dwMessageLength = (DWORD)sizeof(MSV1_0_S4U_LOGON) + (2 + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR);
   pS4uLogon = (PMSV1_0_S4U_LOGON)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwMessageLength);
   if (pS4uLogon == NULL)
   {
      fprintf(stderr, "HeapAlloc failed (error %u).", GetLastError());
      goto End;
   }

   pS4uLogon->MessageType = MsV1_0S4ULogon;
   pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
   pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
   pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);

   //
   // Misc
   //
   strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "S4UWin");
   InitLsaString(&OriginName, "S4U for Windows");
   AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

   //
   // Add extra SID to token.
   //
   // If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
   //
   pGroups = (PTOKEN_GROUPS)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, sizeof(TOKEN_GROUPS) + 2*sizeof(SID_AND_ATTRIBUTES));
   if (pGroups == NULL)
   {
      fprintf(stderr, "HeapAlloc failed (error %u).", GetLastError());
      goto End;
   }

   pGroups->GroupCount = 1;
   pGroups->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
   pGroups->Groups[0].Sid = pLogonSid;

   //
   // If an extra SID is specified to command line, add it to the pGroups structure.
   //
   if (argc==3)
   {
      bResult = ConvertStringSidToSid(argv[2], &pExtraSid);

      if (bResult == TRUE)
      {
         pGroups->GroupCount = 2;
         pGroups->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
         pGroups->Groups[1].Sid = pExtraSid;
      }
      else
      {
         fprintf(stderr, "Unable to convert SID (error %u).", GetLastError());
      }
   }

   //
   // Call LSA
   //
   Status = LsaLogonUser(
      hLsa,
      &OriginName,
      Network,                // Or Batch
      ulAuthenticationPackage,
      pS4uLogon,
      dwMessageLength,
      pGroups,                // LocalGroups
      &TokenSource,           // SourceContext
      &pvProfile,
      &dwProfile,
      &logonId,
      &hTokenS4U,
      &quotaLimits,
      &SubStatus
      );
   if (Status!=STATUS_SUCCESS)
   {
      printf("LsaLogonUser failed (error 0x%x).\n", Status);
      goto End;
   }

   printf("LsaLogonUser: OK, LogonId: 0x%x-0x%x\n", logonId.HighPart, logonId.LowPart);

   //
   // Create process with S4U token.
   //
   si.cb = sizeof(STARTUPINFO);
   si.lpDesktop = TEXT("winsta0\\default");

   //
   // Warning: szCommandLine parameter of CreateProcessAsUser() must be writable
   //
   szCommandLine = (LPTSTR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, MAX_PATH * sizeof(TCHAR));
   if (szCommandLine == NULL)
   {
      fprintf(stderr, "HeapAlloc failed (error %u).", GetLastError());
      goto End;
   }

   if (ExpandEnvironmentStrings(szSrcCommandLine, szCommandLine, MAX_PATH) == 0)
   {
      fprintf(stderr, "ExpandEnvironmentStrings failed (error %u).", GetLastError());
      goto End;
   }

   //
   // CreateProcessAsUser required SeAssignPrimaryTokenPrivilege but no need to be activated.
   //
   bResult = CreateProcessAsUser(
      hTokenS4U,
      NULL,
      szCommandLine,
      NULL,
      NULL,
      FALSE,
      NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
      NULL,
      TEXT("c:\\"),
      &si,
      &pi
      );
   if (bResult == FALSE)
   {
      printf("CreateProcessAsUser failed (error %u).\n", GetLastError());
      goto End;
   }

End:
   //
   // Free resources
   //
   if (Msv1_0Name.Buffer)
      HeapFree(g_hHeap, 0, Msv1_0Name.Buffer);
   if (OriginName.Buffer)
      HeapFree(g_hHeap, 0, OriginName.Buffer);
   if (pLogonSid)
      HeapFree(g_hHeap, 0, pLogonSid);
   if (pExtraSid)
      LocalFree(pExtraSid);
   if (pS4uLogon)
      HeapFree(g_hHeap, 0, pS4uLogon);
   if (pGroups)
      HeapFree(g_hHeap, 0, pGroups);
   if (pvProfile)
      LsaFreeReturnBuffer(pvProfile);
   if (hLsa)
      LsaClose(hLsa);
   if (hToken)
      CloseHandle(hToken);
   if (hTokenS4U)
      CloseHandle(hTokenS4U);
   if (pi.hProcess)
      CloseHandle(pi.hProcess);
   if (pi.hThread)
      CloseHandle(pi.hThread);

   return EXIT_SUCCESS;
}