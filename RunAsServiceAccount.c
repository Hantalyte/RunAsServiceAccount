#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <Windows.h>
#include <LM.h>
#include <accctrl.h>
#include <AclAPI.h>
#include <winternl.h>
#define _NTDEF_ 
#include <NTSecAPI.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ntdll.lib")

#pragma warning(disable : 6011)

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _SidInfo {
	wchar_t* wszName;
	wchar_t* wszDomain;
	SID_NAME_USE SidType;
} SidInfo;

typedef struct _NameInfo {
	PSID pSid;
	wchar_t* wszDomain;
	SID_NAME_USE SidType;
} NameInfo;

typedef struct _POLICY_PRIVILEGE_DEFINITION
{
	LSA_UNICODE_STRING Name;
	LUID LocalValue;
} POLICY_PRIVILEGE_DEFINITION, * PPOLICY_PRIVILEGE_DEFINITION;

// https://ntdoc.m417z.com/ntcreatetoken
typedef NTSYSAPI
NTSTATUS
(NTAPI* _NtCreateToken)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN OPTIONAL PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN OPTIONAL PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
	);

// https://ntdoc.m417z.com/rtlcreateservicesid
typedef NTSYSAPI
NTSTATUS
(NTAPI* _RtlCreateServiceSid)(
	IN PUNICODE_STRING ServiceName,
	OUT OPTIONAL PSID ServiceSid,
	IN OUT PULONG ServiceSidLength
	);

// https://stackoverflow.com/questions/6642945/enumerating-privileges-local-security-policy
typedef NTSYSAPI
NTSTATUS
(NTAPI* _LsaEnumeratePrivileges)(
	IN LSA_HANDLE PolicyHandle,
	IN OUT PLSA_ENUMERATION_HANDLE EnumerationContext,
	OUT PVOID *Buffer,
	IN ULONG PreferedMaximumLength,
	OUT PULONG CountReturned
	);

wchar_t wszTempAcctName[21] = { 0 };

void ErrorExit(wchar_t* wszFunction, DWORD dwErrorCode) {

	if (wcslen(wszTempAcctName) != 0) { RevertToSelf(); NetUserDel(NULL, wszTempAcctName); }

	wchar_t* wszErrorMsg;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, dwErrorCode, LANG_USER_DEFAULT, (LPWSTR)&wszErrorMsg, 0, NULL);

	DWORD dwNumDigits = 0;
	DWORD dwErrorCodeCopy = dwErrorCode;
	do {
		dwErrorCodeCopy /= 10;
		dwNumDigits++;
	} while (dwErrorCodeCopy != 0);
	
	size_t cbNumWChars = wcslen(wszErrorMsg) + wcslen(wszFunction) + strlen(" failed with error : ") + dwNumDigits;
	wchar_t* wszDisplayMsg = malloc(cbNumWChars * sizeof(wchar_t));
	swprintf(wszDisplayMsg, cbNumWChars, L"%ws failed with error %lu: %ws", wszFunction, dwErrorCode, wszErrorMsg);

	MessageBoxW(NULL, wszDisplayMsg, L"Error", MB_OK);
	LocalFree(wszErrorMsg);
	free(wszDisplayMsg);
	ExitProcess(dwErrorCode);
}

#define LsaStatusErrorExit(FunctionName, LsaStatusCode)  ErrorExit(FunctionName, LsaNtStatusToWinError(LsaStatusCode))

void NtStatusErrorExit(wchar_t* wszFunction, NTSTATUS StatusCode) {

	if (wcslen(wszTempAcctName) != 0) { RevertToSelf(); NetUserDel(NULL, wszTempAcctName); }

	wchar_t* wszErrorMsg;
	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		hNtdll, StatusCode, LANG_USER_DEFAULT, (LPWSTR)&wszErrorMsg, 0, NULL);

	long lNumDigits = 0;
	NTSTATUS StatusCodeCopy = StatusCode;
	do { 
		StatusCodeCopy /= 16;
		lNumDigits++;
	} while (StatusCodeCopy != 0);

	size_t cbNumWChars = wcslen(wszErrorMsg) + wcslen(wszFunction) + strlen(" failed with error code 0x: ") + lNumDigits;
	wchar_t* wszDisplayMsg = malloc(cbNumWChars * sizeof(wchar_t));
	swprintf(wszDisplayMsg, cbNumWChars, L"%ws failed with error code 0x%X: %ws", wszFunction, StatusCode, wszErrorMsg);

	MessageBoxW(NULL, wszDisplayMsg, L"Error", MB_OK);
	LocalFree(wszErrorMsg);
	free(wszDisplayMsg);
	ExitProcess(StatusCode);
}

SidInfo* GetSidInfo(PSID Sid) {
	DWORD dwNameSize = 0;
	DWORD dwDomainSize = 0;
	SidInfo* SidData = malloc(sizeof(SidInfo));

	LookupAccountSidW(NULL, Sid, NULL, &dwNameSize, NULL, &dwDomainSize, &SidData->SidType);
	SidData->wszName = malloc(dwNameSize * sizeof(wchar_t));
	SidData->wszDomain = malloc(dwDomainSize * sizeof(wchar_t));

	if (!LookupAccountSidW(NULL, Sid, SidData->wszName, &dwNameSize, SidData->wszDomain, &dwDomainSize, &SidData->SidType)) {
		ErrorExit(L"LookupAccountSid", GetLastError());
	}

	// Remember to free the memory of wszName, wszDomain, and the returned struct after usage!
	return SidData;
}

NameInfo* GetNameInfo(wchar_t* wszName) {
	DWORD dwSidSize = 0;
	DWORD dwDomainSize = 0;
	NameInfo* NameData = malloc(sizeof(NameInfo));

	LookupAccountNameW(NULL, wszName, NULL, &dwSidSize, NULL, &dwDomainSize, &NameData->SidType);
	NameData->pSid = malloc(dwSidSize);
	NameData->wszDomain = malloc(dwDomainSize * sizeof(wchar_t));

	if (!LookupAccountNameW(NULL, wszName, NameData->pSid, &dwSidSize, NameData->wszDomain, &dwDomainSize, &NameData->SidType)) {
		ErrorExit(L"LookupAccountNameW", GetLastError());
	}

	// Remember to free the memory of pSid, wszDomain, and the returned struct after usage!
	return NameData;
}

void EnablePrivileges(LPCWSTR awszPrivileges[], DWORD dwCount) {
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

	DWORD dwSize = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * (dwCount - 1);
	TOKEN_PRIVILEGES* TokenPrivs = malloc(dwSize);
	TokenPrivs->PrivilegeCount = dwCount;
	for (DWORD i = 0; i < dwCount; i++) {
		if (!LookupPrivilegeValueW(NULL, awszPrivileges[i], &TokenPrivs->Privileges[i].Luid)) {
			ErrorExit(L"LookupPrivilegeValue", GetLastError());
		}
		TokenPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, TokenPrivs, 0, NULL, NULL)) {
		ErrorExit(L"AdjustTokenPrivileges", GetLastError());
	}
	CloseHandle(hToken);
}

int main()
{
	/* How the Program Works:
	* Service accounts are tricky, as it is not feasible to call LogonUserW for them.
	* Therefore, in order to create a process as one, one must create a new token and start a process with this.
	* This involves utilizing the undocumented function "NtCreateToken" and "CreateProcessWithTokenW."
	* However, "NtCreateToken" requires the caller to have the privilege "SeCreateTokenPrivilege," which is not normally available.
	* To solve this, a temporary account is created with this privilege and the program then impersonates this account.
	* The SID of the service account is obtained via the undocumented function "RtlCreateServiceSid."
	* One interesting fact is that this function can provide the SID of a non-exist service.
	*/

	NET_API_STATUS NetApiStatus;
	NTSTATUS LsaStatus;
	NTSTATUS NtStatus;
	DWORD dwRes;

	printf("RunAsServiceAccount.exe\n");
	printf("Developed by Hantalyte\n");
	printf("-------------------------\n");

	// Step #1: Get the Service's Name

	wchar_t wszSvcName[SNLEN];
	wprintf(L"Enter Service Name: ");
	fgetws(wszSvcName, SNLEN, stdin);
	wszSvcName[wcslen(wszSvcName) - 1] = '\0'; // Remove the carriage return character

	// Step #2: Create a Temporary Account

	wchar_t awcWChars[] = { L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9',
		L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I', L'J', L'K', L'L', L'M',
		L'N', L'O', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z' };

	wchar_t wszTempAcctPass[21] = { 0 };
	srand(time(NULL));
	for (int i = 0; i < 20; i++) {
		wszTempAcctName[i] = awcWChars[rand() % 36];
		wszTempAcctPass[i] = awcWChars[rand() % 36];
	}

	USER_INFO_1 UserInfo;
	UserInfo.usri1_name = wszTempAcctName;
	UserInfo.usri1_password = wszTempAcctPass;
	UserInfo.usri1_priv = USER_PRIV_USER;
	UserInfo.usri1_home_dir = NULL;
	UserInfo.usri1_comment = NULL;
	UserInfo.usri1_flags = UF_SCRIPT;
	UserInfo.usri1_script_path = NULL;
	NetApiStatus = NetUserAdd(NULL, 1, (LPBYTE)&UserInfo, NULL);
	if (NetApiStatus != NERR_Success) { ErrorExit(L"NetUserAdd", NetApiStatus); }

	// Step #3: Grant the Account the Required Privileges
	// Step 3A: Make the Account an Administrator

	PSID pAdminSid = NULL;
	SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;
	AllocateAndInitializeSid(&NtAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &pAdminSid);
	SidInfo* AdminSidInfo = GetSidInfo(pAdminSid);

	LOCALGROUP_MEMBERS_INFO_3 NewMember;
	NewMember.lgrmi3_domainandname = wszTempAcctName;
	NetApiStatus = NetLocalGroupAddMembers(NULL, AdminSidInfo->wszName, 3, (LPBYTE)&NewMember, 1);
	if (NetApiStatus != NERR_Success) { ErrorExit(L"NetLocalGroupAddMembers", NetApiStatus); }
	free(AdminSidInfo->wszName);
	free(AdminSidInfo->wszDomain);
	free(AdminSidInfo);
	// Note: AdminSid is *not* freed here because it will be used later


	// Step 3B: Give the Account Additional Rights

	LSA_UNICODE_STRING aRequiredPrivs[4] = { 0 };
	aRequiredPrivs[0].Buffer = SE_DEBUG_NAME;
	aRequiredPrivs[0].Length = wcslen(SE_DEBUG_NAME) * sizeof(wchar_t);
	aRequiredPrivs[0].MaximumLength = (wcslen(SE_DEBUG_NAME) + 1) * sizeof(wchar_t);
	aRequiredPrivs[1].Buffer = SE_IMPERSONATE_NAME;
	aRequiredPrivs[1].Length = wcslen(SE_IMPERSONATE_NAME) * sizeof(wchar_t);
	aRequiredPrivs[1].MaximumLength = (wcslen(SE_IMPERSONATE_NAME) + 1) * sizeof(wchar_t);
	aRequiredPrivs[2].Buffer = SE_NETWORK_LOGON_NAME;
	aRequiredPrivs[2].Length = wcslen(SE_NETWORK_LOGON_NAME) * sizeof(wchar_t);
	aRequiredPrivs[2].MaximumLength = (wcslen(SE_NETWORK_LOGON_NAME) + 1) * sizeof(wchar_t);
	aRequiredPrivs[3].Buffer = SE_CREATE_TOKEN_NAME;
	aRequiredPrivs[3].Length = wcslen(SE_CREATE_TOKEN_NAME) * sizeof(wchar_t);
	aRequiredPrivs[3].MaximumLength = (wcslen(SE_CREATE_TOKEN_NAME) + 1) * sizeof(wchar_t);

	LSA_OBJECT_ATTRIBUTES LsaObjAttrs = { 0 };
	LSA_HANDLE hPolicy;
	LsaStatus = LsaOpenPolicy(NULL, &LsaObjAttrs, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &hPolicy);
	if (LsaStatus != STATUS_SUCCESS) { LsaStatusErrorExit(L"LsaOpenPolicy", LsaStatus); }

	NameInfo* TempAcctInfo = GetNameInfo(wszTempAcctName);
	LsaStatus = LsaAddAccountRights(hPolicy, TempAcctInfo->pSid, &aRequiredPrivs, 4);
	if (LsaStatus != STATUS_SUCCESS) { LsaStatusErrorExit(L"LsaAddAccountRights", LsaStatus); }
	LsaClose(hPolicy);

	// Step #4: Impersonate the Newly-Created Account and Enable All Necessary Privileges

	HANDLE hAcctToken;
	if (!LogonUserW(wszTempAcctName, TempAcctInfo->wszDomain, wszTempAcctPass,
		LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &hAcctToken)) {
		ErrorExit(L"LogonUser", GetLastError());
	}
	if (!ImpersonateLoggedOnUser(hAcctToken)) { ErrorExit(L"ImpersonateLoggedOnUser", GetLastError()); }

	CloseHandle(hAcctToken);
	free(TempAcctInfo->pSid);
	free(TempAcctInfo->wszDomain);
	free(TempAcctInfo);
	SecureZeroMemory(wszTempAcctPass, sizeof(wszTempAcctPass));

	wchar_t* awszPrivs[] = { SE_DEBUG_NAME, SE_CREATE_TOKEN_NAME };
	EnablePrivileges(awszPrivs, 2);

	// Step #5: Import the Necessary Undocumented Functions and Retrieve the Service Account's SID

	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (!hNtdll) { ErrorExit(L"LoadLibrary", GetLastError()); }

	_NtCreateToken NtCreateToken = (_NtCreateToken)GetProcAddress(hNtdll, "NtCreateToken");
	if (!NtCreateToken) { ErrorExit(L"GetProcAddress", GetLastError()); }

	_RtlCreateServiceSid RtlCreateServiceSid = (_RtlCreateServiceSid)GetProcAddress(hNtdll, "RtlCreateServiceSid");
	if (!RtlCreateServiceSid) { ErrorExit(L"GetProcAddress", GetLastError()); }
	FreeLibrary(hNtdll);

	HMODULE hAdvapi32 = LoadLibraryW(L"Advapi32.dll");
	if (!hAdvapi32) { ErrorExit(L"LoadLibraryA", GetLastError()); }
	_LsaEnumeratePrivileges LsaEnumeratePrivileges = (_LsaEnumeratePrivileges)GetProcAddress(hAdvapi32, "LsaEnumeratePrivileges");
	if (!LsaEnumeratePrivileges) { ErrorExit(L"GetProcAddress", GetLastError()); }
	FreeLibrary(hAdvapi32);

	UNICODE_STRING usSvcName;
	RtlInitUnicodeString(&usSvcName, wszSvcName);
	DWORD dwSidLen = 0;
	RtlCreateServiceSid(&usSvcName, NULL, &dwSidLen);
	PSID SvcSid = malloc(dwSidLen);
	NtStatus = RtlCreateServiceSid(&usSvcName, SvcSid, &dwSidLen);
	if (NT_ERROR(NtStatus)) { NtStatusErrorExit(L"RtlCreateServiceSid", NtStatus); }

	// Step #6: Create the Token and Launch the Process
	// Step 6A: Establish Privileges for the Token

	LSA_ENUMERATION_HANDLE ulEnumContext = 0;
	POLICY_PRIVILEGE_DEFINITION *aPrivs;
	DWORD dwReturned = 0;

	hPolicy = NULL;
	LsaStatus = LsaOpenPolicy(NULL, &LsaObjAttrs, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy);
	if (LsaStatus != STATUS_SUCCESS) { LsaStatusErrorExit(L"LsaOpenPolicy", LsaStatus); }
	LsaStatus = LsaEnumeratePrivileges(hPolicy, &ulEnumContext, &aPrivs, MAX_PREFERRED_LENGTH, &dwReturned);
	if (LsaStatus != STATUS_SUCCESS) { LsaStatusErrorExit(L"LsaEnumeratePrivileges", LsaStatus); }
	LsaClose(hPolicy);

	DWORD dwTokenPrivsSize = sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * (dwReturned - 1));
	PTOKEN_PRIVILEGES pNewTokenPrivs = malloc(dwTokenPrivsSize);
	pNewTokenPrivs->PrivilegeCount = dwReturned;

	for (DWORD i = 0; i < dwReturned; i++) {
		if (!LookupPrivilegeValueW(NULL, aPrivs[i].Name.Buffer, &pNewTokenPrivs->Privileges[i].Luid)) {
			ErrorExit(L"LookupPrivilegeValue", GetLastError());
		}
		pNewTokenPrivs->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
	}
	
	// Step 6B: Create the DACL for the Token

	TOKEN_DEFAULT_DACL NewTokenDACL;
	EXPLICIT_ACCESSW aExplicitEntries[3];
	memset(aExplicitEntries, 0, 3 * sizeof(EXPLICIT_ACCESSW));

	aExplicitEntries[0].grfAccessPermissions = GENERIC_ALL;
	aExplicitEntries[0].grfAccessMode = SET_ACCESS;
	aExplicitEntries[0].grfInheritance = NO_INHERITANCE;
	aExplicitEntries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	aExplicitEntries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
	aExplicitEntries[0].Trustee.ptstrName = SvcSid;

	PSID pSystemSid;
	AllocateAndInitializeSid(&NtAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &pSystemSid);
	aExplicitEntries[1].grfAccessPermissions = GENERIC_ALL;
	aExplicitEntries[1].grfAccessMode = SET_ACCESS;
	aExplicitEntries[1].grfInheritance = NO_INHERITANCE;
	aExplicitEntries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	aExplicitEntries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	aExplicitEntries[1].Trustee.ptstrName = (LPWCH)pSystemSid;

	aExplicitEntries[2].grfAccessPermissions = GENERIC_READ;
	aExplicitEntries[2].grfAccessMode = SET_ACCESS;
	aExplicitEntries[2].grfInheritance = NO_INHERITANCE;
	aExplicitEntries[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	aExplicitEntries[2].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	aExplicitEntries[2].Trustee.ptstrName = (LPWCH)pAdminSid;

	dwRes = SetEntriesInAclW(3, aExplicitEntries, NULL, &NewTokenDACL.DefaultDacl);
	if (dwRes != ERROR_SUCCESS) { ErrorExit(L"SetEntriesInAclW", dwRes); }
	
	// Step 6C: Establish Groups for the Token

	DWORD dwNumGroups = 10;
	DWORD dwGroupsSize = sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES) * (dwNumGroups - 1);
	PTOKEN_GROUPS pNewTokenGroups = malloc(dwGroupsSize);
	pNewTokenGroups->GroupCount = dwNumGroups;

	/* Enables the Following Groups:
	* 1. System Mandatory Label
	* 2. Everyone
	* 3. Users
	* 4. SERVICE
	* 5. CONSOLE LOGON
	* 6. Authenticated Users
	* 7. This Organization
	* 8. Local
	* 9. Administrators
	* 10. SYSTEM
	*/

	SID_IDENTIFIER_AUTHORITY WorldAuth = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY LocalAuth = SECURITY_LOCAL_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SysMandLabelAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;

	PSID pSysIntegrityLabelSid = NULL;
	AllocateAndInitializeSid(&SysMandLabelAuth, 1, SECURITY_MANDATORY_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &pSysIntegrityLabelSid);
	PSID pEveryoneSid = NULL;
	AllocateAndInitializeSid(&WorldAuth, 1, SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0, &pEveryoneSid);
	PSID pUsersSid = NULL;
	AllocateAndInitializeSid(&NtAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &pUsersSid);
	PSID pServiceSid = NULL;
	AllocateAndInitializeSid(&NtAuth, 1, SECURITY_SERVICE_RID,
		0, 0, 0, 0, 0, 0, 0, &pServiceSid);
	PSID pConsoleLogonSid;
	AllocateAndInitializeSid(&LocalAuth, 1, SECURITY_LOCAL_LOGON_RID,
		0, 0, 0, 0, 0, 0, 0, &pConsoleLogonSid);
	PSID pAuthUsersSid;
	AllocateAndInitializeSid(&NtAuth, 1, SECURITY_AUTHENTICATED_USER_RID,
		0, 0, 0, 0, 0, 0, 0, &pAuthUsersSid);
	PSID pThisOrgSid;
	AllocateAndInitializeSid(&NtAuth, 1, SECURITY_THIS_ORGANIZATION_RID,
		0, 0, 0, 0, 0, 0, 0, &pThisOrgSid);
	PSID pLocalSid;
	AllocateAndInitializeSid(&LocalAuth, 1, SECURITY_LOCAL_RID,
		0, 0, 0, 0, 0, 0, 0, &pLocalSid);
	// Already have the SIDs for Administrators and SYSTEM

	pNewTokenGroups->Groups[0].Sid = pSysIntegrityLabelSid;
	pNewTokenGroups->Groups[0].Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
	pNewTokenGroups->Groups[1].Sid = pEveryoneSid;
	pNewTokenGroups->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pNewTokenGroups->Groups[2].Sid = pUsersSid;
	pNewTokenGroups->Groups[2].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pNewTokenGroups->Groups[3].Sid = pServiceSid;
	pNewTokenGroups->Groups[3].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pNewTokenGroups->Groups[4].Sid = pConsoleLogonSid;
	pNewTokenGroups->Groups[4].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pNewTokenGroups->Groups[5].Sid = pAuthUsersSid;
	pNewTokenGroups->Groups[5].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pNewTokenGroups->Groups[6].Sid = pThisOrgSid;
	pNewTokenGroups->Groups[6].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pNewTokenGroups->Groups[7].Sid = pLocalSid;
	pNewTokenGroups->Groups[7].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pNewTokenGroups->Groups[8].Sid = pAdminSid;
	pNewTokenGroups->Groups[8].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;
	pNewTokenGroups->Groups[9].Sid = pSystemSid;
	pNewTokenGroups->Groups[9].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	
	FreeSid(pSysIntegrityLabelSid);
	FreeSid(pEveryoneSid);
	FreeSid(pUsersSid);
	FreeSid(pServiceSid);
	FreeSid(pConsoleLogonSid);
	FreeSid(pAuthUsersSid);
	FreeSid(pThisOrgSid);
	FreeSid(pLocalSid);
	FreeSid(pSystemSid);

	// Step 6D: Establish Other Necessary Values

	TOKEN_USER NewTokenUser;
	NewTokenUser.User.Sid = SvcSid;
	NewTokenUser.User.Attributes = 0;
	TOKEN_OWNER NewTokenOwner;
	NewTokenOwner.Owner = SvcSid;
	TOKEN_PRIMARY_GROUP NewTokenPrimaryGroup;
	NewTokenPrimaryGroup.PrimaryGroup = pAdminSid;
	FreeSid(pAdminSid);

	LUID AuthID = SYSTEM_LUID;
	LARGE_INTEGER ExpirTime;
	ExpirTime.QuadPart = MAXLONGLONG;

	TOKEN_SOURCE NewTokenSource;
	char szTokenSourceName[8] = "SvcAcct";
	strcpy_s(NewTokenSource.SourceName, 8 * sizeof(char), szTokenSourceName);
	AllocateLocallyUniqueId(&NewTokenSource.SourceIdentifier);
	
	// Step 6E: Create the Token and Create a Process With It

	HANDLE hCreatedToken;
	NtStatus = NtCreateToken(&hCreatedToken, TOKEN_ALL_ACCESS, NULL, TokenPrimary, &AuthID, &ExpirTime,
		&NewTokenUser, pNewTokenGroups, pNewTokenPrivs, &NewTokenOwner, &NewTokenPrimaryGroup, &NewTokenDACL, &NewTokenSource);
	if (NT_ERROR(NtStatus)) { NtStatusErrorExit(L"NtCreateToken", NtStatus); }
	
	wchar_t wszCmdPath[MAX_PATH];
	dwRes = GetSystemDirectoryW(wszCmdPath, MAX_PATH);
	if (dwRes == 0) { ErrorExit(L"GetSystemDirectoryW", GetLastError()); }
	wcscat_s(wszCmdPath, MAX_PATH, L"\\cmd.exe");

	STARTUPINFOW StartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	memset(&StartupInfo, 0, sizeof(STARTUPINFOW));
	StartupInfo.cb = sizeof(StartupInfo);
	memset(&ProcessInfo, 0, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessWithTokenW(hCreatedToken, 0, wszCmdPath, NULL,
		CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInfo)) {
		ErrorExit(L"CreateProcessWithTokenW", GetLastError());
	}

	CloseHandle(hCreatedToken);
	RevertToSelf();
	NetUserDel(NULL, wszTempAcctName);
	printf("Success!\n");
	system("pause");
}
