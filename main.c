#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <Aclapi.h>
#include <AuthZ.h>
#include "libxml/parser.h"
#include "libxml/tree.h"
#include "stretchy_buffer.h"
//Install-Package libxml2
//Install-Package libiconv
//Install-Package zlib-msvc14-x64
//https://www.microsoft.com/en-us/download/details.aspx?id=30679#
//add .lib files to linker depencies, add .dll files to build dir
// https://github.com/nothings/stb/blob/master/stretchy_buffer.h
// linus torvalds list.h or glib datatypes is an alternative, probably better for debuging

// Solid resource for undocumented win32: https://github.com/microsoft/Windows-classic-samples/tree/master/Samples/Security

#define IDSIZE 8
#define PROPSIZE 256
#define ENTSIZE 256

// array of entrys (string array)
//typedef char* vulnEntry;
typedef char** vulnEntry;
vulnEntry* vulnList;
// String Entry format: (Vuln-Type) (Process) (Path) (Misc)...

// OUTPUT FORMAT:
// BP [File Writable] Bad Permission Read
// DH [File Writable] DLL
// DH1 [Directory Writable] Load DLL NAMENOTFOUND
// DH3 [Directory Writable] CreateFile NAMENOTFOUND DLL Loaded
// File Writable [FW], Directory Writable [DW]

// create entry with num strings
vulnEntry genEntry(int num, char* s, ...) {
	va_list valist;
	va_start(valist, s);
	char* buf; // string buffer
	vulnEntry entry; // entry buffer

	entry = NULL;
	for(int a = 0; a<num;a++){
		buf = malloc(PROPSIZE * sizeof(char));
		strcpy_s(buf, PROPSIZE, s);
		sb_push(entry, buf);
		s = va_arg(valist, char*);
	}
	va_end(valist);

	return entry;
}
// sb allocates mem on first call for datastructe but not variables inside struct
void freeEntry(vulnEntry s) {
	for(int a = 0; a<sb_count(s);a++){
		free(s[a]);
	}
	sb_free(s);
}

// xml node traversal helper functions
char* propertyValue(xmlNode* node, int num) {
	xmlNode* iter = node->children;
	for (int n = 0; n < num; n++) {
		iter = iter->next;
	}
	if (iter->children == NULL) { return NULL; }
	return iter->children->content;
}
char* findPropertyValue(xmlNode* node, char* name) {
	xmlNode* iter = node->children;
	while(iter!=NULL){
		if (strcmp(iter->name, name) == 0) {
			break;
		}
		iter = iter->next;
	}
	if (iter == NULL || iter->children == NULL) { return NULL; }
	return iter->children->content;
}

// Parses nodetree, returns a string array of elevated process PIDs
char** getElevatedProc(xmlNode* root) {
	xmlNode* procNodes = root->children;
	// init procid list
	char** eleProcs = NULL;

	// xml tree sanitycheck
	if (strcmp(procNodes->name,"processlist") != 0) {
		return NULL;
	}
	// get process's
	procNodes = procNodes->children;

	// tree iterator
	xmlNode* cur_node = NULL;
	char* prop = NULL;
	for (cur_node = procNodes; cur_node; cur_node = cur_node->next) {
		if (cur_node->children == NULL) { continue; }
		// get integrity level
		prop = findPropertyValue(cur_node, "Integrity");
		if (prop == NULL) { continue; }

		// check if High or System
		if (strcmp(prop, "High") == 0 || strcmp(prop, "System") == 0 ) {
			//printf("%s\n", prop = findPropertyValue(cur_node, "ProcessName"));
			// allocate new string for array
			char* id = malloc(IDSIZE * sizeof(char));
			strcpy_s(id, IDSIZE, findPropertyValue(cur_node, "ProcessId"));
			sb_push(eleProcs, id);
		}
	}
	return eleProcs;
}

// basic contains function, checks if sb array holds string
// return array index or -1 if not found
int strContains(char** arr,char* str) {
	if (arr == NULL || str == NULL) { return -1; }
	for (int s = 0; s < sb_count(arr); s++) {
		if (strcmp(arr[s], str) == 0) { return s; }
	}
	return -1;
}
// array of array of strings contains array of strings
int arrContains(vulnEntry* ents,vulnEntry str_a) {
	if (ents == NULL || str_a == NULL) { return -1; }
	int props = 0;
	for (int e = 0; e < sb_count(ents); e++) {
		props = sb_count(ents[e]);
		if ( props != sb_count(str_a)) { continue; }
		for (int s = 0; s < props; s++) {
			if (strcmp(ents[e][s],str_a[s]) == 0) { 
				// last value
				if ((s+1) == props) {
					return e;
				}
				continue; 
			}
			else {
				break;
			}
		}
	}
	return -1;
}

// struct to simplify accessCheck function cuz only black magic can make it work
typedef struct accessParms {
	HANDLE hToken;
	HANDLE hImpersonatedToken;
	GENERIC_MAPPING mapping;
	PRIVILEGE_SET privileges;
	DWORD grantedAccess; 
	DWORD privilegesLength;
	DWORD genericAccessRights;
}accessParms;
accessParms* initAccessParms() {
	accessParms* p = malloc(sizeof(accessParms));
	p->hToken = NULL;
	p->hImpersonatedToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &(p->hToken));
	DuplicateToken(p->hToken, SecurityImpersonation, &(p->hImpersonatedToken));

	p->mapping = (GENERIC_MAPPING){ 0xFFFFFFFF };
	p->privileges = (PRIVILEGE_SET){ 0 };
	p->grantedAccess = 0;
	p->privilegesLength = sizeof( p->privileges );
	p->genericAccessRights = GENERIC_WRITE; // check for write access

	(p->mapping).GenericRead = FILE_GENERIC_READ;
	(p->mapping).GenericWrite = FILE_GENERIC_WRITE;
	(p->mapping).GenericExecute = FILE_GENERIC_EXECUTE;
	(p->mapping).GenericAll = FILE_ALL_ACCESS;

	MapGenericMask( &(p->genericAccessRights), &(p->mapping) );
	return p;
}
int freeAccessParms(accessParms* p) {
	CloseHandle(p->hImpersonatedToken);
	CloseHandle(p->hToken);
	free(p);
	return 0;
}

// check for reads to an user-writable file from elevated process
void badFilePermissions(xmlNode * cur_node, BOOL elevated, accessParms * p) {
	char* op = NULL;
	char* pid = NULL;
	char* path = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pDACL = NULL; 

	// get operation
	op = findPropertyValue(cur_node, "Operation");
	//op = propertyValue(cur_node, 4); // faster
	if (op == NULL) { return; }

	// reads in both advanced and normal output IRP_MJ_READ, ReadFile
	if (strcmp(op, "IRP_MJ_READ") == 0 || strcmp(op, "ReadFile") == 0) {
		pid = findPropertyValue(cur_node, "PID");
		// check if process is elevated
		if (elevated == TRUE) {
			path = findPropertyValue(cur_node, "Path");
			if (GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS) {
				// cleanup pointers
				if (pSD != NULL) { LocalFree((HLOCAL)pSD); }
				//if (pDACL != NULL) { LocalFree((HLOCAL)pDACL); }
				return;
			}

			// possibly better then access check authz(): https://docs.microsoft.com/en-ca/windows/win32/secauthz/checking-access-with-authz-api?redirectedfrom=MSDN
			// check if file is available to everyone, authorized users, or current user
			BOOL result = FALSE;
			AccessCheck(pSD, p->hImpersonatedToken, p->genericAccessRights, &(p->mapping), &(p->privileges), &(p->privilegesLength), &(p->grantedAccess), &result);

			if (result) {
				char* procName = NULL;
				procName = findPropertyValue(cur_node, "Process_Name");
				vulnEntry entry = NULL;
				entry = genEntry(3,"BP", procName, path);
				//snprintf(entry, ENTSIZE,"BP %s %s",procName,path );

				if (arrContains(vulnList, entry) == -1) {
					sb_push(vulnList, entry);
					//printf("(%s)%s [File Writable] Bad Permission Read\n", procName, path);
				}
				else {
					freeEntry(entry);
				}
			}
		}
	}
	// free descriptor and dacl
	if (pSD != NULL) { LocalFree((HLOCAL)pSD); }
	//if (pDACL != NULL) { LocalFree((HLOCAL)pDACL); }
}

// create dir string from path, must free dir after
char* getDir(char* path) {
	char* dir = malloc(PROPSIZE);
	strcpy_s(dir, PROPSIZE, path);

	char* p = strrchr(dir, '\\');
	if (p == 0) {
		free(dir);
		return NULL;
	}
	// delimit string
	*p = '\0';
	return dir;
}

// check for elevated Procs with Load Image + "NAME NOT FOUND"
// check for elevated Procs that CreateFile(IRP_MJ_CREATE) + "NAME NOT FOUND" then Load Image same file
void dllHijack(xmlNode * cur_node, BOOL elevated, accessParms * p) {
	char* op = NULL;
	char* pid = NULL;
	char* path = NULL;
	char* procName = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pDACL = NULL; 

	// get operation
	op = findPropertyValue(cur_node, "Operation");
	if (op == NULL) { return; }

	// check if process is elevated
	if (elevated == TRUE) {
		pid = findPropertyValue(cur_node, "PID");
		path = findPropertyValue(cur_node, "Path");
		procName = findPropertyValue(cur_node, "Process_Name");

		if (strcmp(op, "Load Image") == 0) {
			char* dir = getDir(path);
			BOOL writable;
			char* result;

			// check if dir/file is writable
			if (GetNamedSecurityInfoA(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS) {
				// cleanup pointers
				if (pSD != NULL) { LocalFree((HLOCAL)pSD); }
				//if (pDACL != NULL) { LocalFree((HLOCAL)pDACL); }
				return;
			}
			// check if file is available to everyone, authorized users, or current user
			writable = FALSE;
			AccessCheck(pSD, p->hImpersonatedToken, p->genericAccessRights, &(p->mapping), &(p->privileges), &(p->privilegesLength), &(p->grantedAccess), &writable);

			result = findPropertyValue(cur_node, "Result");

			// TODO: expanded %PATH check for dll hijack
			if (writable == TRUE) {
				// Normal DLL Hijack DH1
				// Load Image + NAME NOT FOUND + writable (should I just check all writable dlls?)
				if (strcmp(result, "NAME NOT FOUND")) {
					// TODO: lots of code repeat, maybe create a addEntry func?
					vulnEntry entry = genEntry(3, "DH1", procName, path);

					if (arrContains(vulnList, entry) == -1) {
						sb_push(vulnList, entry);
						//printf("(%s)%s [Directory Writable] DLL Hijack\n", procName, path);
					}
					else {
						freeEntry(entry);
					}
				}

				// CreateFile DLL Hijack DH3
				// check for Load Image + DH2 same filename + writable dir 
				vulnEntry  checkDH2 = genEntry(3, "DH2", procName, path);

				if (arrContains(vulnList, checkDH2) == -1) {
					vulnEntry  entry = genEntry(3, "DH3", procName, path);

					if (arrContains(vulnList, entry) == -1) {
						sb_push(vulnList, entry);
						// lots of DLL Hijacks end up being normal hijacks
						//printf("(%s)%s [Directory Writable] CreateFile DLL Hijack\n", procName, path);
					}
					else {
						freeEntry(entry);
					}
				}
				else {
					freeEntry(checkDH2);
				}

			}

			// check if dll is writable DH
			if (pSD != NULL) { LocalFree((HLOCAL)pSD); } // free from previous dir use
			if (GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS) {
				// cleanup pointers
				if (pSD != NULL) { LocalFree((HLOCAL)pSD); }
				//if (pDACL != NULL) { LocalFree((HLOCAL)pDACL); }
				return;
			}
			// check if file is available to everyone, authorized users, or current user
			writable = FALSE;
			AccessCheck(pSD, p->hImpersonatedToken, p->genericAccessRights, &(p->mapping), &(p->privileges), &(p->privilegesLength), &(p->grantedAccess), &writable);

			if (writable == TRUE) {
				vulnEntry  entry = genEntry(3, "DH", procName, path);

				if (arrContains(vulnList, entry) == -1) {
					sb_push(vulnList, entry);
					//printf("(%s)%s [Directory Writable] DLL is writable\n", procName, path);
				}
				else {
					freeEntry(entry);
				}
			}

			free(dir);
		}

		// check for CreateFile/IRP_MJ_CREATE + "NAME NOT FOUND"
		// helper entry for DLLHijack 3, saved as a DH2 entry
		// possible other operations that could indicate the first part of a DLLhijack?
		if(strcmp(op, "IRP_MJ_CREATE") == 0 || strcmp(op, "CreateFile") == 0) {
			char* result;
			result = findPropertyValue(cur_node, "Result");
			if (strcmp(result, "NAME NOT FOUND")) {
				char* procName = NULL;
				procName = findPropertyValue(cur_node, "Process_Name");
				vulnEntry entry = NULL;
				entry = genEntry(3, "DH2", procName, path);

				if (arrContains(vulnList, entry) == -1) {
					sb_push(vulnList, entry);
				}
				else {
					freeEntry(entry);
				}

			}
		}

	}

	// free descriptor and dacl
	if (pSD != NULL) { LocalFree((HLOCAL)pSD); }
	//if (pDACL != NULL) { LocalFree((HLOCAL)pDACL); }
}

// possibilty to make faster with chunck reads or hash tables
void parseEvents(xmlNode* root) {
	xmlNode* entNodes = root->children->next; // entries node in xml

	// get elevated entries
	char** eleProcs = getElevatedProc(root); // string array of PIDs
	accessParms* parms = initAccessParms();

	// xml tree sanitycheck
	if (strcmp(entNodes->name,"eventlist") != 0) {
		return;
	}
	// get process's
	entNodes = entNodes->children;

	// tree iterator
	xmlNode* cur_node = NULL;
	BOOL elevated = FALSE;
	char* pid = NULL;
	for (cur_node = entNodes; cur_node; cur_node = cur_node->next) {
		// if node is blank
		if (cur_node->children == NULL) { continue; }

		pid = findPropertyValue(cur_node, "PID");
		elevated = (strContains(eleProcs, pid) != -1) ?  TRUE : FALSE;
		// check if process is elevated

		// check for bad permissions
		badFilePermissions(cur_node, elevated, parms);

		// DLL search order hijack, CreateFile : “Name Not Found” -> Load Image same file OR Load Image : “Name Not Found” OR DLL is writable
		dllHijack(cur_node, elevated, parms);

		// TODO: implement a exclude list, will only work with exact length entries unless need filter function most will be length 3 anyways
	}

}

int toStringVulnEntry(char* str, vulnEntry ent) {
	// BP [File Writable] Bad Permission Read
	// DH [File Writable] DLL
	// DH1 [Directory Writable] Load DLL NAMENOTFOUND
	// DH3 [Directory Writable] CreateFile NAMENOTFOUND DLL Loaded
	if (str == NULL) { return 1; }

	// clear string
	strcpy_s(str,PROPSIZE, "");
	if (strcmp(ent[0],"BP") == 0) {
		strcat_s(str, PROPSIZE, "Bad Permission Read [FW] ");
	} else if (strcmp(ent[0],"DH") == 0) {
		strcat_s(str, PROPSIZE, "DLL Hijack [FW] ");
	} else if (strcmp(ent[0],"DH1") == 0) {
		strcat_s(str, PROPSIZE, "Load DLL NAMENOTFOUND [DW] ");
	} else if (strcmp(ent[0],"DH3") == 0) {
		strcat_s(str, PROPSIZE, "CreateFile NAMENOTFOUND DLL Loaded [DW] ");
	} else if (strcmp(ent[0],"DH2") == 0) {
		strcat_s(str, PROPSIZE, "DH3 Helper");
	}

	for (int s = 1; s < sb_count(ent); s++) {
		strcat_s(str, PROPSIZE, ent[s]);
		strcat_s(str, PROPSIZE, " ");
	}
	return 0;
}

void printVulnList() {
	char* buff = malloc(sizeof(char) * PROPSIZE);
	for (int x = 0; x < sb_count(vulnList); x++) {
		if (strcmp(vulnList[x][0], "DH2") != 0) {
			toStringVulnEntry(buff,vulnList[x]);
			printf("%s\n", buff);
		}
	}
	//free(buff);
}

int main(int argc, char **argv) 
{
	xmlDoc *doc = NULL;
	xmlNode *root = NULL;
	char* logPath = argv[1];
	//char* logPath = "C:\\Users\\Sam\\Logfile.XML";

	LIBXML_TEST_VERSION // check API and match with DLL's

	if ((doc = xmlReadFile(logPath, NULL, 0)) == NULL) {
		printf("[!] Could not parse xml file.\n");
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	//print_element_names(root);
	parseEvents(root);
	printVulnList();

	xmlFreeDoc(doc);
	xmlCleanupParser();

	return 0;
}
