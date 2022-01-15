# Introduction

## What is a DLL

According to [MSDN](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library) a DLL is *a library that contains code and data that can be used by more than one program at the same time.* DLL's are often used to modularize a program into separate components with each module being loaded by the main program if the module exists. These modules normally extend the functionality of the main program. 

## What is DLL Injection

Since an injected dll can manipulate a running process it gives us a great opportunity to add whatever functionality we want to an application. This is most commonly done either in game hacking or when you want to reverse engineer something and want a bit more control. 

## Purpose of this post

This post is going to go over how to perform a basic dll injection using LoadLibrary, it will then dive into how LoadLibrary works behind the scenes and go through the steps of manually mapping and injecting a DLL into a process.

# Using LoadLibrary and CreateRemoteThread

The most basic way to do a DLL injection in windows is by using the built in functions LoadLibrary and CreateRemoteThread. This requires us to have the dll on the machine as well as requiring us to know the path to the dll. 

## LoadLibrary

Like most winapi functions, LoadLibrary has a LoadLibraryA and a LoadLibraryW function. For those who have not worked with winapi much before, this simply [signifies the type of string that the function expects](https://docs.microsoft.com/en-us/windows/win32/learnwin32/working-with-strings). In this post, we are going to use the LoadLibraryA function, and that's simply because of personal preference and how I normally set up my tools. 

[LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) enables us to load a dll from the disk into memory. This function does all the work for us and only requires us to pass the path to the dll for it to work. If successful it passes us the handle to the loaded module, and if it fails it will return NULL. There is also an [extended function](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) for LoadLibrary that lets you set additional load options using a second parameter for flags.

LoadLibrary will load the module (dll) that we specify into the address space of whatever calls it, which is why we can't just use it on its own since that would just load the dll into our program rather than the program we want to inject our code into.

## CreateRemoteThread

[CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) is the other function that we will need to use in order to perform our injection. CreateRemoteThread lets us execute the LoadLibrary call within the process we want to inject our code into. 

To use CreateRemoteThread we need a handle to the process that we want to inject, a pointer to the function we want to call (LoadLibraryA), and the parameters for the function (dll path). If the function succeeded we will get the handle to the thread, otherwise, the function will return NULL.

As with LoadLibrary, there is also an [extended version](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex) of the function if you want more control over the creation of the thread.

## Finding the handle of a process

Above I mentioned needing the handle for a process quite a bit so now I am going to dive into what a handle is and how to find one for your process.

In winapi, a HANDLE is an abstraction which hides the memory address from the user, reorganizing memory without the program needing to know everything. Therefore, a handle to a process basically just tells us where the memory for that process is.

In order to get the handle to a process we will want to use the winapi function [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess). This function needs to be told what access rights we want, and then it needs to process id. For our injector we can just use `PROCESS_ALL_ACCESS` for the access rights.

You can find the process id through the task manager by going to details and looking at the PID next to the process, this however takes time and is not the way we want to do this. Luckily we can do this programmatically:

```c++
DWORD proc::GetProcId(const wchar_t* procName)
{
    // Assign to 0 for error handling
    DWORD procId = 0;
    // Takes snapshot of the processes
    HANDLE hSnap = (CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    // Check if snapshot exists and didn't error out
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        // Set entry size
        procEntry.dwSize = sizeof(procEntry);
        // Grabs first process in the snapshot and stores in procEntry
        if (Process32First(hSnap, &procEntry)) {
            // Loops through all processes
            do
            {
                // Checks if the process name is our process name
                if (!_wcsicmp(procEntry.szExeFile, procName)) {
                    // When found it saves the id and breaks out of the loop
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    // Closes Handle
    CloseHandle(hSnap);
    // Returns process id
    return procId;
}
```

When given the process name, this function loops through all of the processes and tries to find the process that has a name that matches our processes name. It then returns the process id which we can then use to get the process handle with OpenProcess.

## Diving into the code

Since we only need the two functions we discussed above we can wrap all the logic for performing the injection in one single function:

```c++
void injector::LocAInject(const char* dllPath, HANDLE hProc)
{
    // Gets address to LoadLibraryA function
	LPVOID libAAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    // Allocate space for our dll path in the process we want to inject into
	void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Patch the memory we allocated and write our dll path to it
	mem::PatchEx((BYTE *)loc, (BYTE*)dllPath, (unsigned int)(strlen(dllPath) + 1), hProc);

    // Create the remote thread with LoadLibraryA and the dll path
	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)libAAddr, loc, 0, 0);

    // If the thread isn't null then close the handle 
	if (hThread != NULL) {
		CloseHandle(hThread);
	}
    // Otherwise exit gracefully
	else {
        ErrorHandling::ErrorExit((LPTSTR)(L"CreateRemoteThread"));
	}
}
```

The function takes in two parameters, the path to our dll, and the handle to the process which we can find with what we went over in the last section. 

```c++
LPVOID libAAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
```

In the first line of code, we get the address of LoadLibraryA using the winapi function [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress). This function takes in the handle to the module that contains the function and the name of the function. LoadLibraryA is located in kernel32.dll so that is why we get that module.

```c++
void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

The next line of code lets us allocate space equal to the max path length in windows in the process we want to inject our code into. This is necessary since we need the path to call LoadLibrary and we need the string to be in the process we are calling the function from.

```c++
mem::PatchEx((BYTE *)loc, (BYTE*)dllPath, (unsigned int)(strlen(dllPath) + 1), hProc);
```

After allocating space in the other process we then need to patch that memory and write our dll path into the space we allocated. For this I used the [patch external function from my CPPToolLib](https://github.com/Kasimir123/CPPToolLib/blob/main/CPP%20Tools/mem/mem.cpp), however, this function is fairly short and can be implemented many different ways so I will not go into it too much. 

```c++
HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)libAAddr, loc, 0, 0);
```

After writing the dll path into the other process and getting the pointer to the LoadLibrary function we can now call CreateRemoteThread. I set hThread to the return value of CreateRemoteThread so that I can check if it successfully injected.

```c++
if (hThread != NULL) {
	CloseHandle(hThread);
}
else {
    ErrorHandling::ErrorExit((LPTSTR)(L"CreateRemoteThread"));
}
```

Finally, we check if we successfully created the thread, if we did we close the handle, if not we call an error handling function.

# Manually Performing LoadLibrary

We are going to go in depth for how to manually perform LoadLibrary, this post will go over 32 bit, 64 bit has a few minor differences but after reading the post you should be able to easily update the code for 64 bit based on MSDN. Manually mapping a DLL lets you do everything that LoadLibrary does to load the dll into another process without having the dll show up in the modules list, this means that if some program tries to walk through all the loaded modules they will not see your dll.

## What exactly does LoadLibrary do for us

The first step to manually mapping and injecting the DLL is to understand how Windows does this behind the scenes. This process can be broken down into 5 steps:

1. Reading and Parsing
    - Read file into memory
    - Get headers
2. Allocating Memory
    - Getting and updating the image size
    - Copying the headers into memory
    - Updating the new headers with the new base
3. Copying Sections
    - Loop through section headers
    - Allocate or copy section data
    - Update section header with new address
    - Setting memory protections of each section
4. Relocating the Base of the Program (if applicable)
    - Check if we need to perform a relocation
    - Offset the relocations that need updating
5. Resolving Imports

## Doing the steps ourselves

### Reading and Parsing

We pass LoadLibrary the path to the DLL so the first step in the process is to read the data from the file and bring it into memory. Windows offers an API call in order to perform this operation, [CreateFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea), however I have often run into issues with this call requiring the program to be run in administrator mode so I just use [ifstream](https://www.cplusplus.com/reference/fstream/ifstream/).

This results in a few lines of code where we open the file in binary mode, get the size of the file, allocate space for the contents we are going to read, and then read and close the file:

```c++
// Open file in binary mode
std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

// Get the size of the program
size_t fileSize = File.tellg();

// Allocate space for the data
BYTE* data = new BYTE[fileSize];

// Reset position to the start of the file
File.seekg(0, std::ios::beg);

// Read all of the file into our data
File.read((char*)data, fileSize);

// Close the handle to the file
File.close();
```

Once we have the file in memory we can start extracting the data that we need. The first important bit of information that we need is the [DOS header](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only):

```c++
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

The DOS header is going to be at the start of the data that we just read in so we can just type the data as a pointer to the header:

```c++
// Get dos header
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(data);
```

After the DOS header we have the [File header](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image) and the [Optional header](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only). Windows gives us a nice datastructure that gives us access to both based on the offset defined in the DOS header. So at this point, to get the nt headers we just need to type the offset from the start of the data to that struct:

```c++
// Get nt headers
PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data + dosHeader->e_lfanew);
```

With this we can now move onto the next step, allocating the memory.

### Allocating Memory

The first step in allocating memory is figuring out how much memory we need to allocate in our process. Luckily we can figure this out from the OptionalHeader. We are going to want the data to be aligned to the page size of the system so we are also going to have to possibly allocate slightly more memory based on the image size:

```c++
// Declare the variable where we will store the system information
SYSTEM_INFO sysInfo;

// Get the native system information
GetNativeSystemInfo(&sysInfo);

// Get the image size aligned to the next largest multiple of the page size
size_t imageSize = (ntHeaders->OptionalHeader.SizeOfImage + sysInfo.dwPageSize - 1) & ~(sysInfo.dwPageSize - 1);
```

Now that we have the image size we can allocate memory in our program using the native winapi functions. At first we are going to try to allocate the memory at the image base specified in the headers, and if we are unable to do that we are going to let the system decide where to allocate the memory:

```c++
// Attempt to allocate memory at the image base
unsigned char* code = (unsigned char*)VirtualAlloc((LPVOID)(ntHeaders->OptionalHeader.ImageBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

// If the result was null then let the system decide where to allocate
if (code == NULL) 
	code = (unsigned char*)VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
```

In the above code we use the reserve flag to reserve the memory space and the commit flag to allocate the memory, if you curious about the other flags you can read about them [here](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc).

The last step of allocating memory is copying the headers into our allocated memory and then updating the ImageBase in those headers with where our memory is allocated. This is important because we may not have been able to allocate the memory at the ImageBase when we did our VirtualAlloc earlier:

```c++
// Copy the headers from the data into the allocated memory
memcpy(code, data, ntHeaders->OptionalHeader.SizeOfHeaders);

// Get the pointer to the allocated headers
PIMAGE_NT_HEADERS allocatedHeaders = (PIMAGE_NT_HEADERS)(code + dosHeader->e_lfanew);

// Update the image base to where we allocated our memory
allocatedHeaders->OptionalHeader.ImageBase = (uintptr_t)code;
```

### Copying Sections

The next step in loading the DLL is copying the sections into memory. There are normally two different types of sections that we need to look out for when copying data. The first are sections with data in them, this could be strings or code or other things that need to be accessed, these need to be copied over in their entirety. The others are sections with no data of their own but instead you need to allocate a certain amount of space for them. 

In order to copy the sections over we are going to grab the first section header, and then we are going to loop through all of the sections. Then we are going to either copy the raw data into memory or allocate uninitialized data based on the type of section it is. Once we have copied over the section we then update the section header with the address that we just copied our section to:

```c++
// Get first section header
PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(allocatedHeaders);

// Loop through all sections
for (int i = 0; i < allocatedHeaders->FileHeader.NumberOfSections; i++, section++)
{
	// Get the physical address of the section in memory
	unsigned char* segmentAddress = code + section->VirtualAddress;

	// If the size of the data is 0 then we are "allocating" memory for a data section
	if (!(section->SizeOfRawData))
	{
		// Check if the SectionAlignment is greater than 0, semi redundent check but better safe than sorry
		if (ntHeaders->OptionalHeader.SectionAlignment > 0)
			// Set the SectionAlignment number of bytes to 0
			memset(segmentAddress, 0, ntHeaders->OptionalHeader.SectionAlignment);
	}
	// If not a data section then we need to copy all of the data over to it
	else
		// Copy the raw data into memory
		memcpy(segmentAddress, data + section->PointerToRawData, section->SizeOfRawData);

	// Update the address in the section header to point to our loaded section
	section->Misc.PhysicalAddress = (DWORD)((uintptr_t)segmentAddress & 0xffffffff);
}
```

Normally when LoadLibrary loads a program it performs the relocations, then the imports, and then it goes through the sections and protects the memory (setting to read, write, and or execute). This however does not work for what our final goal is as we want to use this code to inject a dll into another process. Since we are injecting this dll into another process, that process is going to have to do the import resolution. This means we could still set the protections within that process, however, normally when you are manually mapping a dll you are most likely doing something that the process really doesn't want you to be doing so setting protections from within may be a bit questionable. The other reason we don't want to do this inside of that process is because then we would have to pass more function pointers into that process and thats more work. 

Instead of going through the trouble of doing that I am instead going to set all of the protections at this step and just leave everything as writable. You can skip this step if you set everything as executable in the initial memory allocation but that again makes the injection fairly easy to spot.

Our first step in this code is to get the section, it's address, the start of the page it is on, the section size, and it's characteristics:

```c++
// Get the first section
section = IMAGE_FIRST_SECTION(allocatedHeaders);

// Get the physical address of the first section
LPVOID gAddress = (LPVOID)section->Misc.PhysicalAddress;

// Get the address of the first section aligned with the page size
LPVOID gAlignedAddress = (LPVOID)((uintptr_t)gAddress & ~(sysInfo.dwPageSize - 1));

// Get the section size
size_t gSize = GetSectionSize(allocatedHeaders, section);

// Get the section characteristics 
DWORD gCharacteristics = section->Characteristics;

// Set isLast to false
bool isLast = false;
```

IMAGE_FIRST_SECTION is provided by windows while GetSectionSize is one of our functions:

```c++
// Gets the size of the section
size_t GetSectionSize(PIMAGE_NT_HEADERS headers, PIMAGE_SECTION_HEADER section) {
	// Set the size to the size of the raw data
	DWORD size = section->SizeOfRawData;

	// If the section has no raw data then set the size to the size of the data
	if (size == 0) {
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size = headers->OptionalHeader.SizeOfInitializedData;
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size = headers->OptionalHeader.SizeOfUninitializedData;
		}
	}

	// Return the size
	return (size_t)size;
}
```

After we have the initial information we are going to loop through all of the sections and get that data for each section. If the section is on the same page as the previous section we are going to add the characteristics to our "global" characteristics and move on to the next section. Otherwise we are going to go and either free the page or set the protection of the sections and continue to the next section:

```c++
// Loop through all sections
for (int i = 0; i < allocatedHeaders->FileHeader.NumberOfSections; i++, section++) {

	// Get all of the information for the current section
	LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress);
	LPVOID alignedAddress = (LPVOID)((uintptr_t)sectionAddress & ~(sysInfo.dwPageSize - 1));
	SIZE_T sectionSize = GetSectionSize(allocatedHeaders, section);

	// Check if the current section is on the same page as the previous section
	if (gAlignedAddress == alignedAddress || (uintptr_t)gAddress + gSize > (uintptr_t) alignedAddress) {
		// If it is then update the characteristics with those of the current section
		if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (gCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
			gCharacteristics = (gCharacteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
		}
		else {
			gCharacteristics |= section->Characteristics;
		}

		// Get the size from the start of the first section on the page up till the end of the most recent section
		gSize = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)gAddress;

		// Skip the rest of the loop
		continue;
	}

	// If the section can be discarded then free the memory
	if (gCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) {
		// Check that a whole page is getting freed
		if (gAddress == gAlignedAddress &&
			(isLast ||
				allocatedHeaders->OptionalHeader.SectionAlignment == sysInfo.dwPageSize ||
				(gSize % sysInfo.dwPageSize) == 0)
			) {
			VirtualFree(gAddress, gSize, MEM_DECOMMIT);
		}
	}

	// Check if the section is executable and or readable, we ignore writeable since we are going to need
	// the sections to be writable when we do the imports once the dll is injected. The imports need to be 
	// done in the injected process while we want to do this in our injector so we need to make some exceptions.
	bool executable = (gCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
	bool readable = (gCharacteristics & IMAGE_SCN_MEM_READ) != 0;

	// Array of allowed protections
	int ProtectionFlags[2][2] = {{PAGE_WRITECOPY, PAGE_READWRITE, }, {PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READWRITE,}};

	// Get the protection flag to use
	DWORD protection = ProtectionFlags[executable][readable];

	// check if we need to add the no cache flag to the protection
	if (gCharacteristics & IMAGE_SCN_MEM_NOT_CACHED) {
		protection |= PAGE_NOCACHE;
	}

	// Declare old protection
	DWORD oldProtection;

	// Change the protection of the section
	VirtualProtect(gAddress, gSize, protection, &oldProtection);

	// Set the new values
	gAddress = sectionAddress;
	gAlignedAddress = alignedAddress;
	gSize = sectionSize;
	gCharacteristics = section->Characteristics;

	// If this is the last section then set isLast to true
	if (i == allocatedHeaders->FileHeader.NumberOfSections - 1)
		isLast = true;
}
```

### Relocating the Base of the Program (if applicable)

If we were not able to allocate the memory at the original ImageBase we are going to need to go through and update the base relocations to the new address. The first step here is to see if we even need to perform the relocations, the way we are going to do this is we are going to get the difference between the original ImageBase and the base that we allocated our memory at:

```c++
// Get the difference between the two ImageBases
ptrdiff_t ptrDiff = (ptrdiff_t)(allocatedHeaders->OptionalHeader.ImageBase - ntHeaders->OptionalHeader.ImageBase);
```

Once we know that we need to perform the relocation we then need to loop through all of the relocations and all of their info sections and adjust the values based on the difference between the ImageBase if the relocation type is IMAGE_REL_BASED_HIGHLOW:

```c++
	// Check if we need to perform any relocations
if (ptrDiff)
{
	// Get data directory
	PIMAGE_DATA_DIRECTORY directory = &(allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	// Get first base relocation
	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(code + directory->VirtualAddress);

    // Loop through all relocations, check virtual address to see when to quit
    while (relocation->VirtualAddress > 0)
    {
        // Get the physical address of the relocation
        unsigned char* physicalAddress = code + relocation->VirtualAddress;

        // Get the first relocation information for the relocation
        unsigned short* relInfo = (unsigned short*)GetPointerOffset(relocation, sizeof(IMAGE_BASE_RELOCATION));

        // Loop through all relocation info
        for (int i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, relInfo++)
        {
            // Get the type of relocation
            int type = *relInfo >> 12;

            // Get the relocation offset
            int offset = *relInfo & 0xfff;

            // If the type is IMAGE_REL_BASED_HIGHLOW then perform our patch
            if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                // Get the reference
                DWORD*  patch = (DWORD*)(physicalAddress + offset);

                // Adjust the reference based on the difference between the ImageBases
                *patch += (DWORD)ptrDiff;
            }
        }

        // Get the next relocation
        relocation = (PIMAGE_BASE_RELOCATION)GetPointerOffset(relocation, relocation->SizeOfBlock);
    }
}
```

GetPointerOffset is just a preprocessor macro I defined at the top of the file:

```c++
#define GetPointerOffset(data, offset) (void*)((uintptr_t)data + offset)
```

### Resolving Imports

The final step of this process is to resolve the imports, this needs to be done within whatever process that we want to inject our dll into but to start we are just going to act as if our injector is the process that we injected into.

First, we are going to loop through the import table and load each of the imports. Once loaded into memory we are going to loop through all of the thunks and set the addresses of all the function calls. For this part we are just going to use LoadLibrary since resolving all of the relative paths (KERNEL32, etc) will be a pain and is a bit unnecessary. This code looks like:

```c++
// Get the entry import directory
PIMAGE_DATA_DIRECTORY directory = &(allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

// Get the first import descriptor
PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(code + directory->VirtualAddress);

// While the descriptor has a name keep looping through them all
while (importDesc->Name)
{
	// Declare our two reference pointers
	uintptr_t* thunkRef;
	FARPROC* funcRef;

	// Get the handle to the import (using LoadLibrary since we don't want to have to resolve all of the relative paths)
	HMODULE handle = LoadLibraryA((LPCSTR)(code + importDesc->Name));

	// If original first think then use that virtual address, otherwise use first thunk address
	if (importDesc->OriginalFirstThunk)
		thunkRef = (uintptr_t*)(code + importDesc->OriginalFirstThunk);
	else
		thunkRef = (uintptr_t*)(code + importDesc->FirstThunk);

	// Get function reference
	funcRef = (FARPROC*)(code + importDesc->FirstThunk);

	// Loop through all thunks and set the value of the function reference
	for (; *thunkRef; thunkRef++, funcRef++)
	{
		if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
		{
			*funcRef = GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
		}
		else
		{
			PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(code + (*thunkRef));
			*funcRef = GetProcAddress(handle, (LPCSTR)&thunkData->Name);
		}
	}

	// increment the descriptor
	importDesc++;
}
```

After resolving the import table we need to check if we have a TLS directory and then attach all of those DLLs. TLS calls, otherwise known as thread local storage calls, are just subroutines that are executed prior to the entry point being called. We need to call these since we we will manually be calling the entrypoint of the dll. Luckily the code for this is pretty simple:

```c++
// If we have a TLS directory
if (allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
{
	// Get the directory
	IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)(code + allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	// Get the first callback
	PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)(tlsDirectory->AddressOfCallBacks);

	// Loop through all callbacks
	for (; pCallback && (*pCallback); ++pCallback)
	{
		// Attach the dll
		PIMAGE_TLS_CALLBACK Callback = *pCallback;
		Callback(code, DLL_PROCESS_ATTACH, nullptr);
	}
}
```

### Calling the entrypoint

Now that we have loaded the DLL into memory, copied the sections, relocated the base, and resolved the imports it is time to call the entrypoint. For this we simply need to get the address of the entrypoint and then call it:

```c++
// typedef the DLL entry function
typedef bool(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

// Get the address for the entry 
DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(code + allocatedHeaders->OptionalHeader.AddressOfEntryPoint);

// Call the entrypoint
(*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);
```

At this point we have the following code:

<details>
<summary>Current Code</summary>

```c++
// Gets the size of the section
size_t GetSectionSize(PIMAGE_NT_HEADERS headers, PIMAGE_SECTION_HEADER section) {
	// Set the size to the size of the raw data
	DWORD size = section->SizeOfRawData;

	// If the section has no raw data then set the size to the size of the data
	if (size == 0) {
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size = headers->OptionalHeader.SizeOfInitializedData;
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size = headers->OptionalHeader.SizeOfUninitializedData;
		}
	}

	// Return the size
	return (size_t)size;
}

#define GetPointerOffset(data, offset) (void*)((uintptr_t)data + offset)

void ManMap(BYTE* data)
{
	// Get dos header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(data);

	// Get nt headers
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data + dosHeader->e_lfanew);

	// ****************************************************************************************************************************************************

	// Declare the variable where we will store the system information
	SYSTEM_INFO sysInfo;

	// Get the native system information
	GetNativeSystemInfo(&sysInfo);

	// Get the image size aligned to the next largest multiple of the page size
	size_t imageSize = (ntHeaders->OptionalHeader.SizeOfImage + sysInfo.dwPageSize - 1) & ~(sysInfo.dwPageSize - 1);

	// Attempt to allocate memory at the image base
	unsigned char* code = (unsigned char*)VirtualAlloc((LPVOID)(ntHeaders->OptionalHeader.ImageBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// If the result was null then let the system decide where to allocate
	if (code == NULL)
		code = (unsigned char*)VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Copy the headers from the data into the allocated memory
	memcpy(code, data, ntHeaders->OptionalHeader.SizeOfHeaders);

	// Get the pointer to the allocated headers
	PIMAGE_NT_HEADERS allocatedHeaders = (PIMAGE_NT_HEADERS)(code + dosHeader->e_lfanew);

	// Update the image base to where we allocated our memory
	allocatedHeaders->OptionalHeader.ImageBase = (uintptr_t)code;

	// ****************************************************************************************************************************************************

	// Get first section header
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(allocatedHeaders);

	// Loop through all sections
	for (int i = 0; i < allocatedHeaders->FileHeader.NumberOfSections; i++, section++)
	{
		// Get the physical address of the section in memory
		unsigned char* segmentAddress = code + section->VirtualAddress;

		// If the size of the data is 0 then we are "allocating" memory for a data section
		if (!(section->SizeOfRawData))
		{
			// Check if the SectionAlignment is greater than 0, semi redundent check but better safe than sorry
			if (ntHeaders->OptionalHeader.SectionAlignment > 0)
				// Set the SectionAlignment number of bytes to 0
				memset(segmentAddress, 0, ntHeaders->OptionalHeader.SectionAlignment);
		}
		// If not a data section then we need to copy all of the data over to it
		else
			// Copy the raw data into memory
			memcpy(segmentAddress, data + section->PointerToRawData, section->SizeOfRawData);

		// Update the address in the section header to point to our loaded section
		section->Misc.PhysicalAddress = (DWORD)((uintptr_t)segmentAddress & 0xffffffff);
	}

	// Get the first section
	section = IMAGE_FIRST_SECTION(allocatedHeaders);

	// Get the physical address of the first section
	LPVOID gAddress = (LPVOID)section->Misc.PhysicalAddress;

	// Get the address of the first section aligned with the page size
	LPVOID gAlignedAddress = (LPVOID)((uintptr_t)gAddress & ~(sysInfo.dwPageSize - 1));

	// Get the section size
	size_t gSize = GetSectionSize(allocatedHeaders, section);

	// Get the section characteristics 
	DWORD gCharacteristics = section->Characteristics;

	// Set isLast to false
	bool isLast = false;

	// Loop through all sections
	for (int i = 0; i < allocatedHeaders->FileHeader.NumberOfSections; i++, section++) {

		// Get all of the information for the current section
		LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress);
		LPVOID alignedAddress = (LPVOID)((uintptr_t)sectionAddress & ~(sysInfo.dwPageSize - 1));
		SIZE_T sectionSize = GetSectionSize(allocatedHeaders, section);

		// Check if the current section is on the same page as the previous section
		if (gAlignedAddress == alignedAddress || (uintptr_t)gAddress + gSize > (uintptr_t) alignedAddress) {
			// If it is then update the characteristics with those of the current section
			if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (gCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				gCharacteristics = (gCharacteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
			}
			else {
				gCharacteristics |= section->Characteristics;
			}

			// Get the size from the start of the first section on the page up till the end of the most recent section
			gSize = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)gAddress;

			// Skip the rest of the loop
			continue;
		}

		// If the section can be discarded then free the memory
		if (gCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			// Check that a whole page is getting freed
			if (gAddress == gAlignedAddress &&
				(isLast ||
					allocatedHeaders->OptionalHeader.SectionAlignment == sysInfo.dwPageSize ||
					(gSize % sysInfo.dwPageSize) == 0)
				) {
				VirtualFree(gAddress, gSize, MEM_DECOMMIT);
			}
		}

		// Check if the section is executable and or readable, we ignore writeable since we are going to need
		// the sections to be writable when we do the imports once the dll is injected. The imports need to be 
		// done in the injected process while we want to do this in our injector so we need to make some exceptions.
		bool executable = (gCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		bool readable = (gCharacteristics & IMAGE_SCN_MEM_READ) != 0;

		// Array of allowed protections
		int ProtectionFlags[2][2] = {{PAGE_WRITECOPY, PAGE_READWRITE, }, {PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READWRITE,}};

		// Get the protection flag to use
		DWORD protection = ProtectionFlags[executable][readable];

		// check if we need to add the no cache flag to the protection
		if (gCharacteristics & IMAGE_SCN_MEM_NOT_CACHED) {
			protection |= PAGE_NOCACHE;
		}

		// Declare old protection
		DWORD oldProtection;

		// Change the protection of the section
		VirtualProtect(gAddress, gSize, protection, &oldProtection);

		// Set the new values
		gAddress = sectionAddress;
		gAlignedAddress = alignedAddress;
		gSize = sectionSize;
		gCharacteristics = section->Characteristics;

		// If this is the last section then set isLast to true
		if (i == allocatedHeaders->FileHeader.NumberOfSections - 1)
			isLast = true;
	}

	// ****************************************************************************************************************************************************

	// Get the difference between the two ImageBases
	ptrdiff_t ptrDiff = (ptrdiff_t)(allocatedHeaders->OptionalHeader.ImageBase - ntHeaders->OptionalHeader.ImageBase);

	// Check if we need to perform any relocations
	if (ptrDiff)
	{
		// Get data directory
		PIMAGE_DATA_DIRECTORY directory = &(allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		// Get first base relocation
		PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(code + directory->VirtualAddress);

		// Loop through all relocations, check virtual address to see when to quit
		while (relocation->VirtualAddress > 0)
		{
			// Get the physical address of the relocation
			unsigned char* physicalAddress = code + relocation->VirtualAddress;

			// Get the first relocation information for the relocation
			unsigned short* relInfo = (unsigned short*)GetPointerOffset(relocation, sizeof(IMAGE_BASE_RELOCATION));

			// Loop through all relocation info
			for (int i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, relInfo++)
			{
				// Get the type of relocation
				int type = *relInfo >> 12;

				// Get the relocation offset
				int offset = *relInfo & 0xfff;

				// If the type is IMAGE_REL_BASED_HIGHLOW then perform our patch
				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					// Get the reference
					DWORD* patch = (DWORD*)(physicalAddress + offset);

					// Adjust the reference based on the difference between the ImageBases
					*patch += (DWORD)ptrDiff;
				}
			}

			// Get the next relocation
			relocation = (PIMAGE_BASE_RELOCATION)GetPointerOffset(relocation, relocation->SizeOfBlock);
		}
	}

	// ****************************************************************************************************************************************************

	// Get the entry import directory
	PIMAGE_DATA_DIRECTORY directory = &(allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	// Get the first import descriptor
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(code + directory->VirtualAddress);

	// While the descriptor has a name keep looping through them all
	while (importDesc->Name)
	{
		// Declare our two reference pointers
		uintptr_t* thunkRef;
		FARPROC* funcRef;

		// Get the handle to the import (using LoadLibrary since we don't want to have to resolve all of the relative paths)
		HMODULE handle = LoadLibraryA((LPCSTR)(code + importDesc->Name));

		// If original first think then use that virtual address, otherwise use first thunk address
		if (importDesc->OriginalFirstThunk)
			thunkRef = (uintptr_t*)(code + importDesc->OriginalFirstThunk);
		else
			thunkRef = (uintptr_t*)(code + importDesc->FirstThunk);

		// Get function reference
		funcRef = (FARPROC*)(code + importDesc->FirstThunk);

		// Loop through all thunks and set the value of the function reference
		for (; *thunkRef; thunkRef++, funcRef++)
		{
			if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
			{
				*funcRef = GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(code + (*thunkRef));
				*funcRef = GetProcAddress(handle, (LPCSTR)&thunkData->Name);
			}
		}

		// increment the descriptor
		importDesc++;
	}

	// If we have a TLS directory
	if (allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		// Get the directory
		IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)(code + allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

		// Get the first callback
		PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)(tlsDirectory->AddressOfCallBacks);

		// Loop through all callbacks
		for (; pCallback && (*pCallback); ++pCallback)
		{
			// Attach the dll
			PIMAGE_TLS_CALLBACK Callback = *pCallback;
			Callback(code, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	// ****************************************************************************************************************************************************

	// typedef the DLL entry function
	typedef bool(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

	// Get the address for the entry 
	DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(code + allocatedHeaders->OptionalHeader.AddressOfEntryPoint);

	// Call the entrypoint
	(*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);

	// ****************************************************************************************************************************************************

}

void injector::MemMapInject(const char* dllPath, HANDLE hProc)
{

	hProc = GetCurrentProcess();

	// Open file in binary mode
	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

	// Get the size of the program
	size_t fileSize = File.tellg();

	// Allocate space for the data
	BYTE* data = new BYTE[fileSize];

	// Reset position to the start of the file
	File.seekg(0, std::ios::beg);

	// Read all of the file into our data
	File.read((char*)data, fileSize);

	// Close the handle to the file
	File.close();

	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)ManMap, (LPVOID)data, 0, 0);

	if (hThread != NULL) {
		CloseHandle(hThread);
	}
	else {
		ErrorHandling::ErrorExit((LPTSTR)(L"CreateRemoteThread"));
	}

	getchar();

}
```

</details>

When run this now injects whatever DLL we pass to the function into our current process. However, this will fail when being injected into some other process since the process doesn't know how to call LoadLibrayA or GetProcAddress. Because of this we will need to adjust our code and split it into two functions, the second of which we copy into the process we want to inject our code into.

## Injecting the Manually Mapped DLL

In order to copy our data into the other function we are going to have to modify our code a few different ways:

- Convert all memory modifying functions to their external versions and pass the process handle to them
- Allocate space internally for a local version of the data
- Change our section loading and base relocation to work on the local copy
- Move the import resolution to another function and strip function calls
- Copy the local version of our data over to the other process
- Call our shellcode with whatever data it needs

### Converting memory modifying functions

This first step is luckily very easy. Wherever we have VirtualAlloc, VirtualFree, and VirtualProtect, we are going to add Ex to the end of them and add a parameter at the start which is the handle to whatever proces we want to inject our code into:

```c++
unsigned char* code = (unsigned char*)VirtualAlloc((LPVOID)(ntHeaders->OptionalHeader.ImageBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
```

becomes:

```c++
unsigned char* code = (unsigned char*)VirtualAllocEx(hProc, (LPVOID)(ntHeaders->OptionalHeader.ImageBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

We do this since we need these operations to happen in the other process not our own process.

### Allocate space internall for the local version of the data

Since we need to do some modifications on the data, the headers, the sections, and the relocations, we need to have a local copy of the data. For this we are going to allocate memory and rather than setting allocatedHeaders to be based off of code we are going to base it off of that local copy:

```c++
// Attempt to allocate memory at the image base
unsigned char* code = (unsigned char*)VirtualAllocEx(hProc, (LPVOID)(ntHeaders->OptionalHeader.ImageBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// If the result was null then let the system decide where to allocate
if (code == NULL)
	code = (unsigned char*)VirtualAllocEx(hProc, NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Allocate space in the process for the data
unsigned char* localCode = (unsigned char*)VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Copy the headers from the data into the allocated memory
memcpy(localCode, data, ntHeaders->OptionalHeader.SizeOfHeaders);

// Get the pointer to the allocated headers
PIMAGE_NT_HEADERS allocatedHeaders = (PIMAGE_NT_HEADERS)(localCode + dosHeader->e_lfanew);
```

### Update Sections and Relocations to modify local copy

Since we need to perform these operations on the local copy we need to go through this code and make sure that we are offsetting everything from localCode rather than code. The only place we should still be referencing code in these sections of code is when we get the difference between the address of code and the image base in the header at the start of the relocation code.

### Move the import resolution to another function and strip function calls

When we resolve the import table we go through and load all of the required imports into our process and then update our references to point at any imported functions. This needs to be done inside of our injected process since we need the imports to be in that process. To do that we are going to create a function that we are going to copy into the other process and call. 

Since the code is going to be run in another process we need to be careful not to include any function calls in our function since these will not be pointing at an address that we can reach once we are in the new process. To get around this we are going to create a struct that we can pass to our shellcode function, this function will include the base address to our loaded dll, and then pointers to loadLibrary and getProcAddress that the other process has access to:

```c++
// LoadLibrary function 
typedef HMODULE(WINAPI tLoadLibrary)(LPCSTR);

// GetProcAddress function 
typedef FARPROC(WINAPI tGetProcAddress)(HMODULE, LPCSTR);

// Manually mapped data struct
typedef struct {
	unsigned char* code;
	tLoadLibrary* loadLibrary;
	tGetProcAddress* getProcAddress;
} MAN_MAP_DATA;
```

We then create the function, copy the code over, and use the pointers rather than the function calls in order to call those two functions:

```c++
// Shellcode we inject into the function
HINSTANCE __stdcall ManMap(MAN_MAP_DATA * data)
{

	// Get dos header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(data->code);

	// Get the pointer to the allocated headers
	PIMAGE_NT_HEADERS allocatedHeaders = (PIMAGE_NT_HEADERS)(data->code + dosHeader->e_lfanew);

	// Get the entry import directory
	PIMAGE_DATA_DIRECTORY directory = &(allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	// Get the first import descriptor
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(data->code + directory->VirtualAddress);

	auto loadLibrary = data->loadLibrary;
	auto getProcAddress = data->getProcAddress;

	// While the descriptor has a name keep looping through them all
	while (importDesc->Name)
	{
		// Declare our two reference pointers
		uintptr_t* thunkRef;
		FARPROC* funcRef;

		// Get the handle to the import (using LoadLibrary since we don't want to have to resolve all of the relative paths)
		HMODULE handle = loadLibrary((LPCSTR)(data->code + importDesc->Name));


		// If original first think then use that virtual address, otherwise use first thunk address
		if (importDesc->OriginalFirstThunk)
			thunkRef = (uintptr_t*)(data->code + importDesc->OriginalFirstThunk);
		else
			thunkRef = (uintptr_t*)(data->code + importDesc->FirstThunk);

		// Get function reference
		funcRef = (FARPROC*)(data->code + importDesc->FirstThunk);

		// Loop through all thunks and set the value of the function reference
		for (; *thunkRef; thunkRef++, funcRef++)
		{
			if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
			{
				*funcRef = getProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(data->code + (*thunkRef));
				*funcRef = getProcAddress(handle, (LPCSTR)&thunkData->Name);
			}
		}

		// increment the descriptor
		importDesc++;
	}

	 //If we have a TLS directory
	if (allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		// Get the directory
		IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)(data->code + allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

		// Get the first callback
		PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)(tlsDirectory->AddressOfCallBacks);

		// Loop through all callbacks
		for (; pCallback && (*pCallback); ++pCallback)
		{
			// Attach the dll
			PIMAGE_TLS_CALLBACK Callback = *pCallback;
			Callback(data->code, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	// ****************************************************************************************************************************************************

	// typedef the DLL entry function
	typedef bool(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

	// Get the address for the entry 
	DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(data->code + allocatedHeaders->OptionalHeader.AddressOfEntryPoint);

	// Call the entrypoint
	(*DllEntry)((HINSTANCE)data->code, DLL_PROCESS_ATTACH, 0);

	// ****************************************************************************************************************************************************

	// Return the base address of our loaded DLL
	return (HINSTANCE)data->code;

}

// End position of shellcode, used to dynamically determine size of the function
DWORD ManMapEnd() { return 1; }
```

We have to make sure to include the calling convetion in the shellcode as well as that we have a "function" right after our shellcode. The second function, ManMapEnd, will let us dynamically get the size of the shellcode making that we don't have to hardcode any sizes into our program.

### Copy the local version of our data over to the other process

Once we have done everything we needed to do with the local code we need to copy it into the base address that we had allocated earlier. This is done easily with a single function call:

```c++
// Copy the local code to the other process
WriteProcessMemory(hProc, code, localCode, imageSize, NULL);
```

### Call our shellcode with whatever data it needs

The last thing that we need to do it initialize our struct, allocate and copy over that data and the shellcode and then call the shellcode. Luckily this is once a again fairly simply since WINAPI does all the heavy lifting for us:

```c++
// Initialize manually mapped data struct
MAN_MAP_DATA* manMapData = new MAN_MAP_DATA;

// Set the pointer of the code
manMapData->code = code;

// Get the pointer to load library
manMapData->loadLibrary = (tLoadLibrary*)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

// Get the pointer to get proc address
manMapData->getProcAddress = (tGetProcAddress*)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetProcAddress");

// Allocate space for the manually mapped data
LPVOID man_map_data = VirtualAllocEx(hProc, NULL, sizeof(MAN_MAP_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Allocate space for the shellcode
BYTE* man_map = (BYTE*)VirtualAllocEx(hProc, NULL, (DWORD)((ULONG_PTR)ManMapEnd - (ULONG_PTR)ManMap), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Copy the data to the other function
WriteProcessMemory(hProc, man_map_data, manMapData, sizeof(MAN_MAP_DATA), NULL);

// Copy the shellcode to the other function
WriteProcessMemory(hProc, man_map, ManMap, (DWORD)((ULONG_PTR)ManMapEnd - (ULONG_PTR)ManMap), NULL);

// Create the thread in the other process
HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)man_map, man_map_data, 0, 0);
```

Once finished our code should look like:

<details>
<summary>Spoilers</summary>

```c++
// Gets the size of the section
size_t GetSectionSize(PIMAGE_NT_HEADERS headers, PIMAGE_SECTION_HEADER section) {
	// Set the size to the size of the raw data
	DWORD size = section->SizeOfRawData;

	// If the section has no raw data then set the size to the size of the data
	if (size == 0) {
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size = headers->OptionalHeader.SizeOfInitializedData;
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size = headers->OptionalHeader.SizeOfUninitializedData;
		}
	}

	// Return the size
	return (size_t)size;
}

#define GetPointerOffset(data, offset) (void*)((uintptr_t)data + offset)

// LoadLibrary function 
typedef HMODULE(WINAPI tLoadLibrary)(LPCSTR);

// GetProcAddress function 
typedef FARPROC(WINAPI tGetProcAddress)(HMODULE, LPCSTR);

// Manually mapped data struct
typedef struct {
	unsigned char* code;
	tLoadLibrary* loadLibrary;
	tGetProcAddress* getProcAddress;
} MAN_MAP_DATA;

// Shellcode we inject into the function
HINSTANCE __stdcall ManMap(MAN_MAP_DATA * data)
{

	// Get dos header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(data->code);

	// Get the pointer to the allocated headers
	PIMAGE_NT_HEADERS allocatedHeaders = (PIMAGE_NT_HEADERS)(data->code + dosHeader->e_lfanew);

	// Get the entry import directory
	PIMAGE_DATA_DIRECTORY directory = &(allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	// Get the first import descriptor
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(data->code + directory->VirtualAddress);

	auto loadLibrary = data->loadLibrary;
	auto getProcAddress = data->getProcAddress;

	// While the descriptor has a name keep looping through them all
	while (importDesc->Name)
	{
		// Declare our two reference pointers
		uintptr_t* thunkRef;
		FARPROC* funcRef;

		// Get the handle to the import (using LoadLibrary since we don't want to have to resolve all of the relative paths)
		HMODULE handle = loadLibrary((LPCSTR)(data->code + importDesc->Name));


		// If original first think then use that virtual address, otherwise use first thunk address
		if (importDesc->OriginalFirstThunk)
			thunkRef = (uintptr_t*)(data->code + importDesc->OriginalFirstThunk);
		else
			thunkRef = (uintptr_t*)(data->code + importDesc->FirstThunk);

		// Get function reference
		funcRef = (FARPROC*)(data->code + importDesc->FirstThunk);

		// Loop through all thunks and set the value of the function reference
		for (; *thunkRef; thunkRef++, funcRef++)
		{
			if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
			{
				*funcRef = getProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(data->code + (*thunkRef));
				*funcRef = getProcAddress(handle, (LPCSTR)&thunkData->Name);
			}
		}

		// increment the descriptor
		importDesc++;
	}

	 //If we have a TLS directory
	if (allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		// Get the directory
		IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)(data->code + allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

		// Get the first callback
		PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)(tlsDirectory->AddressOfCallBacks);

		// Loop through all callbacks
		for (; pCallback && (*pCallback); ++pCallback)
		{
			// Attach the dll
			PIMAGE_TLS_CALLBACK Callback = *pCallback;
			Callback(data->code, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	// ****************************************************************************************************************************************************

	// typedef the DLL entry function
	typedef bool(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

	// Get the address for the entry 
	DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(data->code + allocatedHeaders->OptionalHeader.AddressOfEntryPoint);

	// Call the entrypoint
	(*DllEntry)((HINSTANCE)data->code, DLL_PROCESS_ATTACH, 0);

	// ****************************************************************************************************************************************************

	// Return the base address of our loaded DLL
	return (HINSTANCE)data->code;

}

// End position of shellcode, used to dynamically determine size of the function
DWORD ManMapEnd() { return 1; }


void injector::ManMapInject(const char* dllPath, HANDLE hProc)
{

	// Open file in binary mode
	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

	// Get the size of the program
	size_t fileSize = File.tellg();

	// Allocate space for the data
	BYTE* data = new BYTE[fileSize];

	// Reset position to the start of the file
	File.seekg(0, std::ios::beg);

	// Read all of the file into our data
	File.read((char*)data, fileSize);

	// Close the handle to the file
	File.close();

	// Get dos header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(data);

	// Get nt headers
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(data + dosHeader->e_lfanew);

	// ****************************************************************************************************************************************************

	// Declare the variable where we will store the system information
	SYSTEM_INFO sysInfo;

	// Get the native system information
	GetNativeSystemInfo(&sysInfo);

	// Get the image size aligned to the next largest multiple of the page size
	size_t imageSize = (ntHeaders->OptionalHeader.SizeOfImage + sysInfo.dwPageSize - 1) & ~(sysInfo.dwPageSize - 1);

	// Attempt to allocate memory at the image base
	unsigned char* code = (unsigned char*)VirtualAllocEx(hProc, (LPVOID)(ntHeaders->OptionalHeader.ImageBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// If the result was null then let the system decide where to allocate
	if (code == NULL)
		code = (unsigned char*)VirtualAllocEx(hProc, NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Allocate space in the process for the data
	unsigned char* localCode = (unsigned char*)VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Copy the headers from the data into the allocated memory
	memcpy(localCode, data, ntHeaders->OptionalHeader.SizeOfHeaders);

	// Get the pointer to the allocated headers
	PIMAGE_NT_HEADERS allocatedHeaders = (PIMAGE_NT_HEADERS)(localCode + dosHeader->e_lfanew);

	// ****************************************************************************************************************************************************

	// Get first section header
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(allocatedHeaders);

	// Loop through all sections
	for (int i = 0; i < allocatedHeaders->FileHeader.NumberOfSections; i++, section++)
	{
		// Get the physical address of the section in memory
		unsigned char* segmentAddress = localCode + section->VirtualAddress;

		// If the size of the data is 0 then we are "allocating" memory for a data section
		if (!(section->SizeOfRawData))
		{
			// Check if the SectionAlignment is greater than 0, semi redundent check but better safe than sorry
			if (ntHeaders->OptionalHeader.SectionAlignment > 0)
				// Set the SectionAlignment number of bytes to 0
				memset(segmentAddress, 0, ntHeaders->OptionalHeader.SectionAlignment);
		}
		// If not a data section then we need to copy all of the data over to it
		else
			// Copy the raw data into memory
			memcpy(segmentAddress, data + section->PointerToRawData, section->SizeOfRawData);

		// Update the address in the section header to point to our loaded section
		section->Misc.PhysicalAddress = (DWORD)((uintptr_t)segmentAddress & 0xffffffff);
	}

	// Get the first section
	section = IMAGE_FIRST_SECTION(allocatedHeaders);

	// Get the physical address of the first section
	LPVOID gAddress = (LPVOID)section->Misc.PhysicalAddress;

	// Get the address of the first section aligned with the page size
	LPVOID gAlignedAddress = (LPVOID)((uintptr_t)gAddress & ~(sysInfo.dwPageSize - 1));

	// Get the section size
	size_t gSize = GetSectionSize(allocatedHeaders, section);

	// Get the section characteristics 
	DWORD gCharacteristics = section->Characteristics;

	// Set isLast to false
	bool isLast = false;

	// Loop through all sections
	for (int i = 0; i < allocatedHeaders->FileHeader.NumberOfSections; i++, section++) {

		// Get all of the information for the current section
		LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress);
		LPVOID alignedAddress = (LPVOID)((uintptr_t)sectionAddress & ~(sysInfo.dwPageSize - 1));
		SIZE_T sectionSize = GetSectionSize(allocatedHeaders, section);

		// Check if the current section is on the same page as the previous section
		if (gAlignedAddress == alignedAddress || (uintptr_t)gAddress + gSize > (uintptr_t) alignedAddress) {
			// If it is then update the characteristics with those of the current section
			if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (gCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				gCharacteristics = (gCharacteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
			}
			else {
				gCharacteristics |= section->Characteristics;
			}

			// Get the size from the start of the first section on the page up till the end of the most recent section
			gSize = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)gAddress;

			// Skip the rest of the loop
			continue;
		}

		// If the section can be discarded then free the memory
		if (gCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			// Check that a whole page is getting freed
			if (gAddress == gAlignedAddress &&
				(isLast ||
					allocatedHeaders->OptionalHeader.SectionAlignment == sysInfo.dwPageSize ||
					(gSize % sysInfo.dwPageSize) == 0)
				) {
				VirtualFreeEx(hProc, gAddress, gSize, MEM_DECOMMIT);
			}
		}

		// Check if the section is executable and or readable, we ignore writeable since we are going to need
		// the sections to be writable when we do the imports once the dll is injected. The imports need to be 
		// done in the injected process while we want to do this in our injector so we need to make some exceptions.
		bool executable = (gCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		bool readable = (gCharacteristics & IMAGE_SCN_MEM_READ) != 0;

		// Array of allowed protections
		int ProtectionFlags[2][2] = { {PAGE_WRITECOPY, PAGE_READWRITE, }, {PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READWRITE,} };

		// Get the protection flag to use
		DWORD protection = ProtectionFlags[executable][readable];

		// check if we need to add the no cache flag to the protection
		if (gCharacteristics & IMAGE_SCN_MEM_NOT_CACHED) {
			protection |= PAGE_NOCACHE;
		}

		// Declare old protection
		DWORD oldProtection;

		// Change the protection of the section
		VirtualProtectEx(hProc, gAddress, gSize, protection, &oldProtection);

		// Set the new values
		gAddress = sectionAddress;
		gAlignedAddress = alignedAddress;
		gSize = sectionSize;
		gCharacteristics = section->Characteristics;

		// If this is the last section then set isLast to true
		if (i == allocatedHeaders->FileHeader.NumberOfSections - 1)
			isLast = true;
	}

	// ****************************************************************************************************************************************************

	// Get the difference between the two ImageBases
	ptrdiff_t ptrDiff = (ptrdiff_t)(code - ntHeaders->OptionalHeader.ImageBase);

	// Check if we need to perform any relocations
	if (ptrDiff)
	{
		// Get data directory
		PIMAGE_DATA_DIRECTORY directory = &(allocatedHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		// Get first base relocation
		PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(localCode + directory->VirtualAddress);

		// Loop through all relocations, check virtual address to see when to quit
		while (relocation->VirtualAddress > 0)
		{
			// Get the physical address of the relocation
			unsigned char* physicalAddress = localCode + relocation->VirtualAddress;

			// Get the first relocation information for the relocation
			unsigned short* relInfo = (unsigned short*)GetPointerOffset(relocation, sizeof(IMAGE_BASE_RELOCATION));

			// Loop through all relocation info
			for (int i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, relInfo++)
			{
				// Get the type of relocation
				int type = *relInfo >> 12;

				// Get the relocation offset
				int offset = *relInfo & 0xfff;

				// If the type is IMAGE_REL_BASED_HIGHLOW then perform our patch
				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					// Get the reference
					DWORD* patch = (DWORD*)(physicalAddress + offset);

					// Adjust the reference based on the difference between the ImageBases
					*patch += (DWORD)ptrDiff;
				}
			}

			// Get the next relocation
			relocation = (PIMAGE_BASE_RELOCATION)GetPointerOffset(relocation, relocation->SizeOfBlock);
		}
	}

	// ****************************************************************************************************************************************************

	// Copy the local code to the other process
	WriteProcessMemory(hProc, code, localCode, imageSize, NULL);

	// Initialize manually mapped data struct
	MAN_MAP_DATA* manMapData = new MAN_MAP_DATA;

	// Set the pointer of the code
	manMapData->code = code;

	// Get the pointer to load library
	manMapData->loadLibrary = (tLoadLibrary*)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	// Get the pointer to get proc address
	manMapData->getProcAddress = (tGetProcAddress*)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetProcAddress");

	// Allocate space for the manually mapped data
	LPVOID man_map_data = VirtualAllocEx(hProc, NULL, sizeof(MAN_MAP_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Allocate space for the shellcode
	BYTE* man_map = (BYTE*)VirtualAllocEx(hProc, NULL, (DWORD)((ULONG_PTR)ManMapEnd - (ULONG_PTR)ManMap), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Copy the data to the other function
	WriteProcessMemory(hProc, man_map_data, manMapData, sizeof(MAN_MAP_DATA), NULL);

	// Copy the shellcode to the other function
	WriteProcessMemory(hProc, man_map, ManMap, (DWORD)((ULONG_PTR)ManMapEnd - (ULONG_PTR)ManMap), NULL);

	// Create the thread in the other process
	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)man_map, man_map_data, 0, 0);

	if (hThread != NULL) {
		CloseHandle(hThread);
	}
	else {
		ErrorHandling::ErrorExit((LPTSTR)(L"CreateRemoteThread"));
	}

}
```


</details>