+++
title = 'Understanding the Windows Portable Executable, Part 2 - Imports & Exports'
date = 2024-05-01T20:54:07+01:00
draft = false
tags = ["Malware Analysis", "Malware Development"]
+++

## Introduction

This post follows [part 1](https://pygrum.github.io/posts/understanding-windows-pe-1-pe-format/) of the Windows PE series, where we parsed basic information about a Windows portable executable, including whether it was 64-bit or not, the compile time, section count, and section sizes. In this article, we parse imported and exported functions in the PE.

### Why?

Imports and exports can prove to be very useful when determining the true nature of malware. Predictions about the malware class or behaviour can be made with reasonable accuracy, if already confirmed to be malicious. For example, seeing that a sample only imports 'LoadLibrary' and 'GetProcAddress' can tell an analyst that malware dynamically loads the rest of its imports. Or, seeing Crypt\*, filesystem and networking functions being imported can suggest that a particular sample may be ransomware. The more data we can extract from artefacts and examine, the better our evaluations will be.

### Note

Here are some important things to consider.
- Typically, more advanced malware would not make it very easy to determine its functionality based simply off of imports and exports. Further advanced static and dynamic analysis techniques are required to create a full picture.
- Various Kernel32 functions are linked to binaries by default when compiled using a recent version of MSVC. This is because Microsoft's C runtime library uses these functions.
- In this article, for simplicity, we will only go over import and export parsing for 64-bit PEs.

All the information and techniques used in this article was found and derived from official Microsoft documentation, listed under 'References' at the end of this article. This is to emulate how early implementations of components of PE parsers or loaders may have been researched and developed.

## Read The Manual!

So, where do we find import and export information? The `.edata` and `.idata` sections [typically](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only%3A~%3Atext%3DSection%2520%28Object%2520Only%29-%2CThe%2520.edata%2520Section%2520%28Image%2520Only%29%2CImport%2520Address%2520Table%2C-The%2520.pdata%2520Section) contain this information. However, this isn't always the case. You'll find during this article that the section that contains the import / export data does not matter to us, as we'll write a function to automatically locate this data based on a provided RVA.

## Import Directory Table (IDT)

There's a comprehensive enough section on the IDT in [this section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table) of the PE format specification. Look in particular at the structure for each import directory entry, represented as a table. To get access to this data, we need to know where to find the IDT. Once again, we consult the docs and see that the import table is [one of the data directories](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only) in the optional header. It's shown as the second entry. [`Winnt.h`](https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-tools/widl/include/winnt.h) (the header that provides most of this information) contains useful macros for each entry in case we forget, or they are changed in the future.

Since we already parsed the NT headers in the last post, we can easily fetch the import directory programmatically.

```c
DWORD ImportCount = 0;
ImportDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
```

Now, from the documentation, we can see how each `IMAGE_DATA_DIRECTORY` entry looks like.

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

This virtual address is described as the RVA (relative virtual address) of the table in memory. 

### Working with RVAs

>  The RVA is the address of the table relative to the base address of the image when the table is loaded.

The important part here is _when the table is loaded_. This means that we can't calculate the RVA by simply offsetting from the base address, since how the PE is structured on disk is not how it will be structured once loaded by Windows. Remember that we find import and export data in `.idata` and `.edata`? If these sections aren't yet mapped into memory, how would we reliably find data?

Well, we can calculate the RVA without needing to load the entire image. It just requires a bit of math (no, sorry, you'll never escape math).

First of all, we need to understand that relative virtual addresses are addresses for once the image is loaded correctly in memory. A section's virtual address is an RVA, as is a data directory's virtual address. To get the raw address (file offset), we need to first find where the raw data is stored, and then find the offset that our RVA will be located at, relative to the base of the raw data.

We know that raw section data will be loaded at `VirtualAddress` (an RVA), and so because the data directory's address is also an RVA within that section, we can find its offset from the section start based on where they both will be once loaded. This is (directoryVA - sectionVA). Now that we know the virtual offset, we can use it to calculate the raw offset. Remember, though, that the raw offset is relative to the image base, so we need to add the base address on too.  
Our final equation looks like this:

imageBase + rawOffset + (directoryVA - sectionVA)

Thankfully, that's just the hardest bit. Since we're going to need to do this for any data that lies within a section, we need to craft a generic function that can:
1. Find which section contains the RVA we want converted
2. Get the raw section data
3. Calculate the absolute offset of the data from the section's raw data
4. Correct and apply to the section base on disk, and the image base

```c
// Converts RVAs found in the image headers to raw file offsets. If an RVA is not found within a section, NULL is returned.
DWORD_PTR RvaToRaw(PPE_CONTEXT Ctx, DWORD RVA) {
	PIMAGE_FILE_HEADER lpFileHeader = Ctx->pFileHeader;
	BYTE* lpOptionalHeader = &Ctx->pNtHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER lpSections = (PIMAGE_SECTION_HEADER)(lpOptionalHeader + lpFileHeader->SizeOfOptionalHeader);
	for (int i = 0; i < lpFileHeader->NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER section = lpSections[i];
		// If RVA is located within section, find the offset relative to section's VA after loading, and then use that as an offset from 
		// PointerToRawData. 
		if (RVA >= section.VirtualAddress && RVA <= section.VirtualAddress + section.Misc.VirtualSize)
			return (CHAR*)Ctx->pImageBase + section.PointerToRawData + (RVA - section.VirtualAddress);
	}
	return NULL;
}
```

Pretty straightforward once implemented!

### Import Descriptors

Now we can move on to parsing import directory entries. As mentioned earlier, there is a table that describes each entry, with the offset of each field shown. Even more handy is the struct that Microsoft provides us in `Winnt.h` for parsing these, `IMAGE_IMPORT_DESCRIPTOR`, although we could define them ourselves if we wanted to.

So, we can get our first image import descriptor using our `RvaToRaw` function and the virtual address of the import directory, as the directory points immediately to the first image import descriptor.

```c
PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToRaw(pCtx, ImportDirectory.VirtualAddress));
```

What if a function has no imports? then the resulting `pImageImportDescriptor` would be NULL. We check the value of the pointer first before discovering imports at all.

Each `IMAGE_IMPORT_DESCRIPTOR` contains the name of the imported DLL in the `Name` field. Checking the definition of the struct (`Ctrl+Click` in Visual Studio 2022), we see that the OriginalFirstThunk is an RVA to the import address table, represented as an array of `PIMAGE_THUNK_DATA` (see code comments). The PIMAGE_THUNK_DATA struct actually contains the [Hint/Name table](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#hintname-table) in the `AddressOfData` field, so we can use it to find the specific imported functions from the DLL.

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

...

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE 
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;

...

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```
*Directly from winnt.h*

Now we have a plan of action.
1. Loop through all imported modules (`IMAGE_IMPORT_DESCRIPTOR`)
2. Extract thunk data (`IMAGE_THUNK_DATA`) from `OriginalFirstThunk`
3. For each thunk data, loop through hint/name table (`AddressOfData` field; `PIMAGE_IMPORT_BY_NAME`) and save `Name` field (which is an RVA)

I'll save this data to an import context struct I defined, which is part of the original context structure from the first part of the series as `ImportCtxList`.

```c
typedef struct _PE_IMPORT_CONTEXT {
	LPSTR szName;
	DWORD ImportCount;
	LPSTR ImportTable[ PE_MAXIMUM_IMPORTS ];
	struct _PE_IMPORT_CONTEXT *Next;
} PE_IMPORT_CONTEXT, *PPE_IMPORT_CONTEXT;
```

Here's the code that does this:

```c
if (pImageImportDescriptor)
{
	PPE_IMPORT_CONTEXT pLastImportCtx = NULL;
	for (; pImageImportDescriptor->Characteristics; pImageImportDescriptor++)
	{
		PPE_IMPORT_CONTEXT pImportCtx = NULL;
		pImportCtx = (PPE_IMPORT_CONTEXT)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PE_IMPORT_CONTEXT));
		if (!pImportCtx)
			return PE_IMPORT_CTX_ALLOC_FAILED;
		PIMAGE_THUNK_DATA pImageImportEntry;
		DWORD ImportEntryCount = 0;
		pImportCtx->szName = RvaToRaw(pCtx, pImageImportDescriptor->Name);
		// First original thunk is the first IAT entry.

		for (pImageImportEntry = RvaToRaw(pCtx, pImageImportDescriptor->OriginalFirstThunk);
			pImageImportEntry->u1.AddressOfData != NULL;
			pImageImportEntry++)
		{
			PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)pImageImportEntry->u1.AddressOfData;
			if (ImportEntryCount <= PE_MAXIMUM_IMPORTS)
				pImportCtx->ImportTable[ImportEntryCount] = RvaToRaw(pCtx, pImportName->Name);
			ImportEntryCount++;
		}
		pImportCtx->ImportCount = ImportEntryCount;
		if (pLastImportCtx)
			pLastImportCtx->Next = pImportCtx;
		else
			pCtx->ImportCtxList = pImportCtx;
		pLastImportCtx = pImportCtx;
		ImportCount++;
	}
}
```

## Export Directory Table (EDT)

The export table is thankfully much simpler to extract. We can save the name of each export to a regular string array, unlike imports, where each imported function is linked to a module.

First, we have to get the export directory. The `IMAGE_DIRECTORY_ENTRY_EXPORT` macro is the index of the export directory table. The `PIMAGE_EXPORT_DIRECTORY` is the struct provided by Microsoft that's used to extract the [export directory fields](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table).

```c
ExportDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
PIMAGE_EXPORT_DIRECTORY pImageExportData = (PIMAGE_EXPORT_DIRECTORY)(RvaToRaw(pCtx, ExportDirectory.VirtualAddress));
```

### Extracting Export Information

Once again, we should check if there are any exports at all, which we could confirm by testing if `pImageExportData` is NULL. Once confirmed, we need to get the name pointer table, which is an RVA to an array of RVAs to the export names. Looking at the export directory table fields, and the `PIMAGE_EXPORT_DIRECTORY` definition, the `AddressOfNames` field contains this data.

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

Since this is just a regular array, we just need to convert each item into a raw pointer, and add it to our context structure. I chose to use a field called `ExportList` that is a fixed-size array of strings.

```c
if (pImageExportData)
{
	DWORD* pNameTable = RvaToRaw(pCtx, pImageExportData->AddressOfNames);
	for (int i = 0; i < pImageExportData->NumberOfNames; i++)
	{
		if (ExportCount <= PE_MAXIMUM_EXPORTS)
			pCtx->ExportList[i] = RvaToRaw(pCtx, pNameTable[i]);
		ExportCount++;
	}
	pCtx->ExportCount = ExportCount;
}
return PE_SUCCESS;
```

## Results

Here's the output from running the tool on a DLL and EXE on my system.

DLL:

```
Name:                   api-ms-win-core-file-l1-2-0.dll
Is 64-bit:              1
Compile time (epoch):   -239993235

Sections (2)
========

Name: .rdata
Size: 1024 bytes
RVA: 1000

Name: .rsrc
Size: 1024 bytes
RVA: 2000

Exports (4)
=======
* CreateFile2
* GetTempPathW
* GetVolumeNameForVolumeMountPointW
* GetVolumePathNamesForVolumeNameW
```

EXE:

```text
Name:                   C:\msys64\clang32.exe
Is 64-bit:              1
Compile time (epoch):   0

Sections (11)
========

Name: .text
Size: 30720 bytes
RVA: 1000

Name: .data
Size: 512 bytes
RVA: 9000

Name: .rdata
Size: 5120 bytes
RVA: a000

Name: .pdata
Size: 1536 bytes
RVA: c000

Name: .xdata
Size: 1536 bytes
RVA: d000

Name: .bss
Size: 0 bytes
RVA: e000

Name: .idata
Size: 2560 bytes
RVA: f000

Name: .CRT
Size: 512 bytes
RVA: 10000

Name: .tls
Size: 512 bytes
RVA: 11000

Name: .rsrc
Size: 32768 bytes
RVA: 12000

Name: .reloc
Size: 512 bytes
RVA: 1a000

Imports (21)
=======
Library name: KERNEL32.dll
        * CreateProcessW
        * DeleteCriticalSection
        * EnterCriticalSection
        * ExpandEnvironmentStringsW
        * FormatMessageW
        * GetCommandLineW
        * GetLastError
        * GetModuleFileNameW
        * GetStartupInfoW
        * InitializeCriticalSection
        * IsDBCSLeadByteEx
        * LeaveCriticalSection
        * LocalFree
        * MultiByteToWideChar
        * SetEnvironmentVariableW
        * SetLastError
        * SetUnhandledExceptionFilter
        * Sleep
        * TlsGetValue
        * VirtualProtect
        * VirtualQuery

Library name: msvcrt.dll
        * __C_specific_handler
        * ___lc_codepage_func
        * ___mb_cur_max_func
        * __iob_func
        * __lconv_init
        * __set_app_type
        * __setusermatherr
        * __wgetmainargs
        * __winitenv
        * _amsg_exit
        * _cexit
        * _commode
        * _errno
        * _fmode
        * _initterm
        * _onexit
        * fwprintf
        * _wcmdln
        * _wcsdup
        * _wcserror
        * _wcsicmp
        * _wfopen
        * abort
        * calloc
        * exit
        * fclose
        * feof
        * fgetws
        * fprintf
        * fputwc
        * free
        * fwrite
        * localeconv
        * malloc
        * memcpy
        * memset
        * realloc
        * signal
        * strerror
        * strlen
        * strncmp
        * vfprintf
        * wcschr
        * wcscmp
        * wcscpy
        * wcslen
        * wcsrchr

Library name: USER32.dll
        * MessageBoxW
```

## References

- `winnt.h` (Visual Studio)
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

The full code can be found [here](https://github.com/pygrum/WindowsPE#importexport) on GitHub.
