/*
	pev - libpe the PE library

	Copyright (C) 2010 - 2012 Fernando Mercês

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef LIBPE_H
#define LIBPE_H

#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define PE32 0x10b
#define PE64 0x20b
#define MZ 0x5a4d

typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint64_t QWORD;

#define MAX_SECTIONS 96

// section name size
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

// resources types
#define RT_CURSOR         1    // cursor image
#define RT_BITMAP         2    // bitmap (.bmp)
#define RT_ICON           3    // icon
#define RT_MENU           4    // menu
#define RT_DIALOG         5    // dialog window
#define RT_STRING         6    // unicode string
#define RT_FONTDIR        7    // font directory
#define RT_FONT           8    // font
#define RT_ACCELERATOR    9    // hot keys
#define RT_RCDATA         10   // data
#define RT_MESSAGETABLE   11   // string table
#define RT_GROUP_CURSOR   12   // cursor group
#define RT_GROUP_ICON     14   // icon group
#define RT_VERSION        16   // version information
#define RT_DLGINCLUDE     17   // names of header files for dialogs (*.h) used by compiler
#define RT_PLUGPLAY       19   // data determined by application
#define RT_VXD            20   // vxd info
#define RT_ANICURSOR      21   // animated cursor
#define RT_ANIICON        22   // animated icon
#define RT_HTML           23   // html page
#define RT_MANIFEST       24   // manifest of Windows XP build
#define RT_DLGINIT        240  // strings used for initiating some controls in dialogs
#define RT_TOOLBAR        241  // configuration of toolbars

// directory Entries
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

#pragma pack(push, 1)

typedef struct _RESOURCE_ENTRY
{
	char name[20];
	unsigned int code;
} RESOURCE_ENTRY;

typedef struct _MACHINE_ENTRY
{
	char name[40];
	WORD code;
} MACHINE_ENTRY;

typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER, IMAGE_COFF_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER_32 {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	DWORD BaseOfData; // only PE32
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Reserved1;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	// IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_32;

/* note some fields are quad-words */
typedef struct _IMAGE_OPTIONAL_HEADER_64 {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	QWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Reserved1;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	QWORD SizeOfStackReserve;
	QWORD SizeOfStackCommit;
	QWORD SizeOfHeapReserve;
	QWORD SizeOfHeapCommit;
	DWORD LoaderFlags; /* must be zero */
	DWORD NumberOfRvaAndSizes;
	// IMAGE_DATA_DIRECTORY DataDirectory[];
} IMAGE_OPTIONAL_HEADER_64;

typedef struct _IMAGE_OPTIONAL_HEADER {
	IMAGE_OPTIONAL_HEADER_32 *_32;
	IMAGE_OPTIONAL_HEADER_64 *_64;
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress; // same value as next field
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations; // always zero in executables
	DWORD PointerToLinenumbers; // deprecated
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers; // deprecated
	DWORD Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	WORD NumberOfNamedEntries;
	WORD NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
	union {
		struct {
			DWORD NameOffset:31;
			DWORD NameIsString:1;
		} s1;
		DWORD Name;
		WORD Id;
	} u1;
	union {
		DWORD OffsetToData;
		struct {
			DWORD OffsetToDirectory:31;
			DWORD DataIsDirectory:1;
		} s2;
	} u2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
	DWORD OffsetToData;
	DWORD Size;
	DWORD CodePage;
	DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY;

typedef struct tagVS_FIXEDFILEINFO {
	DWORD dwSignature;
	DWORD dwStrucVersion;
	DWORD dwFileVersionMS;
	DWORD dwFileVersionLS;
	DWORD dwProductVersionMS;
	DWORD dwProductVersionLS;
	DWORD dwFileFlagsMask;
	DWORD dwFileFlags;
	DWORD dwFileOS;
	DWORD dwFileType;
	DWORD dwFileSubtype;
	DWORD dwFileDateMS;
	DWORD dwFileDateLS;
} VS_FIXEDFILEINFO;

typedef struct _IMAGE_TLS_DIRECTORY32 {
	DWORD StartAddressOfRawData;
	DWORD EndAddressOfRawData;
	DWORD AddressOfIndex;
	DWORD AddressOfCallBacks; // PIMAGE_TLS_CALLBACK
	DWORD SizeOfZeroFill;
	DWORD Characteristics; // reserved for future use
} IMAGE_TLS_DIRECTORY32;

typedef struct _IMAGE_TLS_DIRECTORY64 {
	QWORD StartAddressOfRawData;
	QWORD EndAddressOfRawData;
	QWORD AddressOfIndex;
	QWORD AddressOfCallBacks;
	DWORD SizeOfZeroFill;
	DWORD Characteristics;
} IMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
 } IMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  union {
  DWORD Characteristics; // 0 for terminating null import descriptor
  DWORD OriginalFirstThunk; // RVA to original unbound IAT
  } u1;
  DWORD TimeDateStamp;
  DWORD ForwarderChain; // -1 if no forwarders
  DWORD Name;
  // RVA to IAT (if bound this IAT has actual addresses)
  DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

// import name entry
typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD Hint;
	BYTE Name;
} IMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
	union {
		QWORD ForwarderString;
		QWORD Function;
		QWORD Ordinal;
		QWORD AddressOfData;
	} u1;
} IMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
	union {
		DWORD ForwarderString;
		DWORD Function;
		DWORD Ordinal;
		DWORD AddressOfData;
	} u1;
} IMAGE_THUNK_DATA32;

typedef struct _PE_FILE
{
	FILE *handle;
	
	bool isdll;
	WORD e_lfanew;
	WORD architecture;
	QWORD entrypoint;
	QWORD imagebase;
	QWORD size;
	
	WORD num_sections;
	WORD num_directories;
	WORD num_rsrc_entries;
	
	WORD addr_sections;
	WORD addr_directories;
	WORD addr_dos;
	WORD addr_optional;
	WORD addr_coff;
	WORD addr_rsrc_sec;
	WORD addr_rsrc_dir;
	
	// pointers (will be freed if needed)
	IMAGE_OPTIONAL_HEADER *optional_ptr;
	IMAGE_SECTION_HEADER **sections_ptr;
	IMAGE_DATA_DIRECTORY **directories_ptr;
	//IMAGE_TLS_DIRECTORY32 *tls_ptr;
	IMAGE_RESOURCE_DIRECTORY *rsrc_ptr;
	IMAGE_RESOURCE_DIRECTORY_ENTRY **rsrc_entries_ptr;
	
} PE_FILE;

#pragma pack(pop)

static const RESOURCE_ENTRY resource_types[] = 
{
	{"RT_CURSOR", 1},
	{"RT_BITMAP", 2},
	{"RT_ICON", 3},
	{"RT_MENU", 4},
	{"RT_DIALOG", 5},
	{"RT_STRING", 6},
	{"RT_FONTDIR", 7},
	{"RT_FONT", 8},
	{"RT_ACCELERATOR", 9},
	{"RT_RCDATA", 10},
	{"RT_MESSAGETABLE", 11},
	{"RT_GROUP_CURSOR", 12},
	{"RT_GROUP_ICON", 14},
	{"RT_VERSION", 16},
	{"RT_DLGINCLUDE", 17},
	{"RT_PLUGPLAY", 19},
	{"RT_VXD", 20},
	{"RT_ANICURSOR", 21},
	{"RT_ANIICON", 22},
	{"RT_HTML", 23},
	{"RT_MANIFEST", 24},
	{"RT_DLGINIT", 240},
	{"RT_TOOLBAR", 241}
};


// wrappers
void *xmalloc(size_t size);

// basic functions
bool is_pe(PE_FILE *pe);
void pe_deinit(PE_FILE *pe);
QWORD rva2ofs(PE_FILE *pe, QWORD rva);
DWORD ofs2rva(PE_FILE *pe, DWORD ofs);
QWORD pe_get_size(PE_FILE *pe);

// header functions
bool pe_init(PE_FILE *pe, FILE *handle);
bool pe_get_sections(PE_FILE *pe);
IMAGE_SECTION_HEADER* pe_get_section(PE_FILE *pe, const char* section_name);
bool pe_get_directories(PE_FILE *pe);
bool pe_get_optional(PE_FILE *pe);
bool pe_get_coff(PE_FILE *pe, IMAGE_COFF_HEADER *header);
bool pe_get_dos(PE_FILE *pe, IMAGE_DOS_HEADER *header);

//bool pe_get_tls_callbacks(PE_FILE *pe);
bool pe_get_resource_directory(PE_FILE *pe, IMAGE_RESOURCE_DIRECTORY *dir);
bool pe_get_resource_entries(PE_FILE *pe);

IMAGE_SECTION_HEADER* pe_rva2section(PE_FILE *pe, QWORD rva);

#endif

