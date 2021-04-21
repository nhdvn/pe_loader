
#define LOADER_API __declspec(dllexport)

#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <stddef.h>
#include <tchar.h>


#define line "+----------------------------------------------------+"

#define printf(...) fprintf(outfile, __VA_ARGS__)

#define print_dos(hset, var) printf("|%-30s|%-10X|%-10X|\n", #var, var, hset + offsetof(DOS_HEADER, var))

#define print_nt(hset, var) printf("|%-30s|%-10X|%-10X|\n", #var, var, hset + offsetof(NT_HEADER, var))

#define print_file(hset, var) printf("|%-30s|%-10X|%-10X|\n", #var, var, hset + offsetof(FILE_HEADER, var))

#define print_option32(hset, var) printf("|%-30s|%-10X|%-10X|\n", #var, var, hset + offsetof(OPTIONAL_HEADER32, var))

#define print_option64(hset, var) printf("|%-30s|%-10X|%-10X|\n", #var, var, hset + offsetof(OPTIONAL_HEADER64, var))

#define print_option64_ull(hset, var) printf("|%-30s|%-10llX|%-10X|\n", #var, var, hset + offsetof(OPTIONAL_HEADER64, var))

#define print_data(hset, dir, var) printf("|%-10s%-20s|%-10X|%-10X|\n", dir, #var, var, hset + offsetof(DATA_DIRECTORY, var))

#define print_section(hset, var) printf("|%-30s|%-10X|%-10X|\n", #var, var, hset + offsetof(SECTION_HEADER, var))

#define print_section_str(hset, var) printf("|%-30s|%-10s|%-10X|\n", #var, var, hset + offsetof(SECTION_HEADER, var))

#define print_str(name) printf("\n\n%s\n|%-30s|%-10s|%-10s|\n%s\n", line, name, "Value", "Offset", line)


FILE* outfile;


struct DOS_HEADER : public IMAGE_DOS_HEADER
{
	void write(int offset)
	{
		print_str("DOS_HEADER");
		print_dos(offset, e_magic);
		print_dos(offset, e_cblp);
		print_dos(offset, e_cp);
		print_dos(offset, e_crlc);
		print_dos(offset, e_cparhdr);
		print_dos(offset, e_minalloc);
		print_dos(offset, e_maxalloc);
		print_dos(offset, e_ss);
		print_dos(offset, e_sp);
		print_dos(offset, e_csum);
		print_dos(offset, e_ip);
		print_dos(offset, e_cs);
		print_dos(offset, e_lfarlc);
		print_dos(offset, e_ovno);
		print_dos(offset, e_res[0]);
		print_dos(offset, e_res[1]);
		print_dos(offset, e_res[2]);
		print_dos(offset, e_res[3]);
		print_dos(offset, e_oemid);
		print_dos(offset, e_oeminfo);
		print_dos(offset, e_res2[1]);
		print_dos(offset, e_res2[2]);
		print_dos(offset, e_res2[3]);
		print_dos(offset, e_res2[4]);
		print_dos(offset, e_res2[5]);
		print_dos(offset, e_res2[6]);
		print_dos(offset, e_res2[7]);
		print_dos(offset, e_res2[8]);
		print_dos(offset, e_res2[9]);
		print_dos(offset, e_lfanew);
		printf(line);
	}
};

struct FILE_HEADER : public IMAGE_FILE_HEADER
{
	void write(int offset)
	{
		print_str("FILE_HEADER");
		print_file(offset, Machine);
		print_file(offset, NumberOfSections);
		print_file(offset, TimeDateStamp);
		print_file(offset, PointerToSymbolTable);
		print_file(offset, NumberOfSymbols);
		print_file(offset, SizeOfOptionalHeader);
		print_file(offset, Characteristics);
		printf(line);
	}
};

struct DATA_DIRECTORY
{
	DWORD RVA;
	DWORD Size;

	char Member[16][20] =
	{
		"Export", "Import", "Resource", "Exception",
		"Security", "Relocate", "Debug", "Architect",
		"Reserved", "TLSTable", "Configure", "Bound",
		"IATable", "Delay", "Metadata"
	};

	DATA_DIRECTORY(int Base, IMAGE_DATA_DIRECTORY* Table)
	{
		print_str("DATA_DIRECTORY");

		for (int i = 0; i < 15; i++)
		{
			int offset = Base + i * 8;

			RVA = Table[i].VirtualAddress;
			Size = Table[i].Size;

			print_data(offset, Member[i], RVA);
			print_data(offset, "", Size);
		}

		printf(line);
	}
};


struct OPTIONAL_HEADER32 : public IMAGE_OPTIONAL_HEADER32
{
	void write(int offset)
	{
		print_str("OPTIONAL_HEADER32");
		print_option32(offset, Magic);
		print_option32(offset, MajorLinkerVersion);
		print_option32(offset, MinorLinkerVersion);
		print_option32(offset, SizeOfCode);
		print_option32(offset, SizeOfInitializedData);
		print_option32(offset, SizeOfUninitializedData);
		print_option32(offset, AddressOfEntryPoint);
		print_option32(offset, BaseOfCode);
		print_option32(offset, BaseOfData);
		print_option32(offset, ImageBase);
		print_option32(offset, SectionAlignment);
		print_option32(offset, FileAlignment);
		print_option32(offset, MajorOperatingSystemVersion);
		print_option32(offset, MinorOperatingSystemVersion);
		print_option32(offset, MajorImageVersion);
		print_option32(offset, MinorImageVersion);
		print_option32(offset, MajorSubsystemVersion);
		print_option32(offset, MinorSubsystemVersion);
		print_option32(offset, Win32VersionValue);
		print_option32(offset, SizeOfImage);
		print_option32(offset, SizeOfHeaders);
		print_option32(offset, CheckSum);
		print_option32(offset, Subsystem);
		print_option32(offset, DllCharacteristics);
		print_option32(offset, SizeOfStackReserve);
		print_option32(offset, SizeOfStackCommit);
		print_option32(offset, SizeOfHeapReserve);
		print_option32(offset, SizeOfHeapCommit);
		print_option32(offset, LoaderFlags);
		print_option32(offset, NumberOfRvaAndSizes);
		printf(line);
		
		DATA_DIRECTORY Table(offset + 96, DataDirectory);
	}
};

struct OPTIONAL_HEADER64 : public IMAGE_OPTIONAL_HEADER64
{
	void write(int offset)
	{
		print_str("OPTIONAL_HEADER64");
		print_option64(offset, Magic);
		print_option64(offset, MajorLinkerVersion);
		print_option64(offset, MinorLinkerVersion);
		print_option64(offset, SizeOfCode);
		print_option64(offset, SizeOfInitializedData);
		print_option64(offset, SizeOfUninitializedData);
		print_option64(offset, AddressOfEntryPoint);
		print_option64(offset, BaseOfCode);
		print_option64_ull(offset, ImageBase);
		print_option64(offset, SectionAlignment);
		print_option64(offset, FileAlignment);
		print_option64(offset, MajorOperatingSystemVersion);
		print_option64(offset, MinorOperatingSystemVersion);
		print_option64(offset, MajorImageVersion);
		print_option64(offset, MinorImageVersion);
		print_option64(offset, MajorSubsystemVersion);
		print_option64(offset, MinorSubsystemVersion);
		print_option64(offset, Win32VersionValue);
		print_option64(offset, SizeOfImage);
		print_option64(offset, SizeOfHeaders);
		print_option64(offset, CheckSum);
		print_option64(offset, Subsystem);
		print_option64(offset, DllCharacteristics);
		print_option64_ull(offset, SizeOfStackReserve);
		print_option64_ull(offset, SizeOfStackCommit);
		print_option64_ull(offset, SizeOfHeapReserve);
		print_option64_ull(offset, SizeOfHeapCommit);
		print_option64(offset, LoaderFlags);
		print_option64(offset, NumberOfRvaAndSizes);
		printf(line);
		
		DATA_DIRECTORY Table(offset + 112, DataDirectory);
	}
};



struct SECTION_HEADER : public IMAGE_SECTION_HEADER
{
	void write(int offset)
	{
		print_str("SECTION_HEADER:");
		print_section_str(offset, Name);
		print_section(offset, Misc.PhysicalAddress);
		print_section(offset, Misc.VirtualSize);
		print_section(offset, VirtualAddress);
		print_section(offset, SizeOfRawData);
		print_section(offset, PointerToRawData);
		print_section(offset, PointerToRelocations);
		print_section(offset, PointerToLinenumbers);
		print_section(offset, NumberOfRelocations);
		print_section(offset, NumberOfLinenumbers);
		print_section(offset, Characteristics);
		printf(line);
	}
};

struct NT_HEADER
{
	DWORD Signature;

	void write(int offset)
	{
		print_str("NT_HEADER");
		print_nt(offset, Signature);
		printf(line);
	}
};

extern "C" LOADER_API void ExploreFile(char* input, char* output);

extern "C" LOADER_API void RunLibrary(HWND hwind, HINSTANCE hinst, LPSTR lpIn, int nState)
{
	char* flag = NULL;

	char* input = strstr(lpIn, "-i");

	char* output = strstr(lpIn, "-o");

	if (input == NULL) return;

	if (output == NULL) return;


	flag = input;

	input += 2;

	if (input[0] != ' ') return;

	while (input[0] == ' ') input += 1;

	flag[0] = '\0';


	flag = output;

	output += 2;

	if (output[0] != ' ') return;

	while (output[0] == ' ') output += 1;

	flag[0] = '\0';


	ExploreFile(input, output);
}