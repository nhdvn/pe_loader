

#include "pch.h"
#include "loader.h"

void ExploreFile(char* input, char* output)
{
	FILE* pefile = fopen(input, "rb");

	outfile = fopen(output, "w+");

	// dos header

	int dos_offset = 0;

	DOS_HEADER dos_header;

	fread(&dos_header, sizeof(dos_header), 1, pefile);

	dos_header.write(dos_offset);


	// nt offset

	int nt_offset = dos_header.e_lfanew;

	fseek(pefile, nt_offset, SEEK_SET);

	// nt header

	NT_HEADER nt_header;

	fread(&nt_header, sizeof(nt_header), 1, pefile);

	nt_header.write(nt_offset);


	// file offset

	int file_offset = nt_offset + sizeof(nt_header);

	// file header

	FILE_HEADER file_header;

	fread(&file_header, sizeof(file_header), 1, pefile);

	file_header.write(file_offset);


	// optional offset

	int optional_offset = file_offset + sizeof(file_header);

	// optional header

	if (file_header.SizeOfOptionalHeader == 224)
	{
		OPTIONAL_HEADER32 optional_header;

		fread(&optional_header, sizeof(optional_header), 1, pefile);

		optional_header.write(optional_offset);
	}
	else if (file_header.SizeOfOptionalHeader == 240)
	{
		OPTIONAL_HEADER64 optional_header;

		fread(&optional_header, sizeof(optional_header), 1, pefile);

		optional_header.write(optional_offset);
	}


	// section offset

	int section_offset = optional_offset + file_header.SizeOfOptionalHeader;

	// section header

	for (int i = 0; i < file_header.NumberOfSections; i++)
	{
		SECTION_HEADER section_header;

		fread(&section_header, sizeof(section_header), 1, pefile);

		section_header.write(section_offset);

		section_offset += sizeof(section_header);
	}
}