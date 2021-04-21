#include <windows.h>
#include <winnt.h>
#include <stdio.h>

typedef HRESULT(__cdecl* LPFNDLLFUNC1)(char*, char*);

HRESULT ExploreFile(char* FILE, char* OUTPUT)
{
	LPFNDLLFUNC1 FUNCTION;

	HRESULT RESULT;

	HINSTANCE HDLL = LoadLibraryA("FormatLoader");

	if (NULL != HDLL)
	{
		FUNCTION = (LPFNDLLFUNC1)GetProcAddress(HDLL, "ExploreFile");

		if (NULL == FUNCTION)
		{
			RESULT = ERROR_DELAY_LOAD_FAILED;
		}
		else RESULT = FUNCTION(FILE, OUTPUT);

		FreeLibrary(HDLL);
	}
	else RESULT = ERROR_DELAY_LOAD_FAILED;

	return RESULT;
}

int main(int argc, char** argv)
{
	const char* usage = "\nUsage: FileInspector -i \x22pefile\x22 -o \x22output\x22\n";

	if (argc != 5)
	{
		printf(usage);

		return 0;
	}

	char *input = NULL, *output = NULL;

	for (int i = 0; i < argc; i++)
	{
		if (!strncmp(argv[i], "-i", 2))
		{
			input = argv[i + 1];
		}
		else if (!strncmp(argv[i], "-o", 2))
		{
			output = argv[i + 1];
		}
	}

	if (!input || !output)
	{
		printf(usage);

		return 0;
	}

	ExploreFile(input, output);

	printf("\nEnjoy Reading! \n");

	return 0;
}