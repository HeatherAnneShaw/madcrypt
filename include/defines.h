
#ifndef __DEFINES__
#define  __DEFINES__

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <byteswap.h>

// I need to change all the windows definitions, not enough time for that right now
#include <windef.h>

#define PE_ALIGN(size, align, addr) ((size % align) == 0 ? addr + size : addr + (size / align + 1) * align)

typedef struct _pe_file {
    FILE *file;
    PIMAGE_DOS_HEADER dos_header;
    BYTE *dos_stub;
    PIMAGE_NT_HEADERS nt_headers;
    PIMAGE_FILE_HEADER file_header;
    PIMAGE_OPTIONAL_HEADER optional_header;
    PIMAGE_SECTION_HEADER section_header;
    size_t section_header_size;
    BYTE *sections;
} pe_file_t, *ppefile_t;


typedef enum {false, true} bool;
typedef enum { OPEN, READ, WRITE, COPY } file_errors_t;
extern void file_error(file_errors_t error);

struct arguments {
    char *binary_file;
    int silent, verbose;
    char *output_file;
};

#define FLAGS_BRUTEFORCE 1

typedef struct _image {
    DWORD flags;
    DWORD canary;
    DWORD size;
    DWORD loader_size;
    
    // code to rewrite
    BYTE loader;
    DWORD entry_point;
    
    BYTE pushad;
    
    BYTE push2;
    DWORD loader_address;
} __attribute__((packed)) image_t, *pimage_t;

typedef struct _crypt_data {
    DWORD VirtualAddress;
    DWORD Size;
} crypt_data_t, *pcrypt_data_t;

typedef bool (*is_type_t)(struct arguments arguments);
typedef bool (*inject_t)(struct arguments arguments);

typedef struct _handler {
    pimage_t image;
    is_type_t is_type;
   inject_t inject;
} handler_t;

#define HANDLERS 1

extern handler_t handlers[HANDLERS];

#endif //__DEFINES__

