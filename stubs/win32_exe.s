[bits 32]
[section .data]

global win32_exe_image

; maybe have it copy the encrypted section to where it was supposed to be
; after moving the stub to a new place in lower memory, and then decrypting and
; running the original code...
; OR >>>
; maybe embedd at the bottom of the original .text section, and then resize it to 
; fit file alignment if needed, only do this if the gap between the next section
; can accomidate in memory!!!

; add some oligomorphism in main source code, that way this bitch is randomized
; see about doing this in a way that completely randomizes length, as well as flow
; it would be nice to have it reset the offsets for jmps and memory operations

; write code to scan the executable for other binaries that might be attached, and crypt
; them as well

; make this a general purpose stub for both windows and linux, and change the file name

win32_exe_image:

flags:
    dd 0

canary:
    dd 0xC0FFEEEE

size:
    dd win32_exe_image_end - win32_exe_image

loader_size:
    dd win32_exe_image_end - loader

loader:
    push 0xDEADBEEF ; original entry point
    pushad          ; store context
    mov eax, 0xDEADC0DE ; address of loader section
    mov ebx, 1
    and ebx, dword [eax]
    jnz bruteforce  ; if bruteforce flag is set, we are going to brute force the key
return:
    popad           ; restore context
    ret             ; return to original entry point

bruteforce:
    add eax, 4           ; we are ready to get the address of the canary
    mov ebx, 0
    canary_loop:
        mov edx, dword [eax] ; move canary into edx
        xor edx, ebx         ; try key
        cmp edx, 0xC0FFEEEE  ; test canary
        je decrypt_sections  ; if successful decrypt the sections
        inc ebx              ; increment key
        jmp canary_loop      ; keep trying
        
decrypt_sections:
    sub eax, 4                        ; restore address key for easy manipulation
    add eax, win32_exe_image_end - $$ ; get first address to section offset
    section_loop:
        mov esi, dword [eax] ; get the virtual address of the section
        add eax, 4           ; get the section size pointer
        mov ecx, dword [eax] ; store the size in counter register
        test ecx, ecx        ; if size is zero, we have reached the end
        jz return
        decrypt_loop:
            sub ecx, 4
            xor dword [esi + ecx], ebx
            test ecx, ecx
            jnz decrypt_loop
        add eax, 4               ; get address for next crypt_section struct
        jmp section_loop         ; do the loopty loop 

win32_exe_image_end:
; crypt_section struct array goes here



