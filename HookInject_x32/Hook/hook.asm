;_TEXT	SEGMENT
.586              ;Target processor.  Use instructions for Pentium class machines
.MODEL FLAT, C    ;Use the flat memory model. Use C calling conventions
.STACK            ;Define a stack segment of 1KB (Not required for this example)
.DATA             ;Create a near data segment.  Local variables are declared after
                  ;this directive (Not required for this example)
.CODE
EXTERN DynamicDetour: PROC
EXTERN DynamicTarget: dword

hook_func PROC
    push eax ; Save all registers
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push ebp
    call DynamicDetour
    pop ebp                 ; restore all registers and exit
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax

    mov eax, DynamicTarget
    ;jmp qword ptr [rax]
    push eax
    ret

hook_func ENDP

;_TEXT	ENDS
 
END