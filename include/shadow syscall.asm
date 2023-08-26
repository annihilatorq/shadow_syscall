public asm_syscall
 
.code
 
asm_syscall proc
    mov r10, rcx
    pop rcx
    pop rax
    mov QWORD PTR [rsp], rcx
    mov eax, [rsp + 24]
    syscall
    sub rsp, 8
    jmp QWORD PTR [rsp + 8]
asm_syscall endp

end
