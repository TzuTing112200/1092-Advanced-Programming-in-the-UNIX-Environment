; addsub1: 2500
mov eax, 0x5f1c68ff
add eax, 0xe90dc380
sub eax, 0xb1f05181
done:


; addsub2: 2501
mov eax, [0x600000]
add eax, [0x600004]
sub eax, [0x600008]
mov [0x60000c], eax
done:


; swapreg: 2520
xchg eax, ebx
done:


; swapmem: 2519
mov eax, [0x600000]
mov ebx, [0x600008]
xchg eax, ebx
mov [0x600000], eax
mov [0x600008], ebx
done:


; leax: 2508
lea eax, [edi * 2]
lea ebx, [edi * 2 + edi]
lea ecx, [edi * 4 + edi]
lea edx, [edi * 8 + edi]
done:


; eval1: 2506
mov eax, [0x600000]
neg eax
add eax, [0x600004]
sub eax, [0x600008]
mov [0x60000c], eax
done:


; tolower: 2521
mov eax, [0x600000]
sub eax, 0x20
mov [0x600001], eax
done:


; clear17: 2503
and eax, 0xfffdffff
done:


; dec2ascii: 2504
add eax, 0x30
done:


; * ul+lu: 2522
;add ch, 0x20
;done:
xor ch, 0x20
done:


; mulbyshift: 2516
mov eax, [0x600000]
mov ebx, [0x600000]
shl ebx, 2
add eax, ebx
add eax, ebx
add eax, ebx
shl eax, 1
mov [0x600004], eax
done:


; * isolatebit: 2507
;mov rbx, [0x600001]
;and ax, 0xfe0
;shr ax, 5
;mov [0x600000], ax
;mov [0x600001], rbx
;done:
and ax, 0xfe0
shr ax, 5
mov [0x600000], al
done:


; math1: 2510
mov eax, [0x600000]
add eax, [0x600004]
mov ebx, [0x600008]
mul ebx
mov [0x60000c], rax
done:


; math2: 2511
mov eax, [0x600000]
neg eax
mov ebx, [0x600004]
mul ebx
add eax, [0x600008]
mov [0x60000c], rax
done:


; * math3: 2512
;mov eax, [0x600000]
;mov ebx, 0x5
;mul ebx
;mov ebx, [0x600004]
;sub ebx, 0x3
;div ebx
;mov [0x600008], rax
;done:
mov eax, [0x600000]
mov ebx, 0x5
mul ebx
mov edx, 0x0
mov ebx, [0x600004]
sub ebx, 0x3
div ebx
mov [0x600008], rax
done:


; * math4: 2513
; mov eax, [0x600004]
; neg eax
; mov ebx, [0x600008]
; idiv ebx
; mov ecx, edx
; mov eax, [0x600000]
; mov ebx, 0x5
; neg ebx
; imul ebx
; mov edx, 0x0
; mov ebx, ecx
; idiv ebx
; mov [0x60000c], eax
; done:
mov eax, [0x600004]
neg eax
mov ebx, [0x600008]
cdq
idiv ebx
mov ecx, edx
mov eax, [0x600000]
mov ebx, 0x5
neg ebx
imul ebx
mov edx, 0x0
mov ebx, ecx
cdq
idiv ebx
mov [0x60000c], eax
done:


; math5: 2514
mov eax, [0x600000]
mov ecx, [0x600004]
neg ecx
imul ecx
mov edx, 0x0
neg ebx
add ebx, [0x600008]
cdq
idiv ebx
mov [0x600008], eax
done:


; * posneg: 2517
; cmp eax, 0x0
; jae LA1
; mov eax, 0xffffffff
; mov [0x600000], eax
; jmp LA2
; LA1:
    ; mov eax, 0x1
    ; mov [0x600000], eax
; LA2:

; cmp ebx, 0x0
; jae LB1
; mov ebx, 0xffffffff
; mov [0x600004], ebx
; jmp LB2
; LB1:
    ; mov ebx, 0x1
    ; mov [0x600004], ebx
; LB2:

; cmp ecx, 0x0
; jae LC1
; mov ecx, 0xffffffff
; mov [0x600008], ecx
; jmp LC2
; LC1:
    ; mov ecx, 0x1
    ; mov [0x600008], ecx
; LC2:

; cmp edx, 0x0
; jae LD1
; mov edx, 0xffffffff
; mov [0x60000c], edx
; jmp LD2
; LD1:
    ; mov edx, 0x1
    ; mov [0x60000c], edx
; LD2:
; done:
cmp eax, 0x0
jge LA1
mov eax, 0xffffffff
mov [0x600000], eax
jmp LA2
LA1:
    mov eax, 0x1
    mov [0x600000], eax
LA2:

cmp ebx, 0x0
jge LB1
mov ebx, 0xffffffff
mov [0x600004], ebx
jmp LB2
LB1:
    mov ebx, 0x1
    mov [0x600004], ebx
LB2:

cmp ecx, 0x0
jge LC1
mov ecx, 0xffffffff
mov [0x600008], ecx
jmp LC2
LC1:
    mov ecx, 0x1
    mov [0x600008], ecx
LC2:

cmp edx, 0x0
jge LD1
mov edx, 0xffffffff
mov [0x60000c], edx
jmp LD2
LD1:
    mov edx, 0x1
    mov [0x60000c], edx
LD2:
done:


; loop15: 2509
mov ecx, 0xf
L1:
    mov al, [0x600000 + ecx - 1]
    or al, 0x20
    mov [0x600010 + ecx - 1], al
    loop L1
done:


; dispbin: 2505
mov ecx, 0x10
L0:
    mov bx, ax
    and bx, 0x1
    cmp bx, 0x0
    je L1
    mov dl, 0x31
    jmp L2
L1:
    mov dl, 0x30
L2:
    mov [0x600000 + ecx - 1], dl
    shr ax, 1
    loop L0
done:


; bubble: 2502
mov ecx, 0x9
L0:
    mov edx, 0x0
    
L1:
    mov eax, [0x600000 + edx * 4]
    mov ebx, [0x600000 + (edx + 1) * 4]
    cmp eax, ebx
    jg L2
    jmp L3
L2:
    mov [0x600000 + edx * 4], ebx
    mov [0x600000 + (edx + 1) * 4], eax
L3:
    add edx, 0x1
    cmp edx, ecx
    jl L1
    
    loop L0
done:


; minicall: 2515
    call   a
    jmp    exit

a:
    pop    rax
    push   rax
    ret
    
exit:
done:


; recur: 2518
    mov rdi, 23
    call   r
    jmp    exit

r:
    cmp rdi, 0x0
    jle L0
    cmp rdi, 0x1
    je L1
    jmp L2
L0:
    mov rsi, 0x0
    jmp return
L1:
    mov rsi, 0x1
    jmp return
L2:
    sub rdi, 0x1
    push rdi
    
    call r
    mov rax, rsi
    mov rbx, 0x2
    mul rbx
    mov rdx, 0x0
    mov rsi, rax
    
    pop rdi
    push rax
    
    sub rdi, 0x1
    call r
    mov rax, rsi
    mov rbx, 0x3
    mul rbx
    mov rdx, 0x0
    mov rsi, rax
    
    pop rax
    
    add rax, rsi
    mov rsi, rax
    
    jmp return
    
return:
    ret
    
exit:
done:

