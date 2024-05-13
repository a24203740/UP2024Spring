; (-var2 % var3)
mov EAX, [0x600004]
neg EAX
    ; sign extend EAX
    mov EDX, 0
    cmp EAX, 0
    jge firstmod
    mov EDX, -1
firstmod:
    mov EBX, [0x600008]
    idiv EBX
    mov R9D, EDX ; EDX store the remainder
; (var1 * -5)
mov EAX, [0x600000] 
mov EBX, -5
imul EBX
; truncate the result, sign extend EAX
    mov EDX, 0
    cmp EAX, 0
    jge div
    mov EDX, -1
div: ; (var1 * -5) / (-var2 % var3)
idiv R9D
mov [0x60000c], EAX
done: