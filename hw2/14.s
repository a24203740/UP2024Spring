; (var3 - ebx)
mov EAX, [0x600008]
sub EAX, EBX
mov R8D, EAX
; (var1 * -var2)
mov EAX, [0x600000]
mov EBX, [0x600004]
neg EBX
imul EBX
    ; truncate the result, sign extend EAX
    mov EDX, 0
    cmp EAX, 0
    jge div
    mov EDX, -1
div: ; (var1 * -var2) / (var3 - ebx)
idiv R8D
mov [0x600008], EAX
done: