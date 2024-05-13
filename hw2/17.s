mov R8D, 1
mov R9D, -1
cmp eax, 0
mov [0x600000], R9D
jge var1
var1ret:
cmp ebx, 0
mov [0x600004], R9D
jge var2
var2ret:
cmp ecx, 0
mov [0x600008], R9D
jge var3
var3ret:
cmp edx, 0
mov [0x60000c], R9D
jge var4
var4ret:
jmp exit
var1:
mov [0x600000], R8D
jmp var1ret
var2:
mov [0x600004], R8D
jmp var2ret
var3:
mov [0x600008], R8D
jmp var3ret
var4:
mov [0x60000c], R8D
jmp var4ret
exit:
done: