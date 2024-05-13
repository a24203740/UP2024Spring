mov ebx,26
mov eax, [0x600000]
mul ebx
mov [0x600004], eax
done: