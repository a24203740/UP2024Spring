mov EAX, [0x600000]
mov EBX, -1
imul EBX ; signed multiply
mov EBX, [0x600004]
imul EBX
mov EBX, [0x600008]
add EAX, EBX
done: