mov EAX, [0x600000]
add EAX, [0x600004]
mov EBX, [0x600008]
mul EBX
mov [0x60000c], EAX
done: