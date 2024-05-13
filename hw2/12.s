mov EAX, [0x600000]
mov EBX, 5
mul EBX
mov EDX, 0 ; truncate overflow

mov EBX, [0x600004]
sub EBX, 3

div EBX

mov [0x600008], EAX
done: