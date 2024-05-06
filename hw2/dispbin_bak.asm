mov ebx, 14
mov CL, '0'
mov DL, '1'
forLoop:
	sub ebx, 1
        cmp ebx, 0x0
        jge forLoop
done:
