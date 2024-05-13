mov ebx, 15
mov CL, '0'
mov DL, '1'
forLoop:
	test AX, 1
	jz put0
	jnz put1
check:	
	sub ebx, 1
	sar ax, 1
	cmp ebx, 0x0
	jge forLoop
	jmp end
put1:
	mov [0x600000 + ebx], DL
	jmp check
put0:
	mov [0x600000 + ebx], CL
	jmp check
end:
done:
		
