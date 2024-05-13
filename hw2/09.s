mov ebx, 0
forLoop:
    mov CL, [0x600000 + ebx]
    cmp CL, 90
    jle toLower
check:	
    mov [0x600010 + ebx], CL
	add ebx, 1
	cmp ebx, 15
	jl forLoop
	jmp end
toLower:
    add CL, 32
    jmp check
end:
done: