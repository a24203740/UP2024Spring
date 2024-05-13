mov eax, 0
forLoop:
	mov ebx, 0
innerLoop:
	mov ecx, [0x600000 + ebx * 4]
	mov edx, [0x600000 + ebx * 4 + 4]
	cmp ecx, edx
	jg swap
checkInner:	
	add ebx, 1
	cmp ebx, 9
	jl innerLoop
	jmp checkOuter
checkOuter:
	add eax, 1
	cmp eax, 9
	jl forLoop
	jmp end
swap:
	mov [0x600000 + ebx * 4], edx
	mov [0x600000 + ebx * 4 + 4], ecx
	jmp checkInner
end:
done:
		
