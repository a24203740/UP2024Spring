mov CL, [0x600000]
cmp CL, 97
jge toUpper
store:
    mov [0x600001], CL
    jmp end
toUpper:
    sub CL, 32
    jmp store
end:
done: