; argument store in R8
mov R8, <argument>
call r
jmp end
mov RAX, R9

r:
    cmp R8, 0
    jle if_arg_0
    cmp R8, 1
    je if_arg_1
    ; else
        push R8 ; R8
        sub R8, 1
        call r
        mov RAX, R9
        mov R10, 2
        mul R10
        pop R8 ; R8
        push RAX ; 2 * r(R8 - 1)
        sub R8, 2
        call r
        mov RAX, R9
        mov R10, 3
        mul R10
        pop R10 ; 2 * r(R8 - 1)
        add RAX, R10
        mov R9, RAX
        jmp endif
    if_arg_0:
        mov R9, 0 ; return val store in R9
        jmp endif
    if_arg_1:
        mov R9, 1
        jmp endif
    endif:
        ret
end:
done: