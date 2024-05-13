cmp CH, 97
jge toUpper
jmp toLower
toUpper:
    sub CH, 32
    jmp end
toLower:
    add CH, 32
    jmp end
end:
done: