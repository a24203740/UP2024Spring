#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
import sys
import numpy as np
from pwn import *

def get2DarrayToMap():

    '''
    [[9484 9472 9472 9472 9488]
    [  32   32   32   32 9474]
    [9484 9472 9472 9472 9496]
    [9474   32   32   32   32]
    [9492 9472 9472 9472 9496]]
    = 2

    [[9484 9472 9472 9472 9488]
    [  32   32   32   32 9474]
    [  32 9472 9472 9472 9508]
    [  32   32   32   32 9474]
    [9492 9472 9472 9472 9496]]
    = 3

    [[9474   32   32   32 9474]
    [9474   32   32   32 9474]
    [9492 9472 9472 9472 9508]
    [  32   32   32   32 9474]
    [  32   32   32   32 9474]]
    = 4

    [[9484 9472 9472 9472 9472]
    [9474   32   32   32   32]
    [9492 9472 9472 9472 9488]
    [  32   32   32   32 9474]
    [9492 9472 9472 9472 9496]]
    = 5

    [[9484 9472 9472 9472 9488]
    [9474   32   32   32   32]
    [9500 9472 9472 9472 9488]
    [9474   32   32   32 9474]
    [9492 9472 9472 9472 9496]]
    = 6

    [[9484 9472 9472 9472 9488]
    [9474   32   32   32 9474]
    [  32   32   32   32 9474]
    [  32   32   32   32 9474]
    [  32   32   32   32 9474]]
    = 7

    [[9484 9472 9472 9472 9488]
    [9474   32   32   32 9474]
    [9500 9472 9472 9472 9508]
    [9474   32   32   32 9474]
    [9492 9472 9472 9472 9496]]
    = 8

    [[9484 9472 9472 9472 9488]
    [9474   32   32   32 9474]
    [9492 9472 9472 9472 9508]
    [  32   32   32   32 9474]
    [9492 9472 9472 9472 9496]]
    = 9

    [[  32   32   32   32   32]
    [  32   32 8226   32   32]
    [9472 9472 9472 9472 9472]
    [  32   32 8226   32   32]
    [  32   32   32   32   32]]
    = /

    [[  32   32   32   32   32]
    [  32   32 9474   32   32]
    [9472 9472 9532 9472 9472]
    [  32   32 9474   32   32]
    [  32   32   32   32   32]]
    = +

    [[  32   32   32   32   32]
    [  32 9586   32 9585   32]
    [  32   32 9587   32   32]
    [  32 9585   32 9586   32]
    [  32   32   32   32   32]]
    = *
    '''
    collection = np.zeros((13,5,5), dtype=int);
    collection[0] = np.array([
                        [9484, 9472, 9472, 9472, 9488],
                        [9474,   32,   32,   32, 9474],
                        [9474,   32,   32,   32, 9474],
                        [9474,   32,   32,   32, 9474],
                        [9492, 9472, 9472, 9472, 9496]
                    ])
    collection[1] = np.array([
                        [32, 9472, 9488,   32,   32],
                        [32,   32, 9474,   32,   32],
                        [32,   32, 9474,   32,   32],
                        [32,   32, 9474,   32,   32],
                        [32, 9472, 9524, 9472,   32],
                    ])
    collection[2] = np.array([
                        [9484, 9472, 9472, 9472, 9488],
                        [  32,   32,   32,   32, 9474],
                        [9484, 9472, 9472, 9472, 9496],
                        [9474,   32,   32,   32,   32],
                        [9492, 9472, 9472, 9472, 9496],
                    ])
    collection[3] = np.array([
                        [9484, 9472, 9472, 9472, 9488],
                        [  32,   32,   32,   32, 9474],
                        [  32, 9472, 9472, 9472, 9508],
                        [  32,   32,   32,   32, 9474],
                        [9492, 9472, 9472, 9472, 9496],
                    ])
    collection[4] = np.array([
                        [9474,   32,   32,   32, 9474],
                        [9474,   32,   32,   32, 9474],
                        [9492, 9472, 9472, 9472, 9508],
                        [32,   32,   32,   32, 9474],
                        [32,   32,   32,   32, 9474],
                    ])
    collection[5] = np.array([
                        [9484, 9472, 9472, 9472, 9472],
                        [9474,   32,   32,   32,   32],
                        [9492, 9472, 9472, 9472, 9488],
                        [32,   32,   32,   32, 9474],
                        [9492, 9472, 9472, 9472, 9496],
                    ])
    collection[6] = np.array([
                        [9484, 9472, 9472, 9472, 9488],
                        [9474,   32,   32,   32,   32],
                        [9500, 9472, 9472, 9472, 9488],
                        [9474,   32,   32,   32, 9474],
                        [9492, 9472, 9472, 9472, 9496],
                    ])
    collection[7] = np.array([
                        [9484, 9472, 9472, 9472, 9488],
                        [9474,   32,   32,   32, 9474],
                        [32,   32,   32,   32, 9474],
                        [32,   32,   32,   32, 9474],
                        [32,   32,   32,   32, 9474],
                    ])
    collection[8] = np.array([
                        [9484, 9472, 9472, 9472, 9488], 
                        [9474,   32,   32,   32, 9474], 
                        [9500, 9472, 9472, 9472, 9508], 
                        [9474,   32,   32,   32, 9474], 
                        [9492, 9472, 9472, 9472, 9496]
                    ])
    collection[9] = np.array([
                        [9484, 9472, 9472, 9472, 9488],
                        [9474,   32,   32,   32, 9474],
                        [9492, 9472, 9472, 9472, 9508],
                        [32,   32,   32,   32, 9474],
                        [9492, 9472, 9472, 9472, 9496],
                    ])
    collection[10] = np.array([
                        [32, 32, 32, 32, 32],
                        [32, 32, 8226, 32, 32],
                        [9472, 9472, 9472, 9472, 9472],
                        [32, 32, 8226, 32, 32],
                        [32, 32, 32, 32, 32],
                    ])
    collection[11] = np.array([
                        [32, 32, 32, 32, 32],
                        [32, 32, 9474, 32, 32],
                        [9472, 9472, 9532, 9472, 9472],
                        [32, 32, 9474, 32, 32],
                        [32, 32, 32, 32, 32],
                    ])
    collection[12] = np.array([
                        [32, 32, 32, 32, 32],
                        [32, 9586, 32, 9585, 32],
                        [32, 32, 9587, 32, 32],
                        [32, 9585, 32, 9586, 32],
                        [32, 32, 32, 32, 32],
                    ])
                    
    collectionMap = {  
        collection[0].tobytes(): 0,
        collection[1].tobytes(): 1,
        collection[2].tobytes(): 2,
        collection[3].tobytes(): 3,
        collection[4].tobytes(): 4,
        collection[5].tobytes(): 5,
        collection[6].tobytes(): 6,
        collection[7].tobytes(): 7,
        collection[8].tobytes(): 8,
        collection[9].tobytes(): 9,
        collection[10].tobytes(): '/',
        collection[11].tobytes(): '+',
        collection[12].tobytes(): '*'
    }
    return collectionMap;



    



def get_substring_between_two_words(s, word1, word2):
    try:
        start = s.index(word1) + len(word1)
        end = s.index(word2, start)
        return s[start:end]
    except ValueError:
        return ""

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1];
    print(time.time(), "solving pow ...");
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest();
        if h[:6] == '000000':
            solved = str(i).encode();
            print("solved =", solved);
            break;
    print(time.time(), "done.");
    r.sendlineafter(b'string S: ', base64.b64encode(solved));

def get_one_equation(r):
    r.recvuntil(b': ');
    base64string = r.recvuntil(b' = ?');
    base64string = base64string[:-4];
    decodeString = base64.b64decode(base64string).decode('utf-8')
    print(decodeString);
    return decodeString;

def string_to_ord(s):
    lines = s.split('\n')
    wordCount = int(len(lines[0]) / 7);
    print(wordCount);
    ord_values = np.zeros((wordCount,5,5), dtype=int);
    lineIndex = 0;
    for line in lines:
        wordIndex = 0;
        for i in range(1, len(line), 7):
            ord_values[wordIndex][lineIndex] = np.array([ord(line[i]), ord(line[i+1]), ord(line[i+2]), ord(line[i+3]), ord(line[i+4])]);
            wordIndex += 1;
        lineIndex += 1;
    return ord_values;

if __name__ == "__main__":

    arrayToStrMap = get2DarrayToMap();

    r = None
    if len(sys.argv) == 2:
        r = remote('localhost', int(sys.argv[1]))
    elif len(sys.argv) == 3:
        r = remote(sys.argv[2], int(sys.argv[1]))
    else:
        r = process('./pow.py')
    solve_pow(r);
    welcome = r.recvuntil(b'limited time.');
    welcome = welcome.decode('utf-8');
    print(welcome);
    count = get_substring_between_two_words(welcome, "complete the ", " challenges");
    print("count =", count);
    for i in range(int(count)):
        print("solving equation ... ==============================");
        equationString = get_one_equation(r);
        words = string_to_ord(equationString);
        deImageEquation = "";
        for word in words:
            deImageEquation += str(arrayToStrMap[word.tobytes()]);
            print(arrayToStrMap[word.tobytes()], end='');
        print(" = ", end='')
        answer = str(int(eval(deImageEquation)));
        print(answer, end='\n');
        r.sendline(answer.encode('utf-8'));
    print(r.recvline().decode());
    r.interactive();
    r.close();

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
