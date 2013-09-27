#!/usr/bin/env python

#parses the ELF structures for ELF files

import sys
from copy import copy

elf_head = [52,(16,"e_ident","s"),(2,"e_type"),(2,"e_machine"),(4,"e_version"),(4,"e_entry"),
            (4,"e_phoff"),(4,"e_shoff"),(4,"e_flags"),(2,"e_ehsize"),(2,"e_phentsize"),
            (2,"e_phnum"),(2,"e_shentsize"),(2,"e_shnum"),(2,"e_shstrndx")]

program_header = [32,(4,"p_type"),(4,"p_offset"),(4,"p_vaddr"),(4,"p_paddr"),(4,"p_filesz"),(4,"p_memsz"),
	        (4,"p_flags"),(4,"p_align")]

section_header = [40,(4,"sh_name"),(4,"sh_type"),(4,"sh_flags"),(4,"sh_addr"),
                     (4,"sh_offset"),(4,"sh_size"),(4,"sh_link"),(4,"sh_info"),
                     (4,"sh_addralign"),(4,"sh_entsize")]


def readchunk(fd,offset,size):
    fd.seek(offset)
    return fd.read(size)

def byteorder(chunk):
    ret = b''
    for i in range(len(chunk)):
        t = chunk[len(chunk)-i-1]
        if isinstance(t,int):
            ret += chunk[len(chunk)-i-1].to_bytes(1,'big')
        else:
            ret += t
    return ret

def bytestostr(chunk):
    def hexdigit(i):
        if i < 10: return str(i)
        return chr(i + ord('A') - 10)

    ret = ""
    for i in range(len(chunk)):
        if isinstance(chunk[i],int):
            ret += hexdigit(int((chunk[i]) / 16))
            ret += hexdigit(int((chunk[i]) % 16))
            ret += ' '
        else:
            ret += hexdigit(ord(chunk[i]) / 16)
            ret += hexdigit(ord(chunk[i]) % 16)

    return ret

def bytestoint(chunk):
    r = 0
    bchunk = byteorder(chunk)
    for i in range(len(bchunk)):
        if isinstance(bchunk[i],int):
            r = r*256 + bchunk[i]
        else:
            r = r*256 + ord(bchunk[i])
    return r

def parsechunk(chunk,struc):
    i = 0
    ret = {}
    for e in struc:
        if len(e) != 2: #not integer
            ret[e[1]] = bytestostr(chunk[i:i+e[0]])
        else:
            ret[e[1]] = bytestoint(chunk[i:i+e[0]])
        i += e[0]

    return ret

def print_struct(s):
    for p in s:
        x = s[p]
        if isinstance(x,int):
            print("%s : %s,%d" % (p,hex(x),x))
        else:
            print("%s : %s" % (p,x))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s program" % sys.argv[0])
        sys.exit(1)

    f = open(sys.argv[1],"rb")
    eh_struct = parsechunk(readchunk(f,0,elf_head[0]),elf_head[1:])
    print("ELF Head:")
    print_struct(eh_struct)
    print("\n--------------------------------------------------------------")

    for i in range(eh_struct["e_phnum"]):
        offset = eh_struct["e_phoff"] + eh_struct["e_phentsize"]*i
        ph_struct = parsechunk(readchunk(f,offset,program_header[0]),program_header[1:])
        print("Program header #%d (%s)" % (i,hex(offset)))
        print_struct(ph_struct)
        print("")

    print("--------------------------------------------------------------")

    for i in range(eh_struct["e_shnum"]):
        offset = eh_struct["e_shoff"] + eh_struct["e_shentsize"]*i
        sh_struct = parsechunk(readchunk(f,offset,section_header[0]),section_header[1:])
        print("Section header #%d (%s)" % (i,hex(offset)))
        if i == eh_struct["e_shstrndx"]:
            print("section header table index of the entry associated with the section name string table")
        print_struct(sh_struct)
        print("")


