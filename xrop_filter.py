#!/usr/bin/env python
import sys
import argparse
import re

class XropBlockException(Exception):
    GENERIC_ERROR=0
    REQUIRED_MATCH_NOT_FOUND=1  #No instruction in the gadget matched the provided regex
    NEGATIVE_MATCH_FOUND=2      #A prohibited pattern specified by the regex was found in this gadget
    def __init__(self,code=0):
        super(self.__class__,self).__init__()
        self.code=code

class XropInstructionException(Exception):
    GENERIC_ERROR=0
    MALFORMED_INSTRUCTION=-1
    FILTERED_OPERATION=-2
    FILTERED_REGISTER=-3
    def __init__(self,code=0):
        super(self.__class__, self).__init__()
        self.code=code
        
        

class XropInstruction(object):
    
    """
    TODO: need arch-specific instruction classes
    so we can parse out actual instruction ops
    and registers accessed
    """
    FIRST_MARKER="> "
    def __init__(self,instruction_line,instruction_filter=[],register_filter=[]):
        self.first=False
        self.instruction_filter=instruction_filter
        self.register_filter=register_filter
        #print instruction_filter
        if instruction_line.startswith(self.FIRST_MARKER):
            self.first=True
            instruction_line=instruction_line.lstrip(self.FIRST_MARKER)
        addr,instr_bytes,instr=instruction_line.split(None,2)
        instruction_op,operands=self.__parse_instruction(instr)
        self.addr=int(addr,0)
        #I think ideally we'd be turnning this into a binary string
        #Containing the literal bytes
        # print ("%s\t%s" % (addr,instr_bytes))
        try:
            self.instr_bytes=int(instr_bytes,16)
        except ValueError:
            #print "malformed instruction at %s" % addr
            raise 
        self.__check_instruction_filter(instruction_op)
        self.instruction_op=instruction_op
        if operands:
            self.operands=operands
        else:
            self.operands=""
    
    def __parse_instruction(self, instruction):
        """
        TODO: make this smarter. Ideally:
        - Identify variations of registers (rax,eax,ah,al, etc)
        - Identify whether a register register access is read-only or write
        - Identify relationship between registers (read from A, write to B?, this gets complicated fast)
        """
        parts=instruction.split(None,1)
        if len(parts)<2:
            operand=None
        else:
             operand=parts[1]
        instruction_op=parts[0]
        return instruction_op,operand
    
    def __check_instruction_filter(self,instruction_op):
        if instruction_op in self.instruction_filter:
            raise XropInstructionException(code=XropInstructionException.FILTERED_OPERATION)
    
    def __check_register_filte(self,operand_string):
        """
        TODO: Ugh so gross
        """
        for reg in self.register_filter:
            if reg in self.operand_string:
                raise XropInstructionException(code=FILTERED_REGISTER)
    def __str__(self):
        return "%016x\t%s\t\t%s" % (self.addr,self.instruction_op,self.operands)
        
    def matches_regex(self,regex_str):
        regex=re.compile(regex_str)
        instr_str="%s   %s" % (self.instruction_op, self.operands)
        if(regex.match(instr_str)):
            return True
        else:
            return False


class XropBlock(list):
    def __init__(self,instructions,instruction_filter=[],register_filter=[],contains_regex=None,negative_match_regex=None):
        super(self.__class__,self).__init__()
        match=False
        for instr in instructions:
            xri=XropInstruction(instr,instruction_filter=instruction_filter,register_filter=register_filter)
            if(negative_match_regex):
                if xri.matches_regex(negative_match_regex):
                    raise XropBlockException(code=XropBlockException.NEGATIVE_MATCH_FOUND)
            if(contains_regex):
                if xri.matches_regex(contains_regex):
                    match=True
            self.append(xri)
        if contains_regex and (not match):
            raise XropBlockException(code=XropBlockException.REQUIRED_MATCH_NOT_FOUND)
        
    def __str__(self):
        gadget_str=XropList.SEPERATOR+"\n"
        for instr in self:
            gadget_str+=("%s\n" % instr)
        return gadget_str        


class XropList(list):
    SEPERATOR="_______________________________________________________________"
    FIRST_MARKER="> "
    
    def __init__(self,inputfile,instruction_filter=[],register_filter=[],contains_regex=None,negative_match_regex=None):
        super(self.__class__, self).__init__()
        self.instruction_filter=instruction_filter
        self.register_filter=register_filter
        gadget_lines=None
        samegadget=True
        self.total_gadgets=0
        self.filtered_gadgets=0
        self.malformed_gadgets=0
        
        with open(inputfile,"rb") as infile:
            for line in infile.readlines():
                line=line.strip()
                #if we have a list of gadget addresses
                # and the previous line was one of the separators
                # we need to construct an xrop gadget block
                # from what we have
                if gadget_lines and not samegadget:
                    try:
                        # print line
                        # print gadget_lines
                        xblock=XropBlock(gadget_lines,
                                            instruction_filter=self.instruction_filter,
                                            register_filter=self.register_filter,contains_regex=contains_regex,negative_match_regex=negative_match_regex)
                    except ValueError as ve:
                        # print ve
                        # print ("Skipping malformed gadget block.")
                        gadget_lines=None
                        self.malformed_gadgets+=1
                        continue
                    except XropInstructionException as xie:
                        if xie.code==XropInstructionException.FILTERED_OPERATION:
                            #print("Skipping filtered instruciton")
                            gadget_lines=None
                            self.filtered_gadgets+=1
                            self.total_gadgets+=1
                            continue
                        else:
                            raise
                    except XropBlockException as xbe:
                        if xbe.code==XropBlockException.REQUIRED_MATCH_NOT_FOUND:
                            #Skip gadget block lacking required match
                            gadget_lines=None
                            self.filtered_gadgets+=1
                            self.total_gadgets+=1
                            continue
                        if xbe.code==XropBlockException.NEGATIVE_MATCH_FOUND:
                            #Skip gadget block containing prohibited pattern
                            gadget_lines=None
                            self.filtered_gadgets+=1
                            self.total_gadgets+=1
                            continue
                        else:
                            raise
                    
                    gadget_lines=None
                    self.total_gadgets+=1
                    self.append(xblock)
                #If this line is one of the separators
                #We've reached the end of a gadget block
                if len(line)==0 or line == self.SEPERATOR:
                    samegadget=False
                    continue
                
                #we must have an actual gadget line
                #we should make a new list if neccessary, 
                #then add this line to the current gadget's list.
                if not gadget_lines:
                    gadget_lines=[]
                    samegadget=True
                gadget_lines.append(line)


        


def parse_args():
    parser = argparse.ArgumentParser(description='Filter xrop gadgets')
    parser.add_argument("gadget_file",type=str,help="Input file of xrop-formatted gadgets.")
    parser.add_argument("--instruction-skip",type=str,action='append',help="Exclude gadgets containing this instruction. You may specify this option multiple times.")
    parser.add_argument("--register-skip",type=str,action='append',help="Exclude gadgets referencing this register. You may specify this option multiple times.")
    parser.add_argument("--contains-regex",type=str,help="Gadget must contain an instruction matching this perl-compatible regex.")
    parser.add_argument("--negative-match-regex",type=str,help="Instructions matching this perl-compatible regex are prohibited.")
    args = parser.parse_args()
    return args
    
    
    

def main():
    args=parse_args()
    xrop_file=args.gadget_file
    instr_filter_list=args.instruction_skip
    reg_filter_list=args.register_skip
    contains_regex=args.contains_regex
    negative_match_regex=args.negative_match_regex
    print negative_match_regex
    xrop_list=XropList(xrop_file,instruction_filter=instr_filter_list,contains_regex=contains_regex,negative_match_regex=negative_match_regex)
    if instr_filter_list:
        print("Prohibited instructions: %s"%str(instr_filter_list))
    if reg_filter_list:
        print("Prohibited registers: %s" % str(reg_filter_list))
    if contains_regex:
        print("Required pattern match: %s" % contains_regex)
    if negative_match_regex:
        print("Prohibited pattern: %s" % negative_match_regex)
    print("Total gadgets found: %d" % xrop_list.total_gadgets)
    print("Gadgets filtered out: %d" % xrop_list.filtered_gadgets)
    print("Malformed gadgets: %d" % xrop_list.malformed_gadgets)
    print("Matching gadgets found: %d" % len(xrop_list))
    for rop in xrop_list:
        print rop

if __name__ == '__main__':
    main()
        
        