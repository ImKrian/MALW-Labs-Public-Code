#!/usr/bin/env python
### Author: René Serral
###  Version: 0.1 pre-alpha
### This code is a proof of concept doesn't try to be very
###   professional or even to work on all circumstances. Use at your own risk

import sys
import re

NOP = '90'

class ASMEmbedding:
  original_dump = ""

  __composed_instruction = []
  __finalcode = []

  first_iteration = True
  max_instructions = 6

  def __finalcode_build_header(self):
    self.__finalcode.append("global _start")
    self.__finalcode.append("section .text")
    self.__finalcode.append("_start:")

  def __finalcode_build_fist_instruction(self):
    self.__finalcode.append("mov rax, 0x04eb" + ''.join(self.__composed_instruction))
    self.__finalcode.append("jmp short -9")

  def __finalcode_build_instruction(self):
    self.__finalcode.append("mov rax, 0x02eb" + ''.join(self.__composed_instruction))

  def append_instructions (self, instruction_list):
    if not self.__instructions_fit(instruction_list):
      return False

    for element in instruction_list:
      self.__composed_instruction.insert(0, element)

    return True

  def __pad_nops(self):
    while len(self.__composed_instruction) < self.max_instructions:
      self.__composed_instruction.insert(0, NOP)

  def commit_instruction(self):
    self.__pad_nops()

    if self.first_iteration:
      self.first_iteration = False
      self.__finalcode_build_header()
      self.__finalcode_build_fist_instruction()
    else:
      self.__finalcode_build_instruction()
    self.__composed_instruction = []

  def __parse_line(self, inp):
    result = None
    if inp.startswith(" "):
      result = re.search("( +[0-9a-f]+:)\t+(([0-9a-f][0-9a-f] )+)", inp)
      if result is not None:
        result = result.groups()[1].split(" ")
        result.pop()
    return result
  
  def __instructions_fit(self, instructions):
    if len(instructions) + len(self.__composed_instruction) <= self.max_instructions:
      return True
    return False
  
  def __init__(self, dump):
    self.original_dump = dump
    for line in dump.splitlines():
      instructions = self.__parse_line(line)
      if instructions is None or len(instructions) == 0:
        continue

      if self.__instructions_fit(instructions):
        self.append_instructions(instructions)
        instructions = []
        continue

      self.commit_instruction()
      self.append_instructions(instructions)
    print ('\n'.join(self.__finalcode))

if __name__ == "__main__":
  source = ""
  if len(sys.argv) != 2:
    print ("Reading from standard input the objdump file", file=sys.stderr)
    source = sys.stdin.read()
  else:
    with open(sys.argv[1],'r') as file:
      source = file.read()
  ASMEmbedding(source)
