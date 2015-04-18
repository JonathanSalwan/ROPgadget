## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-17 - ROPgadget tool
## 
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.

def deleteDuplicateGadgets(currentGadgets):
    new, insts = [], []
    for gadget in currentGadgets:
        gad = gadget["gadget"]
        if gad in insts:
            continue
        insts += [gad]
        new += [gadget]
    return new

def alphaSortgadgets(currentGadgets):
    return sorted(currentGadgets, key=lambda key : key["gadget"]) 

