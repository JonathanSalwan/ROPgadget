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
    gadgets_content_set = set()
    unique_gadgets = []
    for gadget in currentGadgets:
        gad = gadget["gadget"]
        if gad in gadgets_content_set:
            continue
        gadgets_content_set.add(gad)
        unique_gadgets += [gadget]
    return unique_gadgets

def alphaSortgadgets(currentGadgets):
    return sorted(currentGadgets, key=lambda key : key["gadget"]) 

