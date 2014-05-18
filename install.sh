#!/bin/sh
PREFIX=dependencies/capstone
BINDING=bindings/python
cd $PREFIX
./make.sh
sudo ./make.sh install
cd $BINDING
sudo make install
exit
