#!/bin/bash

export PYTHONPATH=../
if [ "$#" == "1" ]
then
  RUN="python2 ../ROPgadget.py"
else
  RUN="python3 ../ROPgadget.py"
fi

rm -rf test_output

FILES=`ls | sort -f`
for f in $FILES
do
  if [ "$f" != "test.sh" ] && [ "$f" != "ref_output.bz2" ] && [ "$f" != "test_output" ]
  then
    echo "RUN $f" | tee -a  ./test_output
    if [ "$f" == "raw-x86.raw" ]
    then
      $RUN --rawArch=x86 --rawMode=32 --depth 5 --binary $f 1>> ./test_output
    else
      $RUN --depth 5 --binary $f 1>> ./test_output
    fi
  fi
done

echo "RUN elf-Linux-x86 --ropchain" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --ropchain 1>> ./test_output
echo "RUN elf-Linux-x86 --depth 3" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --depth 3 1>> ./test_output
echo "RUN elf-Linux-x86 --string \"main\"" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --string "main" 1>> ./test_output
echo "RUN elf-Linux-x86 --string \"m..n\"" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --string "m..n" 1>> ./test_output
echo "RUN elf-Linux-x86 --opcode c9c3" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --opcode c9c3 1>> ./test_output
echo "RUN elf-Linux-x86 --only \"mov|ret\"" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --only "mov|ret" 1>> ./test_output
echo "RUN elf-Linux-x86 --only \"mov|pop|xor|ret\"" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --only "mov|pop|xor|ret" 1>> ./test_output
echo "RUN elf-Linux-x86 --filter \"xchg|add|sub|cmov.*\"" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --filter "xchg|add|sub|cmov.*" 1>> ./test_output
echo "RUN elf-Linux-x86 --norop --nosys" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --norop --nosys 1>> ./test_output
echo "RUN elf-Linux-x86 --range 0x08041000-0x08042000" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --range 0x08041000-0x08042000 1>> ./test_output
echo "RUN elf-Linux-x86 --string main --range 0x080c9aaa-0x080c9aba" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --string main --range 0x080c9aaa-0x080c9aba 1>> ./test_output
echo "RUN elf-Linux-x86 --memstr \"/bin/sh\"" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --memstr "/bin/sh" 1>> ./test_output
echo "RUN elf-Linux-x86 --badbytes \"00|01-1f|7f|42\"" | tee -a  ./test_output
$RUN --binary ./elf-Linux-x86 --badbytes "00|01-1f|7f|42" 1>> ./test_output
echo "RUN Linux_lib64.so --offset 0xdeadbeef00000000" | tee -a  ./test_output
$RUN --binary ./Linux_lib64.so --offset 0xdeadbeef00000000 1>> ./test_output
echo "RUN elf-ARMv7-ls --depth 5" | tee -a  ./test_output
$RUN --binary ./elf-ARMv7-ls --depth 5 1>> ./test_output
echo "RUN elf-ARM64-bash --depth 5" | tee -a  ./test_output
$RUN --binary ./elf-ARM64-bash --depth 5 1>> ./test_output

diff test_output <(bunzip2 --stdout ref_output.bz2) 1>&2
