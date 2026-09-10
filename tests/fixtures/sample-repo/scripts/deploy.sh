#!/bin/bash
cd $1
rm -rf $TARGET/*
for f in $(ls *.txt); do
  echo $f
done
if [ $x == "y" ]; then echo hi; fi
