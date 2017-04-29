#!/bin/bash
./madcrypt $1.exe -o $1_new.exe
du -b $1.exe $1_new.exe
md5sum $1.exe $1_new.exe
wine $1_new.exe

