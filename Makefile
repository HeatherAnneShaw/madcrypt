all:
	gcc -m32 -I./include -c madcrypt.c -o madcrypt.o
	
	nasm -f elf stubs/win32_exe.s -o win32_exe.o
	gcc -m32 -I./include -c stubs/win32_exe.c -o win32_exe_c.o
	
	gcc -m32 -o madcrypt madcrypt.o win32_exe.o win32_exe_c.o

clean:
	rm madcrypt
	rm *.o

git:
	make clean
	git add *
	git commit
	git push

