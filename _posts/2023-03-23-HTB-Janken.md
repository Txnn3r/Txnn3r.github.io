---
title: HTB Cyber Apocalypse 2023 - Misc Janken
published: true
---

This writeup will walk you through how to solve the Challenge `Misc - Janken` from Hack The Box's 2023 Cyber Apocalypse CTF!

## [](#Challenge-Overview)Challenge Overview

![image](https://user-images.githubusercontent.com/101006959/227324103-28c7da9a-7d2b-426f-87db-4db5e314800a.png)

To start: From the desciption of `Janken` we can see that the goal of thoal of the challenge is to beat the guru 100 times in a row at the game.
We can also see that the game will be similar to the well known game: rock, paper, scissors.

We are given a docker instance to connect to and some files to help us beat the guru.

#### [](#files)files:

- flag.txt
- janken
- .glibc
  - ld-linux-x86-64.so.2
  - libc.so.6

Using the 'file' command in linux, we can see that `janken` is an ELF file

```
janken: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./.glibc/ld-linux-x86-64.so.2, BuildID[sha1]=56b54cdae265aa352fe2ebb016f86af831fd58d3, for GNU/Linux 3.2.0, not stripped

```
Running the file locally we are greeted with the following output:

![image](https://user-images.githubusercontent.com/101006959/227333440-cb79b7dc-9e11-4bc8-a08c-4f8a04a99ec9.png)

First, let's view the `ℜ ℧ ∟ Ӗ ⅀` of the game:

![image](https://user-images.githubusercontent.com/101006959/227333865-7a0d9a4d-5888-460f-a5be-c4fb232ca9f2.png)

From here we can see the basic rules of rock, paper, scissors; and the requirements of winning 100 times in a row in order to recieve our prize.

Let's first try `ℙ ∟ ₳ Ұ`ing the game and see what happens.

![image](https://user-images.githubusercontent.com/101006959/227383970-2c5dda68-2be8-46d4-a969-2495749bf402.png)

For this example, we chose `rock` , and the guru chose `rock`. The program doesn't seem to consider ties and from that we can assume that we have to win 
every round, no ties or losses, for 100 rounds in a row.

* * *

Next, let's get a little more in depth and go under the hood to see what the program is actually doing with our input, and maybe see if we can figure out
how the guru decides which value he will pick.

## [](#ghidra)Reading The Assembly With Ghidra

A little background: [Ghidra](https://ghidra-sre.org/) is a free and open source tool created by the NSA in order to read binaries and attempt to decompile the assembly back into source code.

First, you will want to open Ghidra, select a folder to work in, and the go to <br />`File > Import File > janken` to import the binary into Ghidra. 

Next, double click on the file `janken` and a picture of a dragon will pop up on your screen before opening the Ghidra CodeBrowser.

![image](https://user-images.githubusercontent.com/101006959/227357297-edb8cbc4-b32c-4dee-91d7-53bdb8b337d2.png)

Alternatively, you can click on the dragon icon after first opening Ghidra and go to <br />`File > Import File > janken` to open the file from within the CodeBrowser.

When first opening a binary, Ghidra will ask you if you would like to analyze the file, click `Yes` and then `Analyze`.

You should be greeted with a `Listing` of the assembly code, as well as a list of `Functions`. If you do not see the `Functions` tab, you can go to `Window > Functions` to view the different functions of the `janken` file.

Let's try viewing the main function in Ghidra and see if we can figure out what the game does & how the guru makes his choice.

![image](https://user-images.githubusercontent.com/101006959/227349063-2a76377c-ced7-4cd0-8a26-5734e4b5d644.png)

Typing `main` into the Filter bar we can see 2 functions returned, double clicking on the one named `main` will bring up Ghidra's attempt to decompile the main function.

###### [](#Note1)It is important to note that the Ghidra Decompiler may not always be 100% correct, make sure to consult your assembly code to verify!

From the `Decompile: main` tab, we can see lots of different variables and functions, but the one that I took notice of almost immediatly was `game()`. We can see that it is inside a loop that itterates by 1 and ends at 100, so this is likely our "100 rounds"!

Double clicking on the `game()` function will open the decompiled version of `game()` and we can try to take a look at how the guru makes his choice.

![image](https://user-images.githubusercontent.com/101006959/227369816-7dfaeca5-c882-46dd-9eea-a413a231e8cf.png)

Looking at the variables in the first `fprintf()` statement, we can see that the guru's choice comes from `local_78` and our choice comes from `local_38`. We can also see that `local_78` has 3 options as expected: rock, paper, and scissors. We should also note of is what decides which choice the guru makes: `iVar1 % 3`.

`iVar1` gets assigned through the following code in the function:
```c
tVar2 = time((time_t *)0x0);
srand((uint)tVar2);
iVar1 = rand();
```

### [](#code-breakdown)Code Breakdown

> `tVar2` is set to the current time in seconds (also known as Unix time).
>
> `srand((uint)tVar2);` will set the seed for the `rand()` function based on the Unix time.
>
> Finally `iVar1 = rand();` will return a random number based on the current `srand()` seed.

* * *

Knowing this, we are ready to exploit the binary! If we can set the seed for the `srand()` function to the same value as the server, we can know the guru's choice every time and base our response off of it!


## [](#solution)Crafting Our Exploit

The moment you all have been waiting for! I have attached my solve.py script below for you to view before I break it down.

```py
from pwn import *
#context.log_level='debug'
from ctypes import CDLL

libc = CDLL('libc.so.6')
def retry():
	r = remote('64.227.41.83',30682)
	line = r.recvline()
	r.send(b'1\n')
	choices = [b'paper\n',b'rock\n',b'scissors\n']
	for i in range(0,100):
		print(i)
		time = libc.time(0)
		libc.srand(time)
		choice = libc.rand()%3
		try:
			line = r.recvuntil('>> ',drop=True)
		except:
			r.close()
			retry()
		r.send(choices[choice])
	r.interactive()
retry()
```
First, let's go over the imports:

#### [](#imports)Imports

*   `pwn` was used to import pwntools to connect to the server for exploiting.
*   `CDLL` from `ctypes` was used to import functions from the C-codebase.

###### [](#Note2)`context.log_level='debug'` is not an import, but is used in conjunction with pwn to debug server connection if needed.

`libc = CDLL('libc.so.6')` was used to define which C library to load and set the variable `libc` equal to said library.

#### [](#exploit)The Exploit

We first connected to the remote server and sent a `1` in order to start the game. We set a variable with all of our `choices`, and then began the loop of 100 rounds.

###### [](#Note3)The order of `choices` is important as it is the opposite of the order of the guru's choices, meaning our index=0 will win against guru index=0.

*   We used `time = libc.time(0)` to set the `time` variable equal to the current time in seconds in the Unix epoch.
*   Next we called `libc.srand(time)` to set the seed for the `rand()` function based on the value of `time`.
*   Finally, we set our `choice` index equal to `libc.rand()%3` to get modulus 3 of the `rand()` output.

If everything goes according to plan our `libc.rand()%3` should be the same as the one running on the remote server!

Finally, the timings between the server and our machine must be synced 100 times in a row since the `srand()` function is reseeded for each round in the game. Due to inconsistencies in the speed of the server / script, it may take a couple tries to get all 100 rounds to sync up. This is the reason for the `retry()` function, and the try / except blocks.

###### [](#Note4)`r.interactive()` is called after the 100th round in the game in order to keep the standard input open, otherwise the server would close the connection without giving us the flag.

If all goes well on syncing times, then this will be our response!

#### [](#flag)Flag

![image](https://user-images.githubusercontent.com/101006959/227394152-b1bd4e87-ad39-41d6-8bae-4ed97de19ac2.png)
