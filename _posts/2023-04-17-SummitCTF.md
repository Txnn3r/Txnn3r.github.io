---
title: VT Summit CTF
published: true
---

The following are a list of writeups from Virginia Tech's `Summit CTF` from this past weekend where my team `MasonCC` and I placed 2nd overall!

Challenges: `Crypto - Ancient Encryption`, `Stego - Job Please`, `Forensics - Summit Secrets`, `Forensics - Escaping the Matrix`, `Forensics - Emergency Exfil`, `Misc - Emoji System`, and `Misc - Close Encounters`

[Forensics - Escaping the Matrix](#Forensics-/-Escaping-the-Matrix)

## [](#Crypto-AncientEncryption)Crypto - Ancient Encryption

![image](https://user-images.githubusercontent.com/101006959/232649519-21cebca1-0982-4522-aa24-4ef579dec9f2.png)


This was the only cryptography challenge at Summit CTF, it was worth 100 points and was created by `Triple Point Security`!

We are given a zip file titled `TPSCryptography.zip` which had the following files inside of it when extracted:

- .Hints.txt
- Instructions.txt

Viewing the `Instructions.txt` file, we see an encoded message and a hint on how it may have been encoded:

```
You have intercepted a message that was encrypted, but the key used to encrypt it is unknown. Your mission is to decode the message and uncover the hidden flag, which is related to the Virginia Tech Hokies and other VT Summit organizers.

Here's the encrypted message: 16sxpl 4yqr1 7okyyw47 mz 8rm Jsoqg Xv tsvh t32m mutyzqh8swr hpy3x 1vo kst4kv3g wx2iy23pmw7j irk 34piy 3zxsy85vm1wo1 zp7s2 xos 4zmwzo Xsp24 1ij92qx6 .ojwp8o ix 4.7gxywztiw3svxzsm3vp89ggv1

PS...Both Vigenere Ciphers and Caesar Ciphers are the earliest forms of encryption
```
Next I viewed the `.Hints.txt` file to see if there was any useful hints in there, shown below:

```
Alphabet: abcdefghijklmnopqrstuvwxyz1234567890.,

Shift: 7b084
```

From this we can see that there is a custom alphabet and a shift of `7b084`. I then used [dCode](https://www.dcode.fr/)'s website and tried using Caesar & Vigenere cipher's to decode the message.

During the competition I first used a Caesar cipher with a custom alphabet and shift as stated in `.Hints.txt` and then used a Vigenere cipher with a custom alphabet and correctly decoded the flag!

However, redoing the challenge for this writeup I simply put the ciphertext into the Vigenere decoder with the custome alphabet and hit `automatic decryption` and the following was my result:

```
TRiple point security is the Flag9 To find more information about the company0 internships0 and other opportunities visit the triple Point security .a0ol1a 9p z.z3nqssf9oylhnrofolh4237nw
```
I believe this was likely the intended solution (or a 'better' solution) as it showed the following with a key of `HOKIE` (Virginia Tech's mascot):

![image](https://user-images.githubusercontent.com/101006959/232649570-ba1e813a-3e36-4fb2-a6c7-a6fdab058d52.png)


`Flag: TRiple point security`

* * *

## [](#Stego-JobPlz)Stego - Job Please

![image](https://user-images.githubusercontent.com/101006959/232649611-18b6aa9f-2d78-419e-ac0a-c5b4a4ff0ab9.png)


This was the only Stego (Steganography) challenge at Summit CTF, it was worth 150 points and was created by `Triple Point Security`!

For this challenge we were only given the description above, based on the challenge description I presumed that the flag was located somewhere on the Triple Point Security website [careers page](https://www.triplepointsecurity.com/careers.html).

Since the challenge was steganography related, the first thing that stood out to me was the large image in the banner.

I was lucky enough to have the solution be one of the first things I tried. I went to [futureboy.us/stegano](https://futureboy.us/stegano/), went to decode, and uploaded the image.

Once I clicked submit the following flag was returned to me!

`Flag: SummitCTF{in_pl41n_sight}`

* * *

## [](#Forensics-SummitSecrets)Forensics - Summit Secrets

![image](https://user-images.githubusercontent.com/101006959/232649634-115ecca2-8c3f-4863-8f5a-c68c9fb2693c.png)


This was the first of three forensics challenges at Summit CTF and was worth 100 points!

We are given a pcap file titled `summit_capture.pcap` which had over 3,000 packets inside of it.

When first viewing the pcap file the majority of the packets are TCP / HTTP packets, however scrolling down to packet number 1118, we can see FTP packets.

Viewing the TCP streams (stream 8-10 specifically) of those FTP packets, we can see that a file is being sent titled `summit_secrets.pdf`. From this I assumed there was a PDF somewhere we had to extract.

Continuing to TCP stream 11 we can see a PDF file header, so we can assume this is the PDF. Clicking `Show data as` > `Raw` > `Save as...` and saving the file as `summit_secrets.pdf`. We successfully extracted the PDF file.

Finally, opening the pdf file we are given a flag!

`Flag: summitCTF{N1c3_f0r3Ns1c_w0rK!}`

* * *

## [](#Forensics-EscapingtheMatrix)Forensics - Escaping the Matrix

## Forensics / Escaping the Matrix

![image](https://user-images.githubusercontent.com/101006959/232649652-a48339b6-31bf-4c70-aa19-e2f1ba8d7c04.png)

This was the second of three forensics challenges at Summit CTF and was worth 150 points!

We are given a pcap file titled `EscapingTheMatrix.pcap` which had just under 600 packets inside of it.

In this pcap, every packet was a DNS packet and what caught my eye imediatly was the URL that it was attempting to request.

![image](https://user-images.githubusercontent.com/101006959/232649671-cf8c2c40-615c-4728-973b-dc90f8c2df35.png)

The random string of letters and numbers looked a lot like base64 encoding to me, so I picked a few out and tried decoding them.

I got lucky and started with `UDP stream 0`, taking the first random string before the period (example below), I began to see words appear as I decoded from base64.

![image](https://user-images.githubusercontent.com/101006959/232649691-9a3ebe7b-ca1d-4514-84bd-ace041ebb63b.png)

I continued this for every first random string in `UDP stream 0` until I finally got a flag!

```
Base64: VGhlIGZsYWcgeW91IGhhdmUgYmVlbiB3YWl0aW5nIGZvciBpcyAuLi4gUGF1c2luZyBmb3IgZHJhbWF0aWMgZWZmZWN0IC4uLiA6IFN1bW1pdENURntTdXNfRDBtYTFuX240bWVzfQ==
```

```
ASCII: The flag you have been waiting for is ... Pausing for dramatic effect ... : SummitCTF{Sus_D0ma1n_n4mes}
```

`Flag: SummitCTF{Sus_D0ma1n_n4mes}`

* * *

## [](#Forensics-EmergencyExfil)Forensics - Emergency Exfil

![image](https://user-images.githubusercontent.com/101006959/232649722-2b7e229d-edde-4c80-a10c-cbdd227f1446.png)

This was the final forensics challenges at Summit CTF and was worth 150 points!

We are given a pcap file titled `exfil.pcap` which had just under 2,000 packets inside of it.

I originally got stuck attempting to find a way to decrypt QUIC packets without an SSHKEYLOG file and spent a good 30 minutes going down that rabbithole.

Eventually, I viewed the Protocol Hierarchy Statistics in wireshark and noticed that there was a fiew ICMP packets I missed previously:

![image](https://user-images.githubusercontent.com/101006959/232649748-c56bd9c7-5506-4107-ada5-1db9e6d56e9f.png)

filtering the packets for ICMP only, there was 8 packets that appeared, 4 request and 4 reply packets.

![image](https://user-images.githubusercontent.com/101006959/232649757-a7371f4c-8291-4be3-a79d-2a11f85cf17c.png)

There was no stream here to follow, so viewing the ASCII representation of the hex data I noticed that the first 3 sets of request/reply packets had strings of numbers in them, so I extracted the data from them by simply just copying it as printable text.

###### [](#Note1)I would have used tshark to extract the data, but since there was only 3 sets of text to extract I figured copying it would be more simple.

I extracted the following data, and noted that it looked encoded similar to previous challenges. This time however it seemed to be hexadecimal encoding rather than base64:

```
P53756d6d6974435453756d6d6974435453756d6d467b6d30754e745f467b6d30754e745f467b6d30Ðµ337633526553747d337633526553747d33763352
```

Decoding from Hex to ASCII I recieved the following text, which looked to me like a flag! However thanks to UDP, it seems it was a bit corrupted and the data was sent multiple times:

```
SummitCTSummitCTSummF{m0uNt_F{m0uNt_F{m03v3ReSt}3v3ReSt}3v3R
```
During the event I simply peiced together the flag, knowing it began with `SummitCTF{` however for the purpose of this writeup I've cleaned up the hex for you:

```
Hex: 53756d6d69744354467b6d30754e745f337633526553747d
```
```
ASCII: SummitCTF{m0uNt_3v3ReSt}
```

`Flag: SummitCTF{m0uNt_3v3ReSt}`

* * *

## [](#Misc-EmojiSystem)Misc - Emoji System

![image](https://user-images.githubusercontent.com/101006959/232649830-a21d556d-8beb-4e25-8efb-e86f3a666c01.png)

This was one of five Miscellaneous (Misc) challenges at Summit CTF and was worth 250 points!

This was one of my favorite challenges and was really fun to complete. I also managed to score first blood in solving it!

![image](https://user-images.githubusercontent.com/101006959/232649842-84b0dded-95f9-4729-9c87-2133bb331131.png)

We are given an explanation of the challenge and a server to connect to `0.cloud.chals.io:23434`. The goal of the challenge was to solve a system of equations with emojis instead of variables.

Connecting to the server we can see that this isn't just a regular systems of equations, we have to script it, and the emojis / numbers change every time:

![image](https://user-images.githubusercontent.com/101006959/232649862-bf83543a-737c-42bc-9c5e-45847e25f8ad.png)

Only 3 seconds?? Looks like we're gonna have to script it! I have included my solution script below to view before I explain it in more detail:

```py
from pwn import *
from z3 import *

#connecting to the server, recieving the data, and separating the emojis from the rest of the text
r = remote('0.cloud.chals.io',23434)
r.recvuntil(b'\n')
list = r.recvuntil(b':').split(b'\n')
emoji1 = list[0].split(b'+')[0].split(b'*')[-1].strip(b' ').strip(b')')
emoji2 = list[0].split(b'+')[1].split(b'*')[-1].strip(b' ').strip(b')')
emoji3 = list[0].split(b'+')[2].split(b'*')[-1].strip(b' ').split(b')')[0]
#creating a list for the systems of equations
math = [list[0], list[1], list[2]]
# creating a dictionary to map the emojis to variables to make working with the data easier (for z3)
dict = {}
dict[emoji1] = b'A'
dict[emoji2] = b'B'
dict[emoji3] = b'C'
# formatting the systems of equations to be used in z3
for i in range(len(math)):
    math[i] = math[i].replace(emoji1, dict[emoji1])
    math[i] = math[i].replace(emoji2, dict[emoji2]) 
    math[i] = math[i].replace(emoji3, dict[emoji3])
    math[i] = math[i].replace(b'=', b'==')
# setting each equation to a variable for ease of use later
str1 = math[0].decode()
str2 = math[1].decode()
str3 = math[2].decode()

# -----Start of z3-----
# setting our variables, creating the solver, and adding the equations to the solver
A = Int('A')
B = Int('B')
C = Int('C')

s = Solver()

s.add(eval(str1))
s.add(eval(str2))
s.add(eval(str3))

# z3 check to ensure we recieved a solution
if s.check() == sat:
    model = str(s.model())
    print(model)
else:
    print("unsat")

# Formatting the answers recieved from z3 and adding them to a dictionary
answerdict = {}
answerdict[model.split(',')[0].split('=')[0].strip(' ').strip('[')] = model.split(',')[0].split('=')[-1].strip(' ').strip(']')
answerdict[model.split(',')[1].split('=')[0].strip(' ').strip('[')] = model.split(',')[1].split('=')[-1].strip(' ').strip(']')
answerdict[model.split(',')[2].split('=')[0].strip(' ').strip('[')] = model.split(',')[2].split('=')[-1].strip(' ').strip(']')

# sending in our solutions for each of the 3 emojis
r.sendline(answerdict['A'])
r.sendline(answerdict['B'])
r.sendline(answerdict['C'])
# interactive to view the flag after we have completed the challenge
r.interactive()
```
### [](#code-breakdown)Code Breakdown

#### [](#imports)Imports

*   `pwn` was used to import pwntools to connect to the server and read in data.
*   `z3` was used to solve the systems of equations once we had it in the right format.

#### [](#formatting)Formatting The Data

To start: I connected to the server and created a list recieving all of the data for the equations, splitting it for every line.

```py
r = remote('0.cloud.chals.io',23434)
r.recvuntil(b'\n')
list = r.recvuntil(b':').split(b'\n')
```

Once I had the data read in, I used a bunch of different string formatting functions to set our variables for the 3 different emojis.

```py
emoji1 = list[0].split(b'+')[0].split(b'*')[-1].strip(b' ').strip(b')')
emoji2 = list[0].split(b'+')[1].split(b'*')[-1].strip(b' ').strip(b')')
emoji3 = list[0].split(b'+')[2].split(b'*')[-1].strip(b' ').split(b')')[0]
```

Next, I created a list of each equation to be used later in out z3 (we will still have to format it correctly though).

```py
math = [list[0], list[1], list[2]]
```
Once I had all the data properly read in, it was time to format it! I created a dictionary and set each of the emojis as a key with the value being a letter that would act as our variables.

```py
dict = {}
dict[emoji1] = b'A'
dict[emoji2] = b'B'
dict[emoji3] = b'C'
```
With the dictionary we created, I was able to use the `replace()` function to change the emojis in our equations to variables! I also changed `=` to `==` since z3 expects a boolean operation.

```py
for i in range(len(math)):
    math[i] = math[i].replace(emoji1, dict[emoji1])
    math[i] = math[i].replace(emoji2, dict[emoji2]) 
    math[i] = math[i].replace(emoji3, dict[emoji3])
    math[i] = math[i].replace(b'=', b'==')
```
And with that, we are ready to solve!

#### [](#z3)Solving with z3

`z3` is such a powerful library and can be used for so much more than just simple equations like this, combined with the `sage` library it can be used to solve some pretty tough cryptography challenges too!

To set everything up in z3, we created our `Int()` variables to show that A, B, and C are expected to be an integer values, we created our `Solver()`, and then added our equations to z3 using `add()`

```py
A = Int('A')
B = Int('B')
C = Int('C')

s = Solver()

s.add(eval(str1))
s.add(eval(str2))
s.add(eval(str3))
```
###### [](#Note2)The `eval()` function was used so that instead of writing out our equations like hand as you would normally do in z3, we could evaluate the variables as equations for z3 to read!

Next we used the `Check()` function to ensure that we had recieved a proper model, this part was not necessarily needed, however it is good practice incase z3 is unable to solve for your variables.

```py
if s.check() == sat:
    model = str(s.model())
    print(model)
else:
    print("unsat")
```
###### [](#Note3)A shorter alternative to this would just be to assume our model was properly created and delete everything except the line `model = str(s.model())`

To finish up the last formatting in the script, we created another dictionary using script formatting functions. This time we mapped the variable to the correct answer from z3's results.
```py
answerdict = {}
answerdict[model.split(',')[0].split('=')[0].strip(' ').strip('[')] = model.split(',')[0].split('=')[-1].strip(' ').strip(']')
answerdict[model.split(',')[1].split('=')[0].strip(' ').strip('[')] = model.split(',')[1].split('=')[-1].strip(' ').strip(']')
answerdict[model.split(',')[2].split('=')[0].strip(' ').strip('[')] = model.split(',')[2].split('=')[-1].strip(' ').strip(']')
```

Finally, it's time to send in our answers to the server! We again use `pwntools` to send each variable value in one line at a time. Then we use `r.interactive()` to keep standard input open so we can view the flag.
```py
r.sendline(answerdict['A'])
r.sendline(answerdict['B'])
r.sendline(answerdict['C'])
r.interactive()
```
###### [](#Note4)I was originally worried about the order in which the server asks for the emojis back, however in testing I realized that it always asks for the emoji's solution in order from 1st to 3rd.

Now, we can run it and recieve our flag!

![image](https://user-images.githubusercontent.com/101006959/232649891-b2b79c29-8473-4215-ba21-c52703dec9b6.png)

`Flag: summitCTF{M4TH3M4T1CZ_IZ_H4RD_W1TH_EM0JIS}`

* * *

## [](#Misc-EmojiSystem)Misc - Close Encounters

![image](https://user-images.githubusercontent.com/101006959/232649903-04ae5b38-4490-4e4f-aad3-932ccf77918c.png)

This was one of five Misc challenges at Summit CTF, it was worth 175 points and was created by `Huntington Ingalls Industries`!

This was a really cool challenge that most CTFs don't have, we were given a `Verilog` file and had to reverse engineer the expected sequence of buttons on a physical FPGA to recieve the flag.

Our goal in this challenge was to turn all 3 LED lights on and have them stay on, once we did that the sponsor would give us the flag!

To start, we were given a Verilog file titled `close_encounters.v` that when opened, displayed the following code:
  
<details>
<summary>Click for Code</summary>
{% highlight verilog %}
//Designed for the Cyclone III FPGA Starter Board
//Reference manual found At https://cdrdv2-public.intel.com/654220/rm_ciii_starter_board.pdf
module close_encounters (buttons[3:0], cpu_reset_n, led[3:0], clk);
	input [3:0] buttons;
	input cpu_reset_n;
	input clk; //50 MHz
	output [3:0] led;
	
	reg [2:0] out = 0;
	
	assign led[2:0] = out;
	assign led[3] = slow_clk;
	
	wire [4:0] all_buttons;
	
	//Assigned in physical layout on board
	assign all_buttons[4:0] = {cpu_reset_n, buttons[0], buttons[1], buttons[2], buttons[3]};
	
	reg slow_clk = 0;
	reg [32:0] count = 0;
	always @(posedge clk) begin
		if(count < 24999999) begin
			count <= count + 1;
		end else begin
			count <= 0;
			slow_clk <= ~slow_clk;
		end
	end
	
	reg [7:0] state = 0;
	
	always @(posedge slow_clk) begin
		case (state)
			0: begin
				if(all_buttons[4:0] == 5'b11101) begin
					state <= 1;
					out <= 3'b110;
				end else begin
					state <= 0;
					out <= 3'b111;
				end
			end
			1: begin
				if(all_buttons[4:0] == 5'b11110) begin
					state <= 2;
					out <= 3'b101;
				end else begin
					state <= 0;
					out <= 3'b111;
				end
			end
			2: begin
				if(all_buttons[4:0] == 5'b11011) begin
					state <= 3;
					out <= 3'b100;
				end else begin
					state <= 0;
					out <= 3'b111;
				end
			end
			3: begin
				if(all_buttons[4:0] == 5'b01111) begin
					state <= 4;
					out <= 3'b011;
				end else begin
					state <= 0;
					out <= 3'b111;
				end
			end
			4: begin
				if(all_buttons[4:0] == 5'b10111) begin
					state <= 5;
					out <= 3'b010;
				end else begin
					state <= 0;
					out <= 3'b111;
				end
			end
			5: begin
				out <= 3'b111;
				state <= 6;
			end
			6: begin
				out <= 3'b100;
				state <= 7;
			end
			7: begin
				out <= 3'b110;
				state <= 8;
			end
			8: begin
				out <= 3'b101;
				state <= 9;
			end
			9: begin
				out <= 3'b011;
				state <= 10;
			end
			10: begin
				out <= 3'b001;
				state <= 11;
			end
			11: begin
				out <= 3'b111;
				state <= 12;
			end
			12: begin
				if(all_buttons[4:0] == 5'b11101) begin
					state <= 13;
					out <= 3'b110;
				end else begin
					state <= 0;
					out <= 3'b111;
				end
			end
			13: begin
				if(all_buttons[4:0] == 5'b11110) begin
					state <= 14;
					out <= 3'b101;
				end else begin
					state <= 0;
					out <= 3'b111;
				end
			end
			14: begin
				if(all_buttons[4:0] == 5'b10111) begin
					state <= 15;
					out <= 3'b100;
				end else begin
					state <= 0;
					out <= 3'b111;
				end
			end
			15: begin
				out <= 3'b111;
				state <= 16;
			end
			16: begin
				out <= 3'b100;
				state <= 17;
			end
			17: begin
				out <= 3'b110;
				state <= 18;
			end
			18: begin
				out <= 3'b001;
				state <= 19;
			end
			19: begin
				out <= 3'b000;
				state <= 19;
			end
		endcase
	end
	
endmodule
{% endhighlight %}

</details>

The code may look a bit daunting at first, but after scanning through it it becomes much easier to understand.

Everything before the `case (state)` is just setup and isn't necessarilly important for this challenge, however it does show us a bit of info about how the FPGA works, such as the speed of the clock, the number of buttons, and the overall physical layout of the board.

Reading through the `case` statement we can see multiple `if` statements, the first one being `if(all_buttons[4:0] == 5'b11101) begin`. From this one we can see that we are expecting the buttons to have the value `11101`.

For this challenge there was 5 buttons, we can assume the order is left to right, so the first `if` statement would be true if the 4th button was pressed down, 0 being down and 1 being up.

Putting it all together, the expected buttons from left to right would be: 4, 5, 3, 1, 2, wait 7 blinks of the counter light (until case 12) 4, 5, 2

###### [](#Note5)The counter light was a light that would blink off and on at the rate of the `clk` which in this case was 50hz, and if the count hit 25000000 then the `state` would reset to 0 as per `if(count < 24999999)`

Once you correctly input the sequence of: `4, 5, 3, 1, 2, wait, 4, 5, 2` then all 3 LEDs would light up and you would recieve the flag from the HII sponsor.

`flag: Sadly I did not write the flag down for this challenge since it was input directly by the HII sponsor`
