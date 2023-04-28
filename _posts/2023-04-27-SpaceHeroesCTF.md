---
title: Space Heroes CTF
published: true
---

The following are a list of `Forensics` writeups I completed after competing in this past weekend's CTF: `Space Heroes CTF` hosted by the Florida Institute of Technology!

![image](https://user-images.githubusercontent.com/101006959/235035459-1e6f1103-57e6-41e7-a69c-2f8c072b8eda.png)

### Challenges:

[Time Leap](#time-leap)

[A New Hope](#a-new-hope)

[Félicette](#félicette)

[Brainiac](#brainiac)

[My God, it's full of .- ... -.-. .. ..](#my-god-its-full-of--------)

[space_stream](#space_stream)

[conspiracy nut](#conspiracy-nut)

* * *

## [](#Time-Leap)Time Leap

![image](https://user-images.githubusercontent.com/101006959/235035472-7ff0c788-7452-455a-85a2-0c392c88613e.png)

For this challenge, we were given a singular file, a compressed image of a USB drive.

#### [](#Files1)File(s):
- convergence.img.gz

We can extract the image through the use of either `gunzip convergence.img.gz` on Linux, or by using `WinRAR` on Windows.

Once we have extracted the image `convergence.img` we can use Autopsy to open it up and get a better look at what was saved on the USB drive.

![image](https://user-images.githubusercontent.com/101006959/235035484-b3a59145-24c9-4fcd-97d6-8a87db5f9825.png)

The first thing we can see is an empty file `$OrphanFiles`, some extracted files `$CarvedFiles` and some unallocated files `$Unalloc`.

Viewing the carved files we can see that many of the files have been deleted, we could take time to scan through those, but the 1 deleted file on the file system caught my eye, so let's check that first.

![image](https://user-images.githubusercontent.com/101006959/235035499-fb1110c1-182b-487f-83af-e2f9244996d8.png)

We can see that a file named `flag.gif` was recently deleted, that is most likely the flag we need! We can extract and view the file by right clicking on it, hitting extract, and saving it into a directory of our choice. Once we do this we are met with the following gif of the flag!

![image](https://user-images.githubusercontent.com/101006959/235035533-25806e3a-9ea9-4242-833d-ce61e369c65f.png)

`Flag: shctf{th1s_i5_the_wi11_0f_St3in5_G4te}`

* * *

## [](#A-New-Hope)A New Hope

![image](https://user-images.githubusercontent.com/101006959/235035561-14164b04-4988-4f57-9d4d-3158a270ea5b.png)

For this challenge, we were given a singular file, a PowerPoint file with a single slide contained within it.

#### [](#Files2)File(s):
- A_New_Hope.pptx

Opening the PowerPoint doesn't give us very much info on where the flag could be hidden, the only slide contains the following picture:

![image](https://user-images.githubusercontent.com/101006959/235035577-ed41746a-23b6-436b-9dbc-52ba04a65a23.png)

If we delete the background image and the picture of a droid running, we are greeted with one last image that was hidden behind the slide, however PowerPoint says "The Picture can't be displayed".

![image](https://user-images.githubusercontent.com/101006959/235035588-371e0bf6-02d8-49ee-8c07-555be3a46bcc.png)

My next idea was to use binwalk with `binwalk -e A_New_Hope.pptx` in order to extract all the images and data from the PowerPoint in order to get a better idea of what this hidden image could be.

After extracting it, I went to `./_A_New_Hope.pptx.extracted/ppt/media` and we can see the three images from the PowerPoint.

![image](https://user-images.githubusercontent.com/101006959/235035609-4ef30a49-8035-437c-94c6-e9e52eaf9ba7.png)

`image2.jpeg` and `image3.png` are the two images that we could see from the PowerPoint slide and open without any error, however `image1.png` seems to be corrupted and cannot be displayed.

Opening `image1.png` in a hex editor, we can see that while the file has a extension of `.png`, the first few bytes of the hex data show us `JFIF` which is typical to jpeg files.

We can also confirm our suspicions by looking at the header and trailer of the file in hex, for the trailer we can see the expected `FF D9` bytes which are typical to the end of a jpeg file, however the header is a different story.

Viewing the file header bytes, we can see the first 4 bytes are `00 00 FF E0`, which are not typical to a jpeg file, knowing that a jpeg starts with `FF D9`, my first thought was to remove the two `00` null bytes and replace `E0` with `D8` as that would make the starting bytes of the file equal to `FF D8`.

Once we do this and save the file with a `.jpg` file extension, the file successfully opens and we are greeted with the following flag!

![image](https://user-images.githubusercontent.com/101006959/235035739-fdde6db2-7e89-4837-8d8a-c77ae667c319.png)

`Flag: shctf{help_m3_ob1_y0u're_my_0n1y_hope}`

* * *

## [](#Félicette)Félicette

![image](https://user-images.githubusercontent.com/101006959/235035768-98ccb3f0-5a8b-4c29-82ca-d3a7354f0d05.png)

For this challenge, we were given a packet capture file that we can view within Wireshark.

#### [](#Files3)File(s):
- chall.jpg.pcap

Opening the pcap file we can see there are thousands of ICMP packets, and no other packet types.

![image](https://user-images.githubusercontent.com/101006959/235035783-89dd2398-fc93-4831-bff3-46ae89a99d3d.png)

There is no data stream for us to view in Wireshark, so I started going through the packets 1 by 1 to see if I could get any idea of where the flag could be. I quickly picked up that the only 2 fields that were changing was the `Data` field, as well as the `Checksum` field.

My first thought was to use `tshark` to extract all the packets from the data field and see if I could convert them or make sense of the data in some day. I used the following command to do this:

```tshark -r chall.jpg.pcap -Y icmp -T fields -e data.data```

From this the first thing I noticed was the file trailer (since the last result is the first thing I in the terminal). `FF D9`, which I immediately knew was the end of a jpeg file (which was also in the name of the pcap!).

My next step was to check the first few bytes of data to see if the expected header of `FF D8` was there, or if I would have to do some file carving, I did this by running the same command as before, just piped into the `head` command as seen below:

```tshark -r chall.jpg.pcap -Y icmp -T fields -e data.data | head```

Through this command we can verify that the start of the data is the 2 bytes `FF D8`, no need for file carving!

The next step was to convert this data into a format that we can then convert to a file to do this I simply just piped the output of the first command into `tr '\n' ' '` to replace all newline characters with a space so things were easier to work with.

After this all that needed to be done was to convert the bytes to a file, however we can't simply output the data to a file using `>` because linux would view that as us outputting ascii data to a file, whereas these are hex bytes of a file. 

I have included my full command below, which you can view before I explain it a little more in detail:

```tshark -r chall.jpg.pcap -Y icmp -T fields -e data.data | tr '\n' ' ' | xxd -p -r > flag.jpg; feh flag.jpg```

The first section of this we have already covered, we use `tshark` to extract the data fields of all ICMP packets from the pcap file, after this we use the translate command `tr` to translate any newline characters to a space so that it is easier to read / work with. Then finally we use `xxd` to properly format the hex values with `-p` and convert them to ascii with `-r`. Now we are ready to output the data to a file with `>`!

The final part of this command is just for ease of use, `; feh flag.jpg` will just end the previous string of commands, and open the file for viewing after all the extractions & conversions have been complete, after this runs we are greeted with the image below containing the flag!

![image](https://user-images.githubusercontent.com/101006959/235035856-263d03c8-5d88-45a8-a4c3-50f97932b677.png)

`Flag: summitCTF{look_at_da_kitty}`

* * *

## [](#Brainiac)Brainiac

![image](https://user-images.githubusercontent.com/101006959/235035879-71fd2d73-b33f-4f97-9758-c947070e7b40.png)

For this challenge, we were given a packet capture file that we can view within Wireshark.

#### [](#Files4)File(s):
- exploit.pcap

Opening the pcap file we can see there are multiple different types of packet protocols, the majority of them being TCP packets.

![image](https://user-images.githubusercontent.com/101006959/235035897-13657c30-f550-4342-b78f-bc1d89bb476b.png)

Viewing the TCP streams, on the very first stream (Stream 0) we can see some peculiar data that looks like someone connecting to a server and successfully getting a shell:

![image](https://user-images.githubusercontent.com/101006959/235035913-27ff9fdf-e34e-4324-bc20-b9bf722d69c3.png)

I searched through the rest of the streams and also attempted to search the file for the string `shctf{` to see if the flag was in there, but had no luck.

After some thinking I decided to check if we were also able to access the server shown in the TCP stream, using the ip `165.227.210.30` and port `16306` we were successfully able connect to the server and received the following screen!

![image](https://user-images.githubusercontent.com/101006959/235035977-e84e59ef-2e07-495d-af1a-cbad161d8543.png)

I originally copy pasted the exact data seen in the TCP stream as seen above, however after the 3rd line of input, the server just closed the connection and I was unable to receive any type of shell.

This confused me a little until I eventually looked at the data closer in Wireshark. Some of the bytes that were being sent to the server were unable to be properly represented in ASCII and therefor were just being represented by `.` which is why I was unable to get a shell

![image](https://user-images.githubusercontent.com/101006959/235035959-1ff4abc3-2123-4707-9508-3259ef011e81.png)

My next idea was to take these expected hex data, and write a python script using pwntools to send the exact hex bytes expected to the server. Below is the script that I wrote:

```py
from pwn import *
r = remote('165.227.210.30', 16306)
r.recvuntil(b'>>>')
r.sendline(bytes.fromhex('41594831f65648bf2f62696e2f73680057545f48c7c180104000ffd10a')) #AYH1.VH./bin/sh.WT_H....@...
r.recvuntil(b'>>>')
r.sendline(bytes.fromhex('000011ca000000000a')) #........
r.recvuntil(b'>>>')
r.sendline(bytes.fromhex('41414141414141410a')) #AAAAAAAA
r.sendline(bytes.fromhex('63617420666C61672E747874')) #cat flag.txt
r.interactive()
```

This script takes each of the hex values that I extracted from Wireshark and 1 by 1 sends them to the server after the expected `>>>` characters. The final 2 lines are used to view the contents of the flag.txt file with `cat flag.txt` encoded as hex (not necessary, but still works), then `r.interactive()` to view the output of the flag from the server.

Once the script was done, I ran it and the response from the server was the flag below!

`Flag: shctf{1_4m_n0t_pr0gr4mm3d_t0_3xp3r13nc3_hum0r}`

* * *

## [](#My-God-its-full-of)My God, it's full of .- ... -.-. .. ..

![image](https://user-images.githubusercontent.com/101006959/235036004-580f4b13-ffc5-403a-ae82-c4b35b362139.png)

For this challenge, we were given a waveform audio file and a hint in the title of morse code.

#### [](#Files5)File(s):
- signal.wav

From the title we have `.- ... -.-. .. ..` which when decoded ends up being morse code for `ASCII`. From this we can assume there is some type of ASCII data hidden within the audio file.

When playing the `signal.wav` file, we can hear primarily what sounds like static, however if we turn the volume up we can hear distinct beeps in the background that sound like they could be morse code spelling out something!

My first idea was to use Sonic Visualizer to view the frequencies of the noises, and I did this by opening up the audio file in Sonic Visualizer, going to `layer > add peak frequency spectrogram` and was able to view the following at the start of the audio:

![image](https://user-images.githubusercontent.com/101006959/235036020-89a22fe5-9121-42e6-a6fc-bdf6eda2f755.png)

From this I started typing out the dots and dashes of morse code by hand into a morse code decoder, but after 3-4 "blocks" of them, I realized I was unable to make out any ASCII letters at all, let alone a flag.

I quickly realized that these "blocks" all contained 8 different dots or dashes, which made me think that they could be an 8 bit binary number.

I tested my theory out by converting all the dots to `0` and all the dashes to `1`. Dots being the shorter waveforms in the image above and dashes being the longer ones.

From this I began to slowly decode the flag, after I first saw `shctf{` I knew that I was on the right track towards the flag!

During the competition when I solved this challenge, I manually decoded the bytes from Sonic Visualizer. However after the challenge I realized that you could use a morse code audio reader to receive the data automatically and make this challenge much easier, instead of manually decoding it.

I used [morsecode.world](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) with the following settings to receive the data as a string of `E`'s and `T`'s.

![image](https://user-images.githubusercontent.com/101006959/235036037-33a14f8f-693e-4210-b016-c6251bdfe48d.png)

after this I used some bash string formatting with `sed` and `tr` to change the letters from E & T to binary so that I could decode them.

```
echo "E T T T E E T T E T T E T E E E E T T E E E T T E T T T E T E E E T T E E T T E E T T T T E T T E T E E T T T E E E T T E E E E E E T E E E E E E E T T E E E T E E T E E E E E E T T E E E T T E E T T E T E E E T T E T T T E E E T E E E E E E T E E T E E E E E T T E E T T E E T T E T E E E T T T E E T E E E T E E E E E E T T T E T E T E E T E E E E E E E T T T E E E E E T T E E T T E E T T E E T T E T E T E E E E E T E T T T T T E E T T T E E E E E T T E E E E E E T T E E E E E T T T E E E E E E T E T E E E E T E E T E E T E T T E T T T E E E T E T E E T E E T E E E E E E E T T T T E E E E T E E E E E E E T E T T T T E T T E E T E E E T T E E T E T E T T T E T T E E E T E T T T T E T T E T T T E E T T T E T E T E T T E T T E E E T T E T T E E E T T T E E T T E T T T E E E E E T T E E E E T E T T E E E T T E T T E E T E T E T T T T T E T" | sed 's/ //g' | tr "ET" "01"
```

Finally, I was left with the following binary values, which I could simply use an online decoder to convert to the flag:

```
0111001101101000011000110111010001100110011110110100111000110000001000000011000100100000011000110011010001101110001000000100100000110011001101000111001000100000011101010010000000111000001100110011001101010000010111110011100000110000001100000111000000101000010010010110111000101001001000000011110000100000001011110110010001100101011101100010111101101110011101010110110001101100011100110111000001100001011000110110010101111101
```

After decoding this string of binary, I received the flag below!

`Flag: shctf{N0 1 c4n H34r u 833P_800p(In) < /dev/nullspace}`

* * *

## [](#space_stream)space_stream

![image](https://user-images.githubusercontent.com/101006959/235036048-d2f818ae-6fe5-4b69-808e-e79554d45adc.png)

For this challenge, we were given a Virtual Hard Disk file (VDH).

#### [](#Files6)File(s):
- starstream.vhd

Seeing that we were given a VHD file, the first thing I did was open the file in Autopsy to see if there was any data I could gather from the disk.

Searching through the drive, we can see a directory titled `data_streams` which contains jpg files titled stream 1-4:

![image](https://user-images.githubusercontent.com/101006959/235036073-b6dc1d23-dba7-4aa7-b3f5-01554b6dbfcf.png)

Most of these streams seem to be just pictures of maps from StarCraft, however the file titled `stream1.jpg:sarah_kerrigan` gives us a hint with the text in the file saying `I should stop using my name as password. Maybe I can just hide my file, they will never find it.`

From this we can assume that the password: `sarah_kerrigan` may be useful, so let's save that for later.

I tried looking all throughout the drive for any other hints or a flag but ended up finding nothing. I then went on to trying to look for steganography in any of the 4 images of StarCraft maps from above, however that didn't yield anything valuable either.

One hint I did find was a logfile titled `$LogFile` which was located at the root of volume 4 of the drive. In this file I found hints at a 5th stream `stream5.pdf` however I was unable to find any other traces of that file anywhere else on the operating system.

![image](https://user-images.githubusercontent.com/101006959/235036121-34a38d08-6da2-49a0-a0f2-7d8ee529b964.png)

I eventually ran out of ideas for looking through autopsy and felt stumped, that is when I thought of possibly using binwalk to see if it could extract any extra files that I could not see before.

![image](https://user-images.githubusercontent.com/101006959/235036133-1e3785bf-b233-481b-9dd0-3c41a02c4e96.png)

As we can see from the image above, binwalk shows us a file `stream5.pdf` that was hidden and unable to view from autopsy!

From this I extracted the data and attempted to extract the `stream5.pdf` file. I successfully managed to find the file hidden within `starstream.vhd`, it was protected with a password so I used the password `sarah_kerrigan` that we obtained before to open it.

This is where I got stumped again though, the pdf file itself was corrupted and as hard as I tried I was unable to obtain any type of useable data from the file even though I was sure I had the right file.

Eventually though, I got the idea to retry the process again but using the command `7z x starstream.vhd` to extract the data from the VDH using 7zip instead of binwalk.

This seemed to work similar to binwalk, as I extracted the data again, and received a file `data_streams:stream5.zip` which I unzipped and again extracted `stream5.pdf`.

I again typed in the password we received earlier and this time I was able to view the full PDF without any corruption in it! The result of the PDF is shown below:

![image](https://user-images.githubusercontent.com/101006959/235036144-33267f99-5b25-4a7a-b7b1-4e89bea03423.png)

I successfully managed to extract the flag from the PDF!

###### [](#Note1)I am still not certain why 7-Zip worked and binwalk didn't, my only assumption to this is that 7zip is a more powerful tool overall that can overcome the difficulties encountered by binwalk, or possibly that this challenge was simply just built to be extracted by 7zip instead of other extraction tools.

`Flag: shctf{r1ver_styx}`

* * *

## [](#conspiracy-nut)conspiracy nut

![image](https://user-images.githubusercontent.com/101006959/235036157-2a4ecff9-3c72-4720-a456-fb8ecf0d06e5.png)

For this challenge, we were given a compressed memory dump file.

#### [](#Files7)File(s):
- conspiracy_nut.tar.gz

The first thing I did for this challenge was extracted the file and received a memory dump file titled `conspiracy_nut.dump`.

From the description of this challenge we are given a hint, we need to extract a missing image that presumably will have a flag.

For this challenge I used `Volatility 2.5` to extract information from the memory dump in an attempt to find the flag.

One of the first things that I did within Volatility was to check the `imageinfo`, giving me a little bit of information on the operating system type and some basic hardware information from the system that took this dump.

![image](https://user-images.githubusercontent.com/101006959/235036178-3f615c8e-4e99-472f-aade-20ab3cb0fe14.png)

I used the profile `Win7SP0x64` for the rest of this challenge since it was the first suggested profile that Volatility gave me. From this we know that we are dealing with a Windows x64 system.

The next thing I tried was running a filescan on the dump and using grep to look for the word `flag`. However no files with that word came up, so I went back to the drawing board.

After some trial and error and some dead ends, I eventually decided to try running strings on the dump and again using grep to look for the word `flag`. This had a large amount of results since the word flag is often used in programs and configuration files, however I noticed some interesting ips that ended in `/flag.jpg`.

![image](https://user-images.githubusercontent.com/101006959/235036215-a77bbeb3-f3a1-4c51-b249-517ac9066686.png)

After I found this I knew 2 things about the flag on the system: 1 that it was likely a `.jpg` file format & 2 that it likely came from the a web-server with the ip / port of `http://57.135.219.202:9000/`.

Knowing this information I tried running a network scan on the memory dump to see if I could get any information about the ip that was listed next to `flag.jpg` and found out that it was opened in the firefox browser:

![image](https://user-images.githubusercontent.com/101006959/235036235-737fd47d-c3e6-4206-ac1f-2e518aa47591.png)

I tried to use the `memdump` command on the process ID `1936` however after some failed attempts I was unable to use this method to extract any sort of flag file or even a .jpg file.

I have to say I was a little stumped here for some time, I tried extracting data from other processes that seemed suspicious to me such as `wmplayer.exe` and `notepad.exe` however each of those came up in deadends and left me with more questions than answers.

Eventually, I thought of the idea of running a filescan on the system and using grep to search for an extension of `.jpg` instead of the word flag, this time I had a few hits, but none of them had extremely obvious names such as `flag.jpg`.

![image](https://user-images.githubusercontent.com/101006959/235036269-6714b2d2-4403-4065-99a6-fc26528c38ef.png)

One file that seemed a little odd though was `TranscodedWallpaper.jpg`. This file was seen twice on the drive, both under the user `tinfoil`. I knew this user had to be a hint based on the title of the challenge but was not certain if the file was correct or not, it was worth a try though.

I used this information I obtained and used the `dumpfiles` command with the physical offset given to me by the previous command.

![image](https://user-images.githubusercontent.com/101006959/235036280-7ab28f10-4dfc-4f06-b469-9ef0214c4334.png)

The file I was returned with had a `.dat` extension, however viewing the file in a hex editor we can see that the header corresponded to the expected header of a jpg file, that being the bytes `FF D8`.

I checked the trailer of the file and it was bytes `94 ED` which did not correspond to the expected trailer of `FF D9`, however based on the header information, I was sure this was supposed to be a jpeg file.

With the information gathered regarding the header of the file, I figured it was a worth a shot to change the extension and at least attempt to open the jpeg, it may be corrupted, but if it opened I could still possibly use that to get some information or even get the flag!

I changed the file name to `TranscodedWallpaper.jpg` and opened the file, and to my luck it opened and showed the following image!

![image](https://user-images.githubusercontent.com/101006959/235036397-c6f050a1-5191-42e9-883f-0696cf673d91.png)

While the file is clearly corrupted somewhat towards the bottom of the image, it still is able to be opened and we can see a flag at the bottom of the whiteboard!

`Flag: shctf{m4D3_1n_A_h0LLYw00d_b45eM3NT}`
