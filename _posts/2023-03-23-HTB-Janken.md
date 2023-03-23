---
title: HTB Cyber Apocalypse 2023 - Misc Janken
published: true
---

This writeup will walk you through how to solve the Challenge `Misc - Janken` from Hack The Box's 2023 Cyber Apocalypse CTF!

## [](#header-1)Challenge Overview

![image](https://user-images.githubusercontent.com/101006959/227324103-28c7da9a-7d2b-426f-87db-4db5e314800a.png)

To start: From the desciption of `Janken` we can see that the goal of thoal of the challenge is to beat the guru 100 times in a row at the game.
We can also see that the game will be similar to the well known game: rock, paper, scissors.

We are given a docker instance to connect to and some files to help us beat the guru.

### [](#header-3)files:

- flag.txt
- janken
- .glibc
  - ld-linux-x86-64.so.2
  - libc.so.6

Using the 'file' command in linux, we can see that `janken` is an ELF file

```
janken: ELF 64-bit LSB pie executable, x86-64
```
Running the file locally we are greeted with the following output:

![image](https://user-images.githubusercontent.com/101006959/227333440-cb79b7dc-9e11-4bc8-a08c-4f8a04a99ec9.png)

First, let's view the `ℜ ℧ ∟ Ӗ ⅀` of the game:

![image](https://user-images.githubusercontent.com/101006959/227333865-7a0d9a4d-5888-460f-a5be-c4fb232ca9f2.png)

From here we can see the basic rules of rock, paper, scissors; and the requirements of winning 100 times in a row in order to recieve our prize.

Let's first try `ℙ ∟ ₳ Ұ`ing the game and see what happens.

![image](https://user-images.githubusercontent.com/101006959/227343416-3ef090dc-c3bd-4bb1-bd84-7aceb0f2c355.png)

For this example, we chose `rock` , and the guru chose `rock`. The program doesn't seem to consider ties and from that we can assume that we have to win 
every round, no ties or losses, for 100 rounds in a row.

:-------------------------------------------------------------------------------------------------------------------------------------------

Next, let's get a little more in depth and go under the hood to see what the program is actually doing with our input, and maybe see if we can figure out
how the guru decides which value he will pick.

## [](#header-2)Reading the assembly with Ghidra

A little background: [Ghidra](https://ghidra-sre.org/) is a free and open source tool created by the NSA in order to read binaries and attempt to decompile the assembly back into source code.

First, you will want to open Ghidra, select a folder to work in, and the go to `File > Import File > janken` to import the binary into Ghidra. 

Next, double click on the file `janken` and a picture of a dragon will pop up on your screen before opening the Ghidra CodeBrowser.

![image](https://user-images.githubusercontent.com/101006959/227357297-edb8cbc4-b32c-4dee-91d7-53bdb8b337d2.png)

Alternatively, you can click on the dragon icon after first opening Ghidra and go to `File > Import File > janken` to open the file from within the CodeBrowser.

When first opening a binary, Ghidra will ask you if you would like to analyze the file, click `Yes` and then `Analyze`.

You should be greeted with a `Listing` of the assembly code, as well as a list of `Functions`. If you do not see the `Functions` tab, you can go to `Window > Functions` to view the different functions of the `janken` file.

Let's try viewing the main function in Ghidra and see if we can figure out what the game does & how he makes his choice.

![image](https://user-images.githubusercontent.com/101006959/227349063-2a76377c-ced7-4cd0-8a26-5734e4b5d644.png)


> This is a blockquote following a header.
>
> When something is important enough, you do it even if the odds are not in your favor.

### [](#header-3)Header 3

```js
// Javascript code with syntax highlighting.
var fun = function lang(l) {
  dateformat.i18n = require('./lang/' + l)
  return true;
}
```

```ruby
# Ruby code with syntax highlighting
GitHubPages::Dependencies.gems.each do |gem, version|
  s.add_dependency(gem, "= #{version}")
end
```

#### [](#header-4)Header 4

*   This is an unordered list following a header.
*   This is an unordered list following a header.
*   This is an unordered list following a header.

##### [](#header-5)Header 5

1.  This is an ordered list following a header.
2.  This is an ordered list following a header.
3.  This is an ordered list following a header.

###### [](#header-6)Header 6

| head1        | head two          | three |
|:-------------|:------------------|:------|
| ok           | good swedish fish | nice  |
| out of stock | good and plenty   | nice  |
| ok           | good `oreos`      | hmm   |
| ok           | good `zoute` drop | yumm  |

### There's a horizontal rule below this.

* * *

### Here is an unordered list:

*   Item foo
*   Item bar
*   Item baz
*   Item zip

### And an ordered list:

1.  Item one
1.  Item two
1.  Item three
1.  Item four

### And a nested list:

- level 1 item
  - level 2 item
  - level 2 item
    - level 3 item
    - level 3 item
- level 1 item
  - level 2 item
  - level 2 item
  - level 2 item
- level 1 item
  - level 2 item
  - level 2 item
- level 1 item

### Small image

![](https://assets-cdn.github.com/images/icons/emoji/octocat.png)

### Large image

![](https://guides.github.com/activities/hello-world/branching.png)


### Definition lists can be used with HTML syntax.

<dl>
<dt>Name</dt>
<dd>Godzilla</dd>
<dt>Born</dt>
<dd>1952</dd>
<dt>Birthplace</dt>
<dd>Japan</dd>
<dt>Color</dt>
<dd>Green</dd>
</dl>

```
Long, single-line code blocks should not wrap. They should horizontally scroll if they are too long. This line should be long enough to demonstrate this.
```

```
The final element.
```
