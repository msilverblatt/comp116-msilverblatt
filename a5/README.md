Assignment 5: Forensics
=======================
Michael Silverblatt and Diogenes Nunez

Steganography
---------------

We downloaded the 3 images from the website. 

We include the images in the `images` directory here file for the reader to crack it on their own.<br>
The extracted file is in `images/hidden` for correctness.

We detail our experience below.

Using `ls -lh` gave us this

> $ ls -lh<br>
> -rw-rw-r-- 1 defcon defcon 892K Nov 14 13:39 a.jpg<br>
> -rw-rw-r-- 1 defcon defcon 893K Nov 14 13:39 b.jpg<br>
> -rw-rw-r-- 1 defcon defcon 893K Nov 14 13:39 c.jpg

Using `cmp`, we confirmed that `b.jpg` and `c.jpg` were the same, leaving `a.jpg`
as the file we need to cover.

From here, we tried two things

- Used wordlists from John the Ripper and Metasploit as passphrases.
  All of them failed.
- The cone on Norman's head looked interesting, so we did some research
  on that. On the bright side, we learned more about Plants vs. Zombies
  and the Wellington Statue in Glasglow than we would ever like to know. 
  Nothing from this search worked.

Upon this string of failures, we looked at the man page for steghide and
found the info option.

> $ steghide info a.jpg

When it asked for the passphrase, we accidentally hit "Enter" and received
this

>  $ steghide info a.jpg 
>  
>  "a.jpg":<br>
>  &nbsp;&nbsp;&nbsp;&nbsp; format: jpeg<br>
>  &nbsp;&nbsp;&nbsp;&nbsp; capacity: 50.2 KB<br>
>  &nbsp;&nbsp;&nbsp;&nbsp; Try to get information about embedded data ? (y/n) y<br>
>  &nbsp;&nbsp;&nbsp;&nbsp; Enter passphrase: <br>
>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; embedded file "prado.jpg":<br>
>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; size: 34.9 KB<br>
>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; encrypted: rijndael-128, cbc<br>
>  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; compressed: yes<br>

We did the same when extracting it.

> $ steghide extract -sf a.jpg
>
> Enter passphrase: <br>
> wrote extracted data to "prado.jpg".


Forensics: `sdcard.dd`
---------------------

1. There are 2 file systems according to `parted`, FAT16 and ext4.
2. We do not believe this device is tied to a carrier. We found no evidence
   of a carrier in the file system.
3. It is Kali 1.0. To be fair, we had to look up how to figure out one's own
   version information in linux. We were pointed to "release" files in `/etc`.
   We searched for them with

   > fls -o 125001 sdcard.dd 11 | grep "release"
   
   This returned one item, `/etc/os-release`. In there was all the information.

   SIDE NOTE: Was this on a Raspberry Pi?
   There are a good deal of other items on the FAT16 file system that mention `hello_pi`,
   `hello_triangle` and so on. There are references to the ARM architrecture on the machine.
   
   There were also numerous documents and code that were from Broadcomm. 
   
   Furthermore, `/root/.bash_history` showed the command `raspi-config` was run.
   
   Finally, some of the pdfs extracted by `foremost` referred to adding a wireless
   card to a Raspberry Pi.
4. In `/usr/bin`, we see the suspect had `netcat`.
   In `/opt`, we found Metasploit and Teeth. Teeth's readme speaks of Maltego,
   a forensics tool. All of this was found by browsing the file system with Autopsy.

   The `.bash_history` in `/root` showed us the suspect installed `tor`.
   In the same directory, the suspect had a `.TrueCrypt` directory. This tells us
   the suspect also installed TrueCrypt.
5. There is a root password. `/etc` contained the passwd and shadow files.
   Autopsy allowed us to extract the files. Using John the Ripper, we 
   found the login:passwd is

   > root:toor
   
6. No. The shadow file shows only one password, the root's. 
   passwd shows a home directory with the path `/home/saned`, but that is actually a daemon.
7. The passwd file showed us root's home directory was `/root`. In there, we
   found deleted `Pictures` and `Documents` directories. `Picutres` had 
   10 jpegs all of the celebrity, according to Google Images. They seem to
   be from different periods of her life. 

   `Documents` had 3 files. 2 of them, labeled `setlist-20122013.txt`
   and `setlist-old.txt`, contained names of songs that she performed. The third
   files is a list of dates, which seem to be the celebrity's concert dates.

   On the home directory itself, there is a file labeled `shortcut.lnk`. This
   links to an album in Spotify called "My Love: Essential Collection" by the celebrity herself.

   We also have 3 more pictures here. While they are named
   `new1.jpg`, `new2.jpg`, `new3.jpg` on the disk, these were recovered by
   foremost and thusly have their names discarded. Google Images confirms
   these 3 are also of our celebrity.

   Finally, we have `receipt.pdf`. We describe the details of it later on.

   While this does not seem as decisive evidence of stalking, it is enough
   to at least justify the suspicion.

   We include all the evidence in a directory labeled `evidence` with the
   same structure described above.
8. Yes. The most recent files deleted are 3 jpgs (`new1`, `new2`, `new3`) and a pdf (`receipt`).
   This can be seen in their `.bash_history`. 
   `foremost` recovered a wealth of files from the disk image. `receipt.pdf` was there. The details
   of how it was found is noted later on.
  
   There were many jpegs found. However 13 of them were of the celebrity. Process of elimination
   ruled out 10 as the ones in `Pictures`. This left us with 3 unaccounted images of our celebrity.
   We could not determine their old names, so we left them with the ones geenrated by `foremost`.

   All these files are in the `evidence` directory.

9. In `/root`, we found a file labeled `.Dropbox.zip`. The `.bash_history` showed us this file
   is a copy of `dropbox.zip`. However, `file` states this is only data. The
   `.TrueCrypt` directory tells us if this is encrypted data, TrueCrypt was used.

   Using a virtual machine running Kali Linux, we ran `truecrack -w dictionary/openwall_3546.txt -v -t Dropbox.zip`

   > Found password:			"iloveyou"<br>
   > Password length:			"9"<br>
   > Total Computations:		"84"

   Within a few seconds, it detected 'iloveyou' as a valid password. Using TrueCrypt, 
   we were able to mount the Dropbox.zip file with that password. There were two encrypted
   files, a photograph of concert tickets named tickets.jpg and a video of a live 
   Celine Dion performance, named open_arms-live.mp4. 
   
   As an aside, the `.TrueCrypt` directory had another file named `.show-request-queue`.
   This was another image of our celebrity.

10. The suspect may have seen the celebrity. The suspected location is
    The Colosseum at Caesars Place in Las Vegas on July 28, 2012. 

    We uncovered this by running foremost on the image. This gave us
    a grand number of files. From there, we performed

    > $ grep -r "Dion" *

    on the output folder. One of the pdf files, `05030089.pdf`, matched.
    This was the suspect's receipt from TicketMaster for her concert.
    
    In `/root`, we found inode information about a file labeled `receipt.pdf`. 
    Autopsy could not retrieve it, but we believe this is `05030089.pdf`.
11. Some of the files, like doc files, were mostly empty. A single PowerPoint (ppt) file stood out.
    It was the only one recovered by foremost. Uploading it to VirusTotal revealed this could be a Trojan Horse.
    We suspect many of these other files (particularly the doc and docx files) are viruses as well.
12. Celine Dion is the celebrity. 
