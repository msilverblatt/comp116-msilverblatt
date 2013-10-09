Comp 116 - Intro to Computer Security
Assignment 2: Incident Alarm with PacketFu
Michael Silverblatt

In this assignment, we were to write a program in Ruby that scans all packets going through a network connection for various possibly malicious events, such as network scans and personal information being transmitted in plain text. The easiest of these to implement were the NULL and XMAS scans, because the tcp flags set for each scan are nearly unmistakeable. The other nmap scans are more tricky because they use more commonly used flag combinations, but Ming instructed us that a search for the word "nmap" in the packet body was sufficient to detect them. Password and credit card leakage were slightly more difficult because not all passwords are the same and the mere appearance of the word "password" does not imply a password is being sent over plain text, and because not all 16 digit numbers that fit a certain credit company's formula are actually credit card numbers. Cross site scripting I also struggled with because I did not know how to distinguish legitimate javascripts from malicious ones.

I received some help from Victor Ansart with getting all the software running on my computer.
This assignment is a day late because I was in the hospital yesterday. I can provide documentation if necessary.

