# hash-java
A (somewhat) simple java application that has similar functionalities as HashCat. You can run the application by running the command `javac Crack.java` (to compile the program) and `java Crack [CRACKABLE] [LEAKED_PWS]` where CRACKABLE are a file containing usernames and password hashes in the format `username:hash` and the LEAKED_PWS file contains lines of possible passwords. The program can be given as many files of leaked passwords as you'd like. Each leaked password list will have created its own thread so the running time of the program should be reduced somewhat.

## DISCLAIMER
Although the purpose of this application is to "crack" password hashes then I would like to emphasize that I by no means endorse using the application for malicious purposes. This application should only be used for scholarly pursuits or if you're curious whether a password you've chosen has previously been leaked.

## Files of Importance
You can test the functionality of the program by running the program with the files `data/ex-table.txt` and `data/ex-leaked.txt`, i.e. using the command `java Crack ./../data/ex-table.txt ./../data/ex-leaked.txt`. There is a lot of websites where it is possible to find lists containing leaked passwords. For instance, see [HaveIBeenPwned](https://haveibeenpwned.com/Passwords) or [SkullSecurity](https://wiki.skullsecurity.org/Passwords?fbclid=IwAR2XDc6-z9ChC760jn41rDi_9fZ8E2hkE-w5RQUr9MiYLQ47xXEOLtUB6bs).
