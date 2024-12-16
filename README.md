# bandit-overthewire-challenges-all-level

# Bandit OverTheWire Challenge: A Comprehensive Guide

Welcome to the Bandit OverTheWire wargame, a captivating journey through the world of cybersecurity, focusing on practical exploitation techniques in a **Linux** environment. This README aims to be your companion, guiding you through the levels and enhancing your understanding of the commands and concepts involved.

## Overview

Bandit presents a series of progressively challenging levels, each demanding the use of specific Linux commands and cybersecurity principles to uncover a hidden password. Your goal? To **chain these passwords together, advancing through each level until you reach the ultimate victory**. 

## Level Breakdown and Strategies

Here's a breakdown of the initial levels, complete with commands and strategies:

**Level 0 to 1**

* **Challenge:** Accessing basic files.
* **Commands:**
    * `ssh bandit0@bandit.labs.overthewire.org -p 2220`: Connects you to the Bandit server.
    * `ls`: Lists directory contents.
    * `cat readme`: Displays the content of the 'readme' file.
* **Strategy:** The initial password is provided for you. Use `cat` to read the 'readme' file, revealing the password for the next level.

**Level 1 to 2**

* **Challenge:** Reading files with special characters in their names.
* **Commands:**
    * `cat ./-`: Reads the file named '-'.
* **Strategy:** The dash (-) is a valid character in file names. You'll need to adapt your `cat` command to access this file.

**Level 2 to 3**

* **Challenge:** Handling filenames with spaces.
* **Commands:**
    * `cat 'spaces in this filename'`: Reads a file with spaces in its name.
* **Strategy:** Enclose the filename within single quotes to prevent the shell from misinterpreting the spaces.

**Level 3 to 4**

* **Challenge:** Uncovering hidden files.
* **Commands:**
    * `cd inhere`: Changes your current directory.
    * `ls -al`: Lists all files, including hidden ones (those starting with a dot).
    * `cat ...Hiding-From-You`: Reads the hidden file.
* **Strategy:** The `-a` flag with `ls` reveals hidden files. Use `cat` to read the content of the hidden file.

**Level 4 to 5**

* **Challenge:** Identifying file types.
* **Commands:**
    * `find . -type f | xargs file`: Lists all files and identifies their types.
    * `cat ./*7`: Reads the file ending in '7'.
* **Strategy:** `find` locates files, `xargs` passes the results to `file` for type identification, and `cat` reads the specific file based on its name.

**Level 5 to 6**

* **Challenge:** Finding files with specific size and permissions.
* **Commands:**
    * `find . -type f -size 1033c ! -executable`: Finds files of size 1033 bytes that are not executable.
    * `cat ./maybehere07/.file2`: Reads the file.
* **Strategy:** `find` allows for filtering by size (`-size`) and negation of properties (`! -executable`).

**Level 6 to 7**

* **Challenge:** Locating system files based on ownership and size.
* **Commands:**
    * `find / -type f -user bandit7 -group bandit6 -size 33c`: Finds files owned by user 'bandit7', group 'bandit6', and size 33 bytes.
    * `cat /var/lib/dpkg/info/bandit7.password`: Reads the found file.
* **Strategy:** This level focuses on using `find` with ownership (`-user`, `-group`) and size (`-size`) filters.

**Level 7 to 8**

* **Challenge:** Extracting text using regular expressions.
* **Commands:**
    * `grep -oP '(?<=millionth\s)\w+' data.txt`: Extracts the word following "millionth " from the 'data.txt' file.
* **Strategy:** `grep` is used with the `-oP` flags for Perl-compatible regular expressions and extracting only the matched portion. The regular expression `(?<=millionth\s)\w+` uses a lookbehind assertion to match the desired pattern.

**Level 8 to 9**

* **Challenge:** Identifying unique lines in a file.
* **Commands:**
    * `sort data.txt | uniq -u`: Sorts the file and outputs only the unique lines.
* **Strategy:** `sort` prepares the input for `uniq`, and the `-u` flag instructs `uniq` to output only lines that appear once.

**Level 9 to 10**

* **Challenge:** Extracting strings and searching for patterns.
* **Commands:**
    * `strings data.txt | grep -E '=+'`: Extracts strings from the file and searches for lines containing one or more equal signs (`=+`).
* **Strategy:** `strings` pulls out printable strings, and `grep -E` enables extended regular expressions for the pattern matching.

**Level 10 to 11**

* **Challenge:** Decoding Base64-encoded data.
* **Commands:**
    * `base64 -d data.txt`: Decodes the Base64-encoded content of 'data.txt'.
* **Strategy:**  The `base64` utility is used with the `-d` flag to decode the data.

**Level 11 to 12**

* **Challenge:** Decrypting text using the ROT13 cipher.
* **Commands:**
    * `cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'`: Decrypts the file content using ROT13 substitution.
* **Strategy:** `tr` is used to translate characters based on the ROT13 cipher.

**Level 12 - 13**

**Command:** `lv 12`

**Description:**  To get the password for level 13, a series of commands were used to decompress and extract files.

*   First, a temporary directory was created and the 'data.txt' file from the home directory of bandit12 was copied to the /tmp directory. The 'data.txt' was then moved to the temporary directory and renamed to 'comp.txt'. The command 'xxd -r comp.txt > comp' converted the hexadecimal representation in 'comp.txt' to its binary equivalent, creating a file named 'comp'.
*   The 'comp' file turned out to be a gzip compressed file, which was then renamed to 'comp.gz' and decompressed using 'gzip -d comp.gz'. The resulting 'comp' file was a bzip2 compressed file, renamed to 'comp.bz2' and decompressed using 'bzip2 -d comp.bz2'.
*   The decompressed 'comp' file was identified as a POSIX tar archive. It was renamed to 'comp.tar' and extracted using 'tar xf comp.tar'. Inside the 'comp.tar' was a file named 'data5.bin', which was also a POSIX tar archive.
*   After removing unnecessary files, 'data5.bin' was renamed to 'comp.tar' and extracted, revealing 'data6.bin'. 'data6.bin' was a bzip2 compressed file, which was decompressed to get a POSIX tar archive named 'comp.tar'. Extracting 'comp.tar' resulted in a file named 'data8.bin', which was a gzip compressed file.
*   Finally, 'data8.bin' was decompressed to get a file named 'comp', which contained the password for level 13: **FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn**.

**Output:**  FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn 


**Level 13 to 14**

* **Challenge:** Using SSH keys for authentication.
* **Commands:**
    * `ssh -i sshkey.private bandit14@localhost -p 2220`: Connects via SSH using a private key.
    * `cat /etc/bandit_pass/bandit14`: Reads the password file.
* **Strategy:** You'll need to use the provided private key (`sshkey.private`) to authenticate and access the next level's password.

**Level 14 to 15**

* **Challenge:** Interacting with a network service.
* **Commands:**
    * `nc localhost 30000`: Connects to a service listening on port 30000 using `nc` (netcat).
* **Strategy:** `nc` is a versatile tool for network communication. Use it to connect to the specified port and retrieve the password.

**Level 15 to 16**

* **Challenge:** Communicating over SSL/TLS.
* **Commands:**
    * `openssl s_client -connect localhost:30001`: Connects to an SSL-enabled service.
* **Strategy:** `openssl` is used to establish a secure connection. 

**Level 16 to 17**

* **Challenge:** Port scanning and connecting to a specific port.
* **Commands:**
    * `nmap localhost -p 31000-32000`: Scans ports 31000-32000 on the local machine.
    * `ncat --ssl localhost 31790`: Connects to the identified port using SSL.
* **Strategy:**  `nmap` helps discover open ports.  You'll then use `ncat` to connect to the correct port.

**Level 17 to 18**

* **Challenge:** Utilizing SSH keys and comparing files.
* **Commands:** 
    * `vim key`: Creates or edits a file named 'key'.
    * `:wq`: Saves and exits `vim`.
    * `chmod 400 key`: Sets appropriate permissions for the key file.
    * `ssh -i key bandit17@bandit.labs.overthewire.org -p 2220`: Connects via SSH using the key.
    * `diff passwords.new passwords.old`: Compares two password files.
* **Strategy:** You'll create an SSH key, connect using it, and then compare two files to find the password.

**Level 18 to 19**

* **Challenge:**  Forcing a TTY allocation with SSH.
* **Commands:**
    * `man ssh | grep terminal`:  Searches the `ssh` manual for information about terminals.
    * `ssh -t bandit18@bandit.labs.overthewire.org -p 2220 /bin/sh`:  Connects via SSH and requests a TTY. 
* **Strategy:** Understanding how to allocate a pseudo-terminal with SSH is key for this level.

**Level 19 to 20**

* **Challenge:** Exploiting SUID (Set User ID) binaries.
* **Commands:**
    * `./bandit20-do`: Executes the provided SUID binary.
    * `./bandit20-do id`: Checks the effective user ID.
    * `./bandit20-do cat /etc/bandit_pass/bandit20`: Uses the SUID binary to read the password file.
* **Strategy:** Learn how SUID binaries can elevate privileges and use that knowledge to access the password.

**Level 20 to 21**

* **Challenge:** Setting up a simple network listener.
* **Commands:**
    * `./suconnect`: Executes a provided script.
    * `cat /etc/bandit_pass/bandit20 | nc -l -p 2008`: Sends the password to a listening network port.
* **Strategy:** This level combines the use of a provided script with basic network listening using `nc`.

**Level 21 to 22**

* **Challenge:** Understanding cron jobs.
* **Commands:**
    * `cd /etc/cron.d/`:  Navigates to the cron job directory.
    * `cat /usr/bin/cronjob_bandit22.sh`:  Views the cron job script.
* **Strategy:** Analyze the cron job script to understand its actions and extract the password.

**Level 22 to 23**

* **Challenge:**  Working with MD5 hashes.
* **Commands:**
    * `whoami`: Displays the current username.
    * `man md5sum`: Displays the manual for `md5sum`.
    * `echo I am user $myname | md5sum | cut -d ' ' -f 1`: Generates an MD5 hash.
    * `cat /tmp/8ca319486bfbbc3663ea0fbe81326349`: Reads a file containing the password.
* **Strategy:** You'll need to generate an MD5 hash based on your username and use it to access the password.

**Level 23 to 24**

* **Challenge:**  Exploiting cron jobs and file permissions.
* **Commands:** 
    * (Series of commands to create a script, set permissions, and copy it to the cron directory.)
* **Strategy:** This level involves crafting a script that can be executed by a cron job to access the password.

**Level 24 to 25**

* **Challenge:** Brute-forcing a 4-digit PIN.
* **Commands:** 
    * (Commands to create a brute-force script.)
* **Strategy:** You'll develop a script to try all possible PIN combinations and send them to a listening service.

**Level 25 to 26**

* **Challenge:**  Analyzing user information and executing commands within a restricted shell.
* **Commands:**
    * `ssh -i sshkey.private bandit26@localhost -p 2220`: Connects via SSH.
    * `cat /etc/passwd | grep bandit26`:  Finds information about the 'bandit26' user.
    * `cat /usr/bin/showtext`:  Examines the provided 'showtext' script.
* **Strategy:**  You'll analyze user details and exploit a restricted shell to execute commands.

**Level 26 to 27**

* **Challenge:** Exploiting SUID binaries and understanding user impersonation.
* **Commands:** 
    * `./bandit27-do`: Executes the SUID binary.
    * `./bandit27-do id`: Checks the effective user ID.
    * `./bandit27-do whoami`: Displays the current user.
    * `./bandit27-do cat /etc/bandit_pass/bandit27`: Reads the password file.
* **Strategy:**  This level builds on the knowledge of SUID binaries and introduces concepts of user impersonation.

**Level 27 to 28**

* **Challenge:** Cloning a Git repository.
* **Commands:** 
    * `cd /tmp/nasirh`: Navigates to a directory.
    * `git clone ssh://bandit27-git@localhost/home/bandit27-git/repo`: Clones a Git repository.
    * `cd repo`: Changes to the repository directory.
    * `cat README`: Reads the 'README' file.
* **Strategy:**  Basic Git commands are needed to clone the repository and access the password.

**Level 28 to 29**

* **Challenge:** Analyzing Git commits and checking out specific revisions.
* **Commands:**
    * `git log`:  Views commit history.
    * `git checkout ****`: Checks out a specific commit using its ID.
* **Strategy:** You'll need to inspect the Git history to locate the commit containing the password.

**Level 29 to 30**

* **Challenge:** Working with Git branches.
* **Commands:** 
    * `git branch`:  Lists local branches.
    * `git branch -a`: Lists all branches (local and remote).
    * `git checkout dev`: Switches to the 'dev' branch.
    * `git log`: Views commit history.
* **Strategy:** Understanding Git branching is crucial to finding the password hidden within a specific branch.

**Level 30 to 31**

* **Challenge:** Utilizing Git tags.
* **Commands:**
    * `git tag`:  Lists tags.
    * `git show secret`: Shows the content associated with the 'secret' tag.
* **Strategy:** Git tags are used to mark specific points in history. You'll need to use the 'secret' tag to retrieve the password.

**Level 31 to 32**

* **Challenge:** Pushing changes to a Git repository.
* **Commands:** 
    * `nano key.txt`:  Creates or edits a file named 'key.txt'.
    * `git add key.txt`:  Adds the file to the staging area.
    * `ls -a`: Lists files, including hidden ones.
    * `nano .gitignore`:  Creates or edits the '.gitignore' file.
    * `git status`:  Displays the status of the repository.
    * `git commit -m "nasir"`: Commits the changes with a message.
    * `git push`:  Pushes the changes to the remote repository.
* **Strategy:**  This level requires pushing a file to a remote Git repository to access the password.

**Level 32 to 33**

* **Challenge:** Exploiting the `$0` variable.
* **Commands:**
    * `$0`: Represents the name of the current script.
    * `whoami`: Displays the current username.
    * `cat /etc/bandit_pass/bandit33`:  Reads the password file.
* **Strategy:** You'll learn how to manipulate the `$0` variable to execute commands as the 'bandit33' user.

**Level 33 to 34**

* **Congratulations!** You've conquered the final level of the Bandit wargame!

## Conclusion

The Bandit wargame provides a hands-on experience, allowing you to practice essential Linux commands and security concepts in a safe and controlled environment. As you progress, you'll gain valuable skills that can be applied in real-world cybersecurity scenarios. Good luck, and enjoy the challenge! Remember, persistence and a curious mind are your greatest assets. 
