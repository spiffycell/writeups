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
