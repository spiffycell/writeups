# Soccer

## Service and Port Enumeration 

We get an IP of `10.129.88.113`, let's run `nmap` on it
```
$ nmap -sC -sT -Pn 10.129.88.113
```

And we get:
```
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_  256 5797565def793c2fcbdb35fff17c615c (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://soccer.htb/
9091/tcp open  xmltec-xmlmail
```

We see that the IP resolves to `http://soccer.htb`
- Let's add that to our `/etc/hosts`, and navigate on our browser

Wappalyzer says that the site is running:
- `nginx`
    - helpful files
        - `/etc/nginx/nginx.conf`
        - `/etc/nginx/conf.d/*`
- `jQuery v3.2.1`
    - seems to be an older version, any big vulns?
    - [snyk vulns for jQuery 3.2.1](https://security.snyk.io/package/npm/jquery/3.2.1)
        - Two types of XSS
        - Protype polution
- `Ubuntu`

Let's run `gobuster` to discover endpoints
```
└─$ gobuster dir -u soccer.htb -w=/usr/share/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/18 01:28:02 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 162]
/.htpasswd            (Status: 403) [Size: 162]
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]                                                                   
Progress: 20399 / 20470 (99.65%)===============================================================
2022/12/18 01:29:10 Finished
```

We see that `soccer.htb/tiny` is a valid endpoint, we travel there and see a user/pass field combo
```
POST /tiny/tinyfilemanager.php HTTP/1.1
Host: soccer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://soccer.htb
DNT: 1
Connection: keep-alive
Referer: http://soccer.htb/tiny/tinyfilemanager.php
Cookie: filemanager=0tjktfap7uldqoqih919iokfdn
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

fm_usr=admin&fm_pwd=admin
```

We see the presence of a `cookie` and two datafields
- the `filemanager` cookie is present on the homepage `soccer.htb` too


Let's take a closer look at this cookie
```
0tjktfap7uldqoqih919iokfdn
```

Crackstation does not recognize the string combination as any particular hashing algorithm

---

We also haven't enumerated subdomains, so let's use `wfuzz` to do that
```
└─$ wfuzz -c -w /opt/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt -u 'http://soccer.htb' -H "Host: FUZZ.soccer.htb" --hc 400,301
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://soccer.htb/
Total requests: 38267

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================


Total time: 0
Processed Requests: 38267
Filtered Requests: 38267
Requests/sec.: 0
```

Not seeing much pop up as a result of that

---

If we remember from before, the app is using jQuery 3.2.1
- [Snyk](https://security.snyk.io/vuln/SNYK-JS-JQUERY-567880) says that jQuery has a Cross-Site Scripting vuln

Can we open up the console and leverage that?
