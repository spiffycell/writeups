# Mentor [In Progress]

Our target machine is `10.10.11.193`:

We get:
```
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 c73bfc3cf9ceee8b4818d5d1af8ec2bb (ECDSA)
|_  256 4440084c0ecbd4f18e7eeda85c68a4f7 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://mentorquotes.htb/
```

Looks like we're resolving to `http://mentorquotes.htb`
- Let's add this to our `/etc/hosts` file
```
10.10.11.193    mentorquotes.htb
```

Let's go visit the site and see what it's running!
- We're running a Flask server (Python)

Important Flask server files:
- `views.py`
- `routes.py` (ROUTES!!!)
- `models.py`
- `forms.py`

> More info on important Flask items can be found [here](https://flask.palletsprojects.com/en/2.2.x/patterns/packages/)

Routes will help us understand the internal mapping of the application if other means fail

Our methods of domain enumeration:
- Run `ffuf` for endpoints
    - Discovery / Web_Content
- Run `ffuf` for subdomains
    - Discovery / Web_Content
- Run `ffuf` for subdomain endpoints
    - Discovery / Web_Content

Let's run `gobuster`! 
`gobuster dir -u http://mentorquotes.htb -w=/usr/share/wordlists/dirb/big.txt`

What do we get?
```
/server-status        (Status: 403) [Size: 281]
```

We get a `403: Forbidden` with `/server-status`
- Meaning, we'll likely need to AuthN somehow
    - We weren't prompted with login fields
    - So maybe we perform AuthN via a cookie/token?

What does our request look like?
```
GET /server-status HTTP/1.1
Host: mentorquotes.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

We are holding no cookies, cache storage, local storage, session storage, &c.
- So our access must be based on some other method


We also see from our `Forbidden` status that we are using 
- `Apache 2.4.52 (Ubuntu)`
    - I can haz [vulns](https://github.com/advisories/GHSA-2hwm-6xjf-3xmx)?
    - Nothing jumps off the page for something we can easily leverage


Now that we've tried enumerating directores / endpoints, let's try enumerating subdomains with `ffuf`
```
ffuf -u http://FUZZ.mentorquotes.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
```

We can also try with `wfuzz`:
```
wfuzz -H "Host: FUZZ.mentorquotes.htb" --hc 302,404 -c -z file,"/opt/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt" http://mentorquotes.htb
```

The general approach for subdomain enum:
```
wfuzz -c -f -w /opt/SecLists/ -u 'http://target.tld' -H "Host: FUZZ.target.tld"
```

MANY requests come back with `302` and `400`, and generate a lot of noise.

We do get back a `404` status for `api`, so let's try `http://api.mentorquotes.htb
- now how about we check for endpoints to this subdomain?




