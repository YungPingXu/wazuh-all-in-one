Cowrie
######

Fix Bugs
*****************************************

用新版 python 的話，跑 proxy 模式會遇到 python 語法錯誤導致程式 crash

.. image:: https://i.imgur.com/OnvEQKA.png

因此修正了 ./src/backend_pool/pool_service.py 的程式碼

執行環境：Ubuntu 22.04 主機 + python 3.10.12

安裝必要套件::

    sudo apt-get install python3-venv openssh-server libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind qemu qemu-system-arm qemu-system-x86 libvirt-dev libvirt-daemon libvirt-daemon-system libvirt-clients nmap
    python3 -m venv cowrie-env
    source cowrie-env/bin/activate

然後會進到 (cowrie-env)::

    python3 -m pip install --upgrade pip
    pip3 install -r requirements.txt
    bin/cowrie start

接著用 ssh 連連看::

    ssh root@localhost -p 2222

如果出現以下錯誤::

    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
    Someone could be eavesdropping on you right now (man-in-the-middle attack)!
    It is also possible that a host key has just been changed.
    The fingerprint for the ED25519 key sent by the remote host is
    Please contact your system administrator.
    Add correct host key in /home/user/.ssh/known_hosts to get rid of this message.
    Offending ED25519 key in /home/user/.ssh/known_hosts:7
    remove with:
    ssh-keygen -f "/home/user/.ssh/known_hosts" -R "[localhost]:2222"
    Host key for [localhost]:2222 has changed and you have requested strict checking.
    Host key verification failed.

就按照它說的用上面的命令刪除 ssh key 即可::

    ssh-keygen -f "/home/your_username.ssh/known_hosts" -R "[localhost]:2222"

./etc/userdb.txt 裡面已添加了帳密::

    root:x:asd1234
    user:x:1234

必須要用裡面的帳密組合(可自行修改)才可成功登入，而不是像原本預設的帳密亂打也能進來

Proxy 模式 (Backend Pool)
*****************************************

讓使用者可以執行 libvirt::

    sudo usermod -aG libvirt your_username

並且為了要讓 QEMU 可以使用 disk image 和 snapshot

用下列指令更改 qemu.conf 的設定 (用 vim 也可以)::

    sudo nano /etc/libvirt/qemu.conf

修改 user 和 group 的值::

    user = "your_username"
    group = "your_username"

接著重啟 libvirt::

    sudo systemctl restart libvirtd.service

上述 qemu.conf 的部分如果沒做修改的話可能會遇到以下錯誤

.. image:: https://i.imgur.com/YMRz40F.png

建立資料夾::

    mkdir cowrie-imgs

下載官方提供的 image - ubuntu18.04-minimal.qcow2

https://drive.google.com/open?id=1ZNE57lzaGWR427XxynqUVJ_2anTKmFmh
(連結已失效 用下面的)
https://drive.google.com/drive/folders/1-bvEYMDO6voa6Y8tA42w9kjobpuzQIB6?usp=drive_link

放到 ./cowrie-imgs 資料夾

安裝 virtinst 以及 virtual machine manager::

    sudo apt install virtinst virt-manager

修改 cowrie.cfg.dist 配置，改為 proxy 模式

將 guest_image_path 設為剛才下載的 image 路徑

以及由於預設的 kvm 不能用，因此將 guest_hypervisor 改為 qemu::

    [honeypot]
    backend = proxy
    [backend_pool]
    guest_image_path = /home/your_username/Desktop/cowrie/cowrie-imgs/ubuntu18.04-minimal.qcow2
    guest_hypervisor = qemu
    guest_qemu_machine = pc-q35-bionic

guest_qemu_machine 的部份可下指令查詢可支援的環境::

    qemu-system-x86_64 -machine help

guest_qemu_machine 的值有出現在此指令的執行結果就行

裝 backend 虛擬機的部份只需要這樣就行，因為它會直接讀 guest_image_path，不用再自己手動安裝

更改權限::
    
    sudo chmod 777 /var/run/libvirt/libvirt-sock

接下來重啟 cowrie::

    bin/cowrie restart

接著它會開始建立 backend 虛擬機，需稍等 1~2 分鐘

查看日誌檔最後面 100 行的紀錄::

    tail ./var/log/cowrie/cowrie.log -n 100

要有出現以下這些才是成功::

    Guest 0 ready for connections @ 192.168.150.43! (boot 16s)
    Guest 1 ready for connections @ 192.168.150.72! (boot 16s)
    Guest 2 ready for connections @ 192.168.150.221! (boot 16s)
    Guest 3 ready for connections @ 192.168.150.119! (boot 15s)
    Guest 4 ready for connections @ 192.168.150.151! (boot 15s)

同時也會在 virtual machine manager 裡面看到

.. image:: https://i.imgur.com/fNw1hNg.png

都有了才能用 ssh 連::

    ssh root@localhost -p 2222

之後在 proxy 模式下，重啟都用 stop 和 start，別用 restart

而且每次 stop 完要先稍等一下再 start

因為它還要砍掉虛擬機，所以會比較慢

不然會出現以下錯誤::

    Another twistd server is running, PID 17478
    This could either be a previously started instance of your application or a
    different application entirely. To start a new one, either run it in some other
    directory, or use the --pidfile and --logfile parameters to avoid clashes.

用 ``bin/cowrie status`` 可以查看目前 stop 好了沒

另外，它預設會開 5 個虛擬機，如果開這麼多虛擬機會太 lag 跑不動的話

可以修改 ./etc/cowrie.cfg.dist 裡的設定，減少建立的虛擬機個數::

    [proxy]
    pool_max_vms = 虛擬機個數

參考資料
*****************************************

Installing Cowrie in seven steps

https://cowrie.readthedocs.io/en/latest/INSTALL.html#installing-backend-pool-dependencies-optional

Backend Pool

https://cowrie.readthedocs.io/en/latest/BACKEND_POOL.html

用 Cowrie 來架 SSH Honeypot

https://blog.d1tt0.net/posts/deploy_a_ssh_honeypot_with_cowrie/

Honeypot #13 手動安裝 Cowrie

https://ithelp.ithome.com.tw/articles/10304345

Honeypot #18 Cowrie 指令與配置

https://ithelp.ithome.com.tw/articles/10307721

Honeypot #19 Cowrie - 使用代理(Proxy)模式 - 設置虛擬環境

https://ithelp.ithome.com.tw/articles/10308120

Honeypot #20 Cowrie - 使用代理(Proxy)模式-測試 Proxy 模式

https://ithelp.ithome.com.tw/articles/10308491

【cowrie蜜罐系列2】cowrie蜜罐配置代理成為高交互蜜罐（避免踩坑）

https://www.cnblogs.com/ABKing/p/14047223.html

kvm 权限报错- cannot access storage file (as uid:107, gid:107) permission denied
https://blog.csdn.net/yuezhilangniao/article/details/113743688

Welcome to the Cowrie GitHub repository
*****************************************

This is the official repository for the Cowrie SSH and Telnet
Honeypot effort.

What is Cowrie
*****************************************

Cowrie is a medium to high interaction SSH and Telnet honeypot
designed to log brute force attacks and the shell interaction
performed by the attacker. In medium interaction mode (shell) it
emulates a UNIX system in Python, in high interaction mode (proxy)
it functions as an SSH and telnet proxy to observe attacker behavior
to another system.

`Cowrie <http://github.com/cowrie/cowrie/>`_ is maintained by Michel Oosterhof.

Documentation
****************************************

The Documentation can be found `here <https://cowrie.readthedocs.io/en/latest/index.html>`_.

Slack
*****************************************

You can join the Cowrie community at the following `Slack workspace <https://www.cowrie.org/slack/>`_.

Features
*****************************************

* Choose to run as an emulated shell (default):
   * Fake filesystem with the ability to add/remove files. A full fake filesystem resembling a Debian 5.0 installation is included
   * Possibility of adding fake file contents so the attacker can `cat` files such as `/etc/passwd`. Only minimal file contents are included
   * Cowrie saves files downloaded with wget/curl or uploaded with SFTP and scp for later inspection

* Or proxy SSH and telnet to another system
   * Run as a pure telnet and ssh proxy with monitoring
   * Or let Cowrie manage a pool of QEMU emulated servers to provide the systems to login to

For both settings:

* Session logs are stored in an `UML Compatible <http://user-mode-linux.sourceforge.net/>`_  format for easy replay with the `bin/playlog` utility.
* SFTP and SCP support for file upload
* Support for SSH exec commands
* Logging of direct-tcp connection attempts (ssh proxying)
* Forward SMTP connections to SMTP Honeypot (e.g. `mailoney <https://github.com/awhitehatter/mailoney>`_)
* JSON logging for easy processing in log management solutions

Docker
*****************************************

Docker versions are available.

* To get started quickly and give Cowrie a try, run::

    $ docker run -p 2222:2222 cowrie/cowrie:latest
    $ ssh -p 2222 root@localhost

* On Docker Hub: https://hub.docker.com/r/cowrie/cowrie

* Configuring Cowrie in Docker

Cowrie in Docker can be configured using environment variables. The
variables start with COWRIE_ then have the section name in capitals,
followed by the stanza in capitals. An example is below to enable
telnet support::

    COWRIE_TELNET_ENABLED=yes

Alternatively, Cowrie in Docker can use an `etc` volume to store
configuration data.  Create `cowrie.cfg` inside the etc volume
with the following contents to enable telnet in your Cowrie Honeypot
in Docker::

    [telnet]
    enabled = yes

Requirements
*****************************************

Software required to run locally:

* Python 3.8+
* python-virtualenv

For Python dependencies, see `requirements.txt <https://github.com/cowrie/cowrie/blob/master/requirements.txt>`_.

Files of interest:
*****************************************

* `etc/cowrie.cfg` - Cowrie's configuration file. Default values can be found in `etc/cowrie.cfg.dist <https://github.com/cowrie/cowrie/blob/master/etc/cowrie.cfg.dist>`_.
* `share/cowrie/fs.pickle` - fake filesystem
* `etc/userdb.txt` - credentials to access the honeypot
* `honeyfs/ <https://github.com/cowrie/cowrie/tree/master/honeyfs>`_ - file contents for the fake filesystem - feel free to copy a real system here or use `bin/fsctl`
* `honeyfs/etc/issue.net` - pre-login banner
* `honeyfs/etc/motd <https://github.com/cowrie/cowrie/blob/master/honeyfs/etc/issue>`_ - post-login banner
* `var/log/cowrie/cowrie.json` - transaction output in JSON format
* `var/log/cowrie/cowrie.log` - log/debug output
* `var/lib/cowrie/tty/` - session logs, replayable with the `bin/playlog` utility.
* `var/lib/cowrie/downloads/` - files transferred from the attacker to the honeypot are stored here
* `share/cowrie/txtcmds/ <https://github.com/cowrie/cowrie/tree/master/share/cowrie/txtcmds>`_ - file contents for simple fake commands
* `bin/createfs <https://github.com/cowrie/cowrie/blob/master/bin/createfs>`_ - used to create the fake filesystem
* `bin/playlog <https://github.com/cowrie/cowrie/blob/master/bin/playlog>`_ - utility to replay session logs

Contributors
***************

Many people have contributed to Cowrie over the years. Special thanks to:

* Upi Tamminen (desaster) for all his work developing Kippo on which Cowrie was based
* Dave Germiquet (davegermiquet) for TFTP support, unit tests, new process handling
* Olivier Bilodeau (obilodeau) for Telnet support
* Ivan Korolev (fe7ch) for many improvements over the years.
* Florian Pelgrim (craneworks) for his work on code cleanup and Docker.
* Guilherme Borges (sgtpepperpt) for SSH and telnet proxy (GSoC 2019)
* And many many others.