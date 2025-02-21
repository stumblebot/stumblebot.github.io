---
layout: post
title: Pentaho Kettle Decrypt Tools
date: 2025-02-20 00:32 -0500
categories:
- infosec
- tools
tags:
- infosec
- credentials
- encryption
- xor
- ktr
- pentaho
- password
- kettle
- spoon
- seed
---
TL;DR If you need to recover passwords from `.ktr` files, use this tool:
[ktr_parse](https://github.com/stumblebot/ktr_parse)

# The Story

On an assessment last year I ran into a web service that I had never seen before called 'Pentaho Business Analytics'. It was so friendly that it literally let me one-click login with the default admin password. 

![Pentaho Login Page](/assets/img/pentaho_login_page.png)
_So friendly!_

Poking around, I found a web-based file navigator with multiple directories and files. Most of these files used the extension `.ktr` and appeared to allow some kind of execution on the server. Since that would be dangerous without knowing what these files are and what they contain, I downloaded a few and took a look. 

![Pentaho Home Page](/assets/img/pentaho_home_page.png)

# What is Pentaho? What is a KTR file? What?
Pentaho is a company that makes 'Data Management software'. That's pretty broad, eh? As far as I can tell, the platform acts as a 'no code' way to execute various database function. This includes viewing data, changing data, generating reports, etc. It seems to be relatively flexible, claiming to allow for multi-step actions involving multiple data sources.

A 'Pentaho Kettle Transformation file' or `.ktr` is an XML-fmratted text file that defines a series of attributes and actions to be executed and used to execute a Transform. These transforms are usually created using a GUI tool that facilitate the whole 'no code' element of the service. 

As you might imagine, since these transforms often involve connecting to a database service, they have to have access to database credentials. Credentials for external resources are stored in each `.ktr`, inside the `<connection>` or `<step>` element. Sub-elements will define the relevant details, including a `<password>`. Supported database types appear to include:
- Generic Database
- H2
- Hypersonic
- MSSQL
- MonetDB
- Pentaho Data Services
- PostgreSQL
- Teradata
- SparkSQL
- Cloudera Impala
- Impala
- Hadoop Hive 2
- Oracle
- MYSQL
- MS Access
- Sybase

Other protocols supported for non-database actions include:
- LDAP
- SMTP

There might be more too!

 Additionally, the `<slaveservers>` element may store credentials and hostnames for other Pentaho servers. 

```xml
<connection>
    <name>Generic Sample</name>
    <server/>
    <type>GENERIC</type>
    <access>Native</access>
    <database/>
    <port>-1</port>
    <username>PENTAHO_USER</username>
    <password>Encrypted 2be98afc86aa7f2e49b389d43e9bd9dfe</password>
    <servername/>
...snip...
  </connection>
```

# Fingerquotes 'Encryption'
The password value is stored as... ^^^ THAT. In the `<password>` element. Some research revealed some very helpful prior art that figured out everything I needed for the instance in question. Specifically, [Riktastic](https://github.com/Riktastic/Pentaho-Kettle-Password-Decrypt), [Bissol Consulting](https://diethardsteiner.github.io/pdi/2017/03/03/PDI-Password-Encryption.html), and [Zinea Infosec](https://zineausa.com/blog/2020/07/pen-test-guide-to-pentaho-business-analytics/). All of these resources were great and helped me to recover the credentials stored in all available `.ktr` files. Unfortunately, they mostly require the use of the GUI tool that I mentioned earlier, called the 'Pentaho Data Integration Client'. This utility is relatively big at around 450 MB, and I found using the GUI to execute each decryption transform pretty cumbersome. I decided to build something smaller and easier to use.

After reading and using the resources referenced above, I found that the password value was 'encrypted' using XoR. I use quotes because while the primary function in Pentaho's codebase for this is called `decryptPassword`, [the documentation admits](https://javadoc.pentaho.com/kettle800/kettle-core-8.0.0.0-6-javadoc/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.html):
> Note that it's not really encryption, it's more obfuscation. Passwords are difficult to read, not impossible.

Also, by default passwords in transforms are encrypted using a default key. Poking around in the source code a bit reveals [the key](https://github.com/pentaho/pentaho-kettle/blob/bcde3387edbf63cfc5ad916ce1de5fa52c1a9cd7/core/src/main/java/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.java#L48) and [the function that does the decryption](https://github.com/pentaho/pentaho-kettle/blob/master/core/src/main/java/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.java#L123).

I asked github copilot to port the java function to python and after some tweaks a minimal PoC came together. From there I spent some time adding quality of life improvements, such as parsing each `.ktr` file for all relevant objects, formatting the output nicely, generating some basic statistics for the user, and searching for `.ktr` files within `.zip` archives. This last one was particularly nice to have because files downloaded from the Pentaho server ALWAYS come in a `.zip` file. Now you can just point the script at a directory and have it process everything for you!

This work is published as `ktr_parse.py`

```shell
python3 ktr_parse.py --help
usage: ktr_parse.py [-h] [--path PATH] [--output OUTPUT] [--seed SEED]

Process ZIP files and KTR files.

options:
  -h, --help            show this help message and exit
  --path PATH, -p PATH  Path to the ZIP file, KTR file, or directory containing ZIP and KTR files
  --output OUTPUT, -o OUTPUT
                        Path to the output CSV file
  --seed SEED, -s SEED  Custom seed for decryption
```
{: .nolineno }

```shell
REDACTED@REDACTED:~/ktr_parse$ python3 ktr_parse.py 
[+] Processed 0 ZIP files and 1 KTR files.
[+] Unique connection strings: 1
[+] Unique user:pass pairs: 1
[+] Unique 'sa' user:pass@server pairs: 0
ktr_file,server,type,database,port,username,password
Database - generic driver usage.ktr,N/A,GENERIC,N/A,-1,PENTAHO_USER,PASSWORD
```
{: .nolineno }

# Fingerquotes 'Hard' mode

As I was writing `ktr_parse.py`, I mentioned it to [Haicen](https://blog.haicen.me/) and told them I was still working on how to recover passwords stored using the non-default key.
>But it's XoR.

>>Yeah?

>So it's linear.

>>...yeah?

>So if you have the plaintext and the ciphertext you can get the key

>>Oh?

> Yeah!

Or something like that. I didn't record it. 

So, the default behavior is either:

```
plaintext xor seed == ciphertext
ciphertext xor seed == plaintext
```
But we also have the option of doing:
```
plaintext xor ciphertext == seed 
```
Assuming you have a plaintext/ciphertext pair anyways. 

There are a few ways I found to accomplish this with credentialed access to a Pentaho Data Client server.

1. Set/get the plaintext
- **Set**: Create a new database connection on the server and set a password.
- **Get**: Temporarily modify an existing database conntion from within the Pentaho Server. By pointing the config at a service that you own and clicking the 'test' button, the server may intiate a connection request that reveals a plaintext password. [Responder](https://github.com/lgandx/Responder/) is nice for this, but simpler options like netcat are viable depending on the protocol.
2. Get the ciphertext
- Download the `.ktr` for the connection you touched in step 1. Use `ktr_parse.py` to parse it or just open it and search for the relevant connection element.

I published `key_recovery.py` to facilitate recovering the seed from a plaintext/ciphertext combo. 

```shell
python3 key_recovery.py -p password -c 2be98afc86aa7f2e4bb18bd63c99dbdde
Recovered seed: 933910847463829827159347601486730416058
```
{: .nolineno }

You can then use `ktr_parse.py` with the `--seed` flag to define the recovered seed.
```shell
python3 ktr_parse.py --path ./ktr_files --output output.csv --seed 933910847463829827159347601486730416058
```
{: .nolineno }

# Tooling
You can find the tools referenced in this post at the github repo for [ktr_parse](https://github.com/stumblebot/ktr_parse), along with some other details about functionaility and arguments.

# Thanks
Thanks to [Haicen](https://blog.haicen.me/) for pointing out how simple it was to recover the 'seed' and saving us all a lot of time as a result. 

# References
1. Pentaho Kettle source code that includes the `decryptPasswordInternal` function, used for decrypting the 'Encrypted' values and the default `envSeed` value: [Pentaho Kettle: KettleTwoWayPasswordEncoder.java](https://github.com/pentaho/pentaho-kettle/blob/master/core/src/main/java/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.java#L123). 
2. Pentaho's official documentation for class: [`KettleTwoWayPasswordEncoder`](https://javadoc.pentaho.com/kettle800/kettle-core-8.0.0.0-6-javadoc/org/pentaho/di/core/encryption/KettleTwoWayPasswordEncoder.html). 
3. Riktastic's KTR that executes the (now deprecated) `decryptPassword` function: [DecryptPassword.ktr](https://github.com/Riktastic/Pentaho-Kettle-Password-Decrypt/blob/master/Decrypt_password.ktr)
4. A nice writeup by zinea llc (aka [serialenabler(???)](https://github.com/serialenabler)) on the process of preparing and using `DecryptPassword.ktr`: [Pentest Guide to Pentaho Business Analytics](https://zineausa.com/blog/2020/07/pen-test-guide-to-pentaho-business-analytics/)
5. Another reference to some of the encrypt/decrypt functions and how they are used in existing one-off utilities within the larger Pentaho Data Integration toolkit: [PDI Password Encryption](https://diethardsteiner.github.io/pdi/2017/03/03/PDI-Password-Encryption.html)
