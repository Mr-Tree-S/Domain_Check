# Domain_Check

> A simple script for checking the reputation, MX record, and URL of multiple domains

**Domain_Check** is being actively developed by [@Ripper-S](https://github.com/Ripper-S)


## Installation & Usage
**Requirement: python 3.7 or higher**

Choose one of these installation options:

- Install with **git**: `git clone https://github.com/Ripper-S/Domain_Check.git`(**RECOMMENDED**)
- Install relevant modules: `pip install -r requirements.txt`

### Options
The script accepts the following command line arguments:

- `domains`: One or more domains to check, separated by spaces.

- `--file`: A file containing a list of domains to check, with one domain per line. If this option is used, any domains specified on the command line are ignored.

- `-r`, `--reputation`: Check the reputation of each domain. This option queries the VirusTotal API to determine the number of malicious and harmless reports associated with each domain.

- `-m`, `--mx`: Check the MX record of each domain. This option queries the VirusTotal API to determine the MX record associated with each domain.

- `-u`, `--url`: Check the URL associated with each domain. This option queries the urlscan.io API to determine the URL associated with each domain.

### Configuration
To use your API keys, replace your_VT_API_KEY and your_URLSCAN_API_KEY with your actual keys.
Make sure to **keep your API keys secure and not to share them publicly**, as they can be used to make API requests on your behalf and may incur charges.

### How to use
To check one or more domains, run the following command in your terminal:
```
python main.py -rmu example.com

```
You can specify multiple domains separated by spaces:
```
python main.py -rmu example.com example.net

```
If you have a text file containing a list of domains to check, you can use the following command:
```
python main.py -rmu --file domain_list.txt

```
Note that you can use any combination of the -r, -m, and -u options, and that the order of the parameters does not matter as long as the domain names and the --file option (if used) come after the options for checking reputation, MX records, and URLs.

### Threads
The thread number (**-t | --threads**) reflects the number of separated brute force processes. And so the bigger the thread number is, the faster domain check runs. By default, the number of threads is 4, but you can increase it if you want to speed up the progress.


## Contribution
At present, I am alone in contributing


## License
Copyright (C) Ripper-S (ripper-s@ripper-s.com)

License: Apache License 2.0