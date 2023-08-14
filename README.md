# Trinity File Inspection Service (TC:File) - Version 1.0.0 Python Helper Script

## Description
The Trinity Cyber File Inspection (TC:File) API is a service that provides a verdict and metadata for any submitted file to quickly determine maliciousness. Results are powered by the Trinity Cyber in-house Formula Set, which is a growing set of detections focused on malware, exploits, techniques, and other threat vectors which are present in files.

`submit_file_v1.py` is a standalone script that allows quick testing of an uploaded file to TC:File. For v1, it can retrieve:

1. A JSON object containing a verdict + metadata (about the file and any threats Trinity has found inside the file) + debugging information (submission_id, timing).
2. A JSON object containing a verdict + expanded metadata (the full parsing tree called `parsed_metadata` + debugging information. Note: this is a licensed feature.

## Installation
This script is written for Python >= 3
We encourage the use of virtual environments; in a Linux/MacOS environment:
```
python -m venv runtime
source runtime/bin/activate
```
On Windows cmd.exe
```
python -m venv runtime
runtime\Scripts\activate.bat
```

To install the requirements, please run:
`pip install -r requirements.txt`

If not using a venv and instead globally installing the requirements for a local user:
`pip install -r requirements.txt --user`

## JWT Authentication and Submitting a File

### Usage
```
usage: submit_file_v1.py [-h] -f INFILE [-m]
                         [-pl [PASSWORD_LIST [PASSWORD_LIST ...]]]
                         [-pf PASSWORD_FILE] [-t JWT_TOKEN] [-c CONFIG]
                         [-i CLIENT_ID] [-s CLIENT_SECRET]

Submission requires a time limited token (JWT) which can either be:
 - Managed by this script (saved to a file and renewed automatically). *The JWT managed by the script is saved to `./jwt_token`; this is relative to where the script is being run from!*
 - Provided via a CLI argument
If being managed by this script, a Client ID and Client Secret are needed. These were provided to you at onboarding to the service.
To supply your Client ID and Client Secret you can (in order of precedence):
   - Provide them via CLI arguments (caveat: if not careful, this could leave secrets in your CLI history; consider exporting HISTCONTROL=ignorespace in Bash)
   - Set the environment variables `TC_FILE_ID` and `TC_FILE_SECRET` (e.g. with a .bash_profile entry to export `TC_FILE_ID=...`)
   - A JSON config file `{"client_id": "your client ID here", "client_secret": "your client secret here"}`; make sure to set good permissions (0400 or similar) on your config file. 
   - Set the `CLIENT_ID` and `CLIENT_SECRET` variables at the top of this script (caveat: protect this script as you would a password!)
   - Enter them when prompted

The preferred method of supplying secrets is the config file or entering when prompted; environments can be leaked (`/proc/${pid}/env`) and hard coded creds get accidentally commited to `git` all too often.

optional arguments:
  -h, --help            show this help message and exit

Required Arguments:
  -f INFILE, --infile INFILE
                        File to submit to TC:File

Service Feature Arguments (optional):
  -m, --parsed_metadata
                        Return additional parsed metadata
  -pl [PASSWORD_LIST [PASSWORD_LIST ...]], --password_list [PASSWORD_LIST [PASSWORD_LIST ...]]
                        List of passwords separated by a space for example:
                        'pass1 pass2 pass3'
  -pf PASSWORD_FILE, --password_file PASSWORD_FILE
                        Newline separated file to submit passwords

Authentication Arguments (optional):
  -t JWT_TOKEN, --jwt_token JWT_TOKEN
                        JWT Token for authentication; if not provided one will
                        be generated based on provided ID and SECRET.
  -c CONFIG, --config CONFIG
                        Config file to read client ID and client secret from a
                        config file. Syntax is JSON object: {"client_id":
                        "...", "client_secret": "..."}
  -i CLIENT_ID, --client_id CLIENT_ID
                        Client ID to generate JWT
  -s CLIENT_SECRET, --client_secret CLIENT_SECRET
                        Client Secret to generate JWT
```

### Submitting files for a Verdict

By default, this script will submit a file so that a user may obtain a verdict of either "malicious" or "unknown".  To view detailed parsed metadata, see "Submitting a file for Parsed Metadata" below.

*Note: if you see an unknown verdict, please do not assume a benign file - pass the file through additional analysis systems for further verification*

To submit a file (after generating a JWT token):

```
$ python submit_file_v1.py -f my_file.zip
```
A JSON object is returned and printed to the screen


### Submitting a file for a Verdict + Parsed Metadata (licensed feature):

To receive a JSON object containing extra metadata for every parsed node from a file (after generating a JWT token):

```
$ python submit_file_v1.py -f my_file.zip -m
```

A JSON object is returned and printed to the screen. This is the equivalent of using the argument `parsed_metadata=true` in the POST URI path.


### Submitting a ZIP archive with custom password list:

To submit a file and recieve JSON object containing either Verdict, or Verdict + Parsed Metadata (pending license) inside of a password protected ZIP archive, you can supply a custom password list up to 10,000 entries:

```
$ python submit_file_v1.py -f my_file.zip -pf my_password_file

// Note: password files submitted with the -pf argument should contain passwords in a newline separated format

$ python submit_file_v1.py -f my_file.zip -pl password1 password2 password3

// Note: passwords supplied with the -pl argument should be separated with one space character between each password
```

A JSON object is returned and printed to the screen. This is the equivalent of supplying a known password to decrypt an archive. By default, Trinity Cyber will apply it's own password list to ZIP files if this feature isn't used.
