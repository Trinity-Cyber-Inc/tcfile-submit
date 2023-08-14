import requests
import os
from base64 import b64encode
#import magic
import argparse
import json
import urllib3
import sys
import jwt
import time
import getpass
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SUBMISSION_URI = "https://deepocean.trinitycyber.com/api/v1/submit"
OAUTH_URL = "https://login.trinitycyber.com/oauth2/token"
SCOPE = "target-entity:907b165c-ceaf-469b-81ed-1364c54ceea1"
CLIENT_ID = None
CLIENT_SECRET= None

def generate_jwt_token(id_flag=None, secret_flag=None):
    if not (id_flag and secret_flag):
        print("Please provide a valid client id and client secret via the TC_FILE_ID and TC_FILE_SECRET environment variables, -i and -s CLI parameters, or input prompt to authenticate.")
        sys.exit(1)
    auth_params = auth=(id_flag, secret_flag)
    rv = requests.post(OAUTH_URL, auth=auth_params, data=dict(
        grant_type='client_credentials', scope=SCOPE), verify=False)
    rv.raise_for_status()
    response_json = rv.json()
    expiration_date = time.time() + response_json["expires_in"]
    print("Received JWT Token and stored as jwt_token in this directory")
    print("Your token expires {}".format(time.ctime(expiration_date) + " UTC"))
    with open("jwt_token", "w") as fout:
        fout.write(response_json["access_token"])
    return response_json["access_token"]

def check_expiration(jwt_token):
    decoded_jwt = jwt.decode(jwt_token, verify=False)
    expiration_date = decoded_jwt["exp"]
    iat_date = decoded_jwt["iat"]
    return expiration_date, iat_date

class DeepOcean:
    def __init__(self, jwt_token):
        self.jwt_token = jwt_token
        self.headers = {"Authorization": "Bearer {}".format(self.jwt_token),
                        "Content-Type": "application/json"}

    def create_base64_data(self, infile):
        base64_data = b64encode(
            infile).strip(b"\n").decode("ascii")
        return base64_data

    def submit(self, file_name, base64_data, parsed_metadata=None, pass_list=None,
               pass_file = None):
        #mime = magic.Magic(mime=True)
        #mimetype = mime.from_file(file_name)
        body = {
            "data_b64": base64_data,
            "file_name": file_name
        }
        if mimetype is not None:
            body["mime_type"] = mimetype
        if pass_list and not pass_file:
            body["file_passwords"] = pass_list
        if pass_file and not pass_list:
            body["file_passwords"] = [i.strip() for i in pass_file.readlines()]
        endpoint = SUBMISSION_URI
        if parsed_metadata:
            endpoint = endpoint + "?parsed_metadata=true"
        try:
            rv = requests.post(endpoint,
                            headers=self.headers,
                            json=body,
                            verify=False)
            rv.raise_for_status()
            response_json = rv.json()
            return response_json
        except requests.exceptions.HTTPError as error:
            print(error)


def arguments():
    class HelpfulParser(argparse.ArgumentParser):
        def error(self, message):
            self.print_help()
            sys.stderr.write('{:s}: error: {:s}\n'.format(sys.argv[0], message))
            sys.exit(2)

    description_text = """
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
"""

    parser = HelpfulParser(description=description_text, formatter_class=argparse.RawDescriptionHelpFormatter)
    required_arg_group = parser.add_argument_group('Required Arguments')
    required_arg_group.add_argument("-f", "--infile",
                            help="File to submit to TC:File",
                            required=True
                        )
    
    service_arg_group = parser.add_argument_group('Service Feature Arguments (optional)')
    service_arg_group.add_argument("-m", "--parsed_metadata",
                        help="Return additional parsed metadata",
                        action="store_true")
    service_arg_group.add_argument("-pl", "--password_list",
                        nargs='*',
                        help="List of passwords separated by a space \
                        for example: \'pass1 pass2 pass3\'")
    service_arg_group.add_argument("-pf","--password_file",
                        type=argparse.FileType('r'),
                        help="Newline separated file to submit passwords")

    opt_arg_group = parser.add_argument_group('Authentication Arguments (optional)')
    opt_arg_group.add_argument("-t", "--jwt_token",
                        help="JWT Token for authentication; if not provided one will be generated based on provided ID and SECRET.")
    opt_arg_group.add_argument("-c", "--config",
                        help="Config file to read client ID and client secret from a config file. Syntax is JSON object: {\"client_id\": \"...\", \"client_secret\": \"...\"}")
    opt_arg_group.add_argument("-i", "--client_id",
                        help="Client ID to generate JWT")
    opt_arg_group.add_argument("-s", "--client_secret",
                        help="Client Secret to generate JWT")
    return parser.parse_args()

def get_id(args):
    ident = args.client_id
    if not ident and "TC_FILE_ID" in os.environ:
        ident = os.environ["TC_FILE_ID"]
    if not ident and CLIENT_ID:
        ident = CLIENT_ID
    if not ident:
        ident = input("Please enter your TC:File client ID (provided to you at onboarding): ")
    return ident

def get_secret(args):
    secret = args.client_secret
    if not secret and "TC_FILE_SECRET" in os.environ:
        secret = os.environ["TC_FILE_SECRET"]
    if not secret and CLIENT_SECRET:
        secret = CLIENT_SECRET
    if not secret:
        secret = getpass.getpass("Please enter your TC:File client secret (provided to you at onboarding): ")
    return secret

if __name__ == '__main__':
    args = arguments()
    JWT = args.jwt_token

    if args.config:
        if not os.path.exists(args.config):
            print(f"The provided path to the config file: {args.config} does not exist.")
            exit(1)
        with open(args.config, 'r') as fin:
            config_json = json.loads(fin.read())
            if "client_id" in config_json:
                CLIENT_ID = config_json["client_id"]
            if "client_secret" in config_json:
                CLIENT_SECRET = config_json["client_secret"]
                

    if not JWT and os.path.exists("jwt_token"):
        with open("jwt_token", 'r') as fin:
            JWT = fin.read()
        expiration, iat = check_expiration(JWT)
        now = time.time()
        if expiration < now:
            JWT = generate_jwt_token(get_id(args), get_secret(args))

        if (expiration >  now):
            # sets a threshold to renew if more than 50% of expiration time has
            # elapsed
            if ((expiration - now) / (expiration - iat)) < .5:
                JWT = generate_jwt_token(get_id(args), get_secret(args))

    if not JWT:
        JWT = generate_jwt_token(get_id(args), get_secret(args))

    deepocean = DeepOcean(JWT)
    with open(args.infile, 'rb') as fin:
        fh = fin.read()

    b64_data = deepocean.create_base64_data(fh)
    if args.parsed_metadata:
        if not args.password_list and not args.password_file:
            response = deepocean.submit(args.infile, b64_data, parsed_metadata=True)
        if args.password_list and not args.password_file:
            response = deepocean.submit(args.infile, b64_data, parsed_metadata=True, pass_list=args.password_list)
        if args.password_file and not args.password_list:
            response = deepocean.submit(args.infile, b64_data, parsed_metadata=True, pass_file = args.password_file)
    else:
        if args.password_list and not args.password_file:
            response = deepocean.submit(args.infile, b64_data, pass_list = args.password_list)
        if args.password_file and not args.password_list:
            response = deepocean.submit(args.infile, b64_data, pass_file = args.password_file)
        if not args.password_file and not args.password_list:
            response = deepocean.submit(args.infile, b64_data)
    print(json.dumps(response, indent=2))
