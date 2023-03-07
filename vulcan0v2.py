import falcon
import mod_wsgi.server
from modsecurity import ModSecurity
from modsecurity import Rules
import argparse
import logging

LOG_FILE = '/var/log/api_firewall.log'
CONFIG_FILE = '/etc/api_firewall.conf'
RULES_FILE = '/etc/modsecurity.d/owasp-crs.conf'

class APIFirewall:
    def __init__(self):
        self.modsec = ModSecurity()
        self.modsec.set_connector("PROXY")
        self.modsec.set_debug_log(CONFIG_FILE)
        self.modsec.set_audit_log(CONFIG_FILE)
        self.modsec.set_rules(Rules.from_file(RULES_FILE))

    def process_request(self, req, resp):
        if req.method in ['POST', 'PUT']:
            buffer_size = 4096
            try:
                while True:
                    chunk = req.stream.read(buffer_size)
                    if not chunk:
                        break
                    self.modsec.transaction(chunk, req.headers)
            except Exception as e:
                logging.error(f'Error while processing request: {str(e)}')

    def process_response(self, req, resp, resource):
        try:
            self.modsec.transaction(resource.resp.body, resource.resp.headers)
        except Exception as e:
            logging.error(f'Error while processing response: {str(e)}')

# Initialize logging
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR)

# ASCII art menu
print('''
 __     __                    _ _           
 \ \   / /__  _ __  ___ _ __ (_) | ___ _ __ 
  \ \ / / _ \| '_ \/ __| '_ \| | |/ _ \ '__|
   \ V / (_) | | | \__ \ |_) | | |  __/ |   
    \_/ \___/|_| |_|___/ .__/|_|_|\___|_|   
                       |_|                  
''')

# Parse command-line arguments
parser = argparse.ArgumentParser(description='API Firewall')
parser.add_argument('--port', type=int, default=8000, help='server port number')
args = parser.parse_args()

# Create Falcon app
app = falcon.API()

# Create API Firewall instance
api_firewall = APIFirewall()

# Add hooks for processing requests and responses
app.req_options.before_hooks.insert(0, api_firewall.process_request)
app.resp_options.after_hooks.insert(0, api_firewall.process_response)

# Start the server
try:
    mod_wsgi.server.start_server(app, port=args.port)
    print(f'\nServer started on port {args.port}.\n')
except Exception as e:
    logging.error(f'Server failed to start: {str(e)}')
