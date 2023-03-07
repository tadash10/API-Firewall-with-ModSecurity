import falcon
import mod_wsgi.server
from modsecurity import ModSecurity
from modsecurity import Rules

class APIFirewall:
    def __init__(self):
        self.modsec = ModSecurity()
        self.modsec.set_connector("PROXY")
        self.modsec.set_debug_log('/var/log/modsec_debug.log')
        self.modsec.set_audit_log('/var/log/modsec_audit.log')
        self.modsec.set_rules(Rules.from_file('/etc/modsecurity.d/owasp-crs.conf'))

    def process_request(self, req, resp):
        if req.method == 'POST' or req.method == 'PUT':
            self.modsec.transaction(req.stream.read(), req.headers)

    def process_response(self, req, resp, resource):
        self.modsec.transaction(resource.resp.body, resource.resp.headers)

# ASCII art menu
print('''
 __     __                    _ _           
 \ \   / /__  _ __  ___ _ __ (_) | ___ _ __ 
  \ \ / / _ \| '_ \/ __| '_ \| | |/ _ \ '__|
   \ V / (_) | | | \__ \ |_) | | |  __/ |   
    \_/ \___/|_| |_|___/ .__/|_|_|\___|_|   
                       |_|                  
''')

print('Welcome to API Firewall!\n')
print('Please select an option:\n')
print('1. Start the server')
print('2. Exit\n')

# Get user input
choice = input('Enter your choice (1 or 2): ')

if choice == '1':
    # Create Falcon app
    app = falcon.API()

    # Create API Firewall instance
    api_firewall = APIFirewall()

    # Add hooks for processing requests and responses
    app.req_options.before_hooks.append(api_firewall.process_request)
    app.resp_options.after_hooks.append(api_firewall.process_response)

    # Start the server
    mod_wsgi.server.start_server(app, port=8000)
    print('\nServer started on port 8000.\n')
elif choice == '2':
    print('\nGoodbye!\n')
else:
    print('\nInvalid choice. Please try again.\n')
