from OpenSSL import crypto
import rpyc
import ConfigParser


class AutoVPNClient(object):
    """Client to generate private key and certificate signing request. Request
    is sent to RPyC server to be signed."""
    def __init__(self):
        config = ConfigParser.SafeConfigParser()
        config.read('autovpn-client.conf')
        cn = config.get('SSL', 'common_name')
        country = config.get('SSL', 'country')
        state = config.get('SSL', 'state')
        city = config.get('SSL', 'city')
        self.size = int(config.get('SSL', 'key_size'))
        org = config.get('SSL', 'organization')
        email = config.get('SSL', 'email')
        self.req_dict = {'CN': cn,
                         'ST': state,
                         'L': city,
                         'O': org,
                         'emailAddress': email,
                         'C': country}
        rpc_host = config.get('Host', 'name')
        rpc_port = int(config.get('Host', 'port'))
        self.conn = rpyc.ssl_connect(rpc_host, rpc_port,
                                 keyfile='autovpn-client-default.key',
                                 certfile='autovpn-client-default.crt')

    def create_key(self):
        """Generate private key"""
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, self.size)
        keyfile = '{0}.key'.format(self.req_dict['CN'])
        with open(keyfile, 'w+') as key:
            key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
        return pkey

    def create_request(self, pkey):
        """Generate certificate signing request"""
        req = crypto.X509Req()
        subj = req.get_subject()
        for key, value in self.req_dict.items():
            if len(value) > 0:
                setattr(subj, key, value)
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha256')
        return req

    def get_request_signed(self, req):
        """Call RPyC remote method to get request signed"""
        req_string = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        try:
            cert = self.conn.root.sign_request(req_string, self.req_dict['CN'])
        except RetryMethodError as e:
            cert = self.conn.root.sign_request(req_string, self.req_dict['CN'])
        with open('{0}.crt'.format(self.req_dict['CN']), 'w+') as certfile:
            certfile.write(cert)


class RetryMethodError(Exception):
    """Custom exception to signal that the calling program should re-attempt
    the failed method"""
    pass

if __name__ == '__main__':
    client = AutoVPNClient()
    key = client.create_key()
    req = client.create_request(key)
    client.get_request_signed(req)
    client.conn.close()