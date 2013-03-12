from rpyc import Service
from rpyc.utils.server import ForkingServer
from rpyc.utils.authenticators import SSLAuthenticator
import paramiko
import ConfigParser
from OpenSSL import crypto
import os
import socket
import logging
from logging import handlers
import time


class AutoVPNServer(Service):
    """Class to handle automation of OpenVPN certificate generation."""
    def __init__(self, *args, **kwargs):
        super(AutoVPNServer, self).__init__(*args, **kwargs)
        config = ConfigParser.SafeConfigParser()
        config.read('autovpn-server.conf')
        log_level = config.get('Operation', 'log_level')
        log_dict = {'debug': logging.DEBUG,
                    'info': logging.INFO,
                    'warn': logging.WARN,
                    'error': logging.ERROR,
                    'critical': logging.CRITICAL}
        self.host1 = config.get('SSH', 'host1').split(':')
        self.host2 = config.get('SSH', 'host2').split(':')
        self.ssh_user = config.get('SSH', 'user')
        self.ssh_key = config.get('SSH', 'keyfile')
        self.log = logging.getLogger('auto_vpn_log')
        self.th = handlers.TimedRotatingFileHandler('auto_vpn.log',
                                                    when='midnight',
                                                    backupCount=30,
                                                    utc=True)
        fmt = logging.Formatter(fmt=
            '%(asctime)s - %(process)d -- %(levelname)s: %(message)s\n')
        self.th.setFormatter(fmt)
        self.log.addHandler(self.th)
        self.log.setLevel(log_dict[log_level])

    def exposed_sign_request(self, req, common_name):
        """Method for receiving a certificate signing request, forwarding it
        to an OpenVPN server via SSH, signing it and returning the certificate
        to the client"""
        reqfile = '{0}.csr'.format(common_name)
        certfile = '{0}.crt'.format(common_name)
        # Save certificate request to be forwarded
        with open(os.getcwd() + '/{0}'.format(reqfile), 'w+') as req_file:
            req_file.write(req)
        # Establish SSH channel to OpenVPN server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.host1[0], int(self.host1[1])))
        except socket.error as e:
            try:
                sock.connect((self.host2[0], int(self.host2[1])))
            except socket.error as e:
                self.log.error('Unable to open a socket to the firewall')
                sock = None
        if sock:
            trans = paramiko.Transport(sock)
            sshkey = paramiko.RSAKey.from_private_key_file(self.ssh_key)
            try:
                trans.connect(username=self.ssh_user, pkey=sshkey)
            except paramiko.SSHException as e:
                self.log.error('Unable to connect: {0}'.format(str(e)))
                raise RetryMethodError()
            print('Connected to firewall')
            if trans.authenticated:
                chan = trans.open_session()
                sftp = trans.open_sftp_client()
                # Send request to server
                try:
                    sftp.put(os.getcwd() + '/{0}'.format(reqfile), 
                             '/home/{0}/{1}'.format(self.ssh_user, reqfile))
                except paramiko.SFTPError as e:
                    self.log.error('Unable to transfer request to firewall')
                    raise RetryMethodError()
                self.log.info('Successfully transferred request from '
                              + '{0} to firewall'.format(common_name))
                # Connect to server and use EasyRSA to sign request
                chan.get_pty()
                chan.invoke_shell()
                chan.combine_stderr = True
                while not chan.recv_ready():
                    time.sleep(1)
                chan.recv(1024)
                if chan.send_ready():
                    chan.send('sudo su -\n')
                    chan.send('mv /home/{0}/{1}'.format(self.ssh_user, reqfile)
                          + ' /etc/openvpn/gateways/keys/{0}\n'.format(reqfile))
                    while not chan.recv_ready():
                        time.sleep(1)
                    chan.recv(1024)
                if chan.send_ready():
                    chan.send('cd /etc/openvpn/gateways/easy-rsa/2.0/\n')
                    chan.send('. ./vars\n')
                    while not chan.recv_ready():
                        time.sleep(1)
                    chan.recv(1024)
                    chan.send('./sign-req {0}\n'.format(common_name))
                    while not chan.recv_ready():
                        time.sleep(1)
                    chan.recv(1024)
                    chan.send('y\n')
                    while not chan.recv_ready():
                        time.sleep(1)
                    chan.recv(1024)
                    chan.send('y\n')
                    while not chan.recv_ready():
                        time.sleep(1)
                    chan.recv(1024)
                    self.log.info('Successfully signed request from {0}'.format(
                        common_name))
                    chan.send('cp /etc/openvpn/gateways/keys/'
                              + '{0} /home/{1}/{0}\n'.format(certfile, self.ssh_user))
                    while not chan.recv_ready():
                        time.sleep(1)
                    chan.recv(1024)
                # Retrieve signed certificate from server
                try:
                    sftp.get('/home/{0}/{1}'.format(self.ssh_user, certfile),
                         os.getcwd() + '/{0}'.format(certfile))
                except paramiko.SFTPError as e:
                    self.log.error('Unable to retrieve certificate from firewall: {0}'.format(str(e)))
                chan.send('rm /home/{0}/{1}\n'.format(self.ssh_user, certfile))
                chan.close()
                sftp.close()
            with open(certfile, 'r') as certificate:
                cert = certificate.read()
            os.remove(reqfile)
            os.remove(certfile)
            # Return signed cert to client
            return cert


class RetryMethodError(Exception):
    """Custom exception used for signaling that the calling process should
    perform another attempt at method execution."""
    pass

if __name__ == '__main__':
    # Connection requires an SSL certificate signed by the same CA as the server's certificate
    authenticator = SSLAuthenticator('autovpn-server.key', 'autovpn-server.crt')
    logging.basicConfig()
    server = ForkingServer(AutoVPNServer, port=54321,
                           authenticator=authenticator)
    server.start()