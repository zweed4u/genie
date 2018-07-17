#!/usr/bin/python3
import base64
import requests


class Genie:
    def __init__(self, email, password, gateway_password, gateway_user='admin'):
        self.session = requests.session()
        self.ocapi_headers = {
            'Host':                    'ocapi.netgear.com',
            'Content-Type':            'application/json',
            'Connection':              'keep-alive',
            'X-DreamFactory-Api-Key':  '0cde913b523e6fe909aa5a403dc9f5661344b9cf60f7609f70952eb488f31641',
            'Accept':                  '*/*',
            'Accept-Language':         'en-us',
            'Accept-Encoding':         'gzip, deflate',
            'User-Agent':              'Genie_Swift4/1 CFNetwork/808.2.16 Darwin/16.3.0'
        }
        self.genieremote_headers = {
            'Host':             'genieremote.netgear.com',
            'Accept':           '*/*',
            'Accept-Language':  'en-us',
            'Connection':       'keep-alive',
            'Accept-Encoding':  'gzip, deflate',
            'User-Agent':       'Genie_Swift4/1 CFNetwork/808.2.16 Darwin/16.3.0'
        }
        self.login_response = self.netgear_login(email, password)
        self.token = self.login_response['data']['token']
        self.userId = self.login_response['data']['userId']
        byte_encoded_auth = f'{gateway_user}:{gateway_password}'.encode()
        self.auth_header = f'Basic {base64.b64encode(byte_encoded_auth).decode()}'

    def _make_request(self):
        # TODO flesh this requester method out with parameterization
        # Might be hard with different base api/urls
        pass

    def netgear_login(self, email, password):
        payload = {
            "email": email,
            "password": password
        }
        return self.session.post('https://ocapi.netgear.com/api/v2/ocAuth', json=payload, headers=self.ocapi_headers).json()

    def get_user_profile(self):
        return self.session.get('https://ocapi.netgear.com/api/v2/ocGetUserProfile', params={'accessToken':self.token}, headers=self.ocapi_headers).json()

    def get_devices(self):
        return self.session.get('https://genieremote.netgear.com/genie-remote/devices', params={'t':self.token}, headers=self.genieremote_headers).json()

    def enable_access(self):
        headers = {
            'Host':              'routerlogin.net',
            'Content-Type':      'text/plain; charset=utf-8',
            'Connection':        'keep-alive',
            'Proxy-Connection':  'keep-alive',
            'Accept':            '*/*',
            'User-Agent':        'Genie_Swift4/1 CFNetwork/808.2.16 Darwin/16.3.0',
            'Authorization':     self.auth_header,
            'Accept-Language':   'en-us',
            'Accept-Encoding':   'gzip, deflate'
        }
        # 401? Access to this resource is denied, your client has not supplied the correct authentication - wtf
        return self.session.get('http://routerlogin.net/cgi-bin/genie.cgi', params={'t':self.token}, headers=headers).content


g = Genie(NETGEAR_EMAIL_HERE, NETGEAR_PASS_HERE, GATEWAY_PASS_HERE, GATEWAY_ADMIN_HERE)
print(g.enable_access())
