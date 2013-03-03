from threading import local
try:
    import StringIO
except ImportError:
    from io import StringIO

from oauthlib.oauth1.rfc5849 import SIGNATURE_PLAINTEXT, SIGNATURE_TYPE_AUTH_HEADER, SIGNATURE_TYPE_BODY
import requests

import foauth.providers

class Launchpad(foauth.providers.OAuth1):
    # General info about the provider
    provider_url = 'https://launchpad.net/'
    docs_url = 'https://launchpad.net/+apidoc/1.0.html'
    category = 'Code'

    # URLs to interact with the API
    request_token_url = 'https://launchpad.net/+request-token'
    authorize_url = 'https://launchpad.net/+authorize-token'
    access_token_url = 'https://launchpad.net/+access-token'
    api_domains = ['api.launchpad.net', 'api.staging.launchpad.net']

    signature_method = SIGNATURE_PLAINTEXT

    available_permissions = [
        ('READ_PUBLIC', 'read non-private data'),
        ('WRITE_PUBLIC', 'read and write non-private data'),
        ('READ_PRIVATE', 'read anything, including private data'),
        ('WRITE_PRIVATE', 'read and write anything, including private data'),
    ]
    permissions_widget = 'radio'

    _local = local()

    def __init__(self, key, secret):
        # Launchpad secret must be empty. Configurated key is ignored.
        super(Launchpad, self).__init__(key, '')

    def get_user_id(self, key):
        # As the redirection keep the same headers, the second request fail
        # because the nonce has already been consumed. In fact we don't even
        # need a to follow the redirect as we can extract the user_id from the
        # redirection url.
        r = super(Launchpad, self).api(key, self.api_domains[0], '/1.0/people/+me',
                                       allow_redirects=False)
        redirection = r.headers['location']
        return redirection.rsplit('~', 1)[-1]

    def get_authorize_params(self, redirect_uri, scopes):
        params = super(Launchpad, self).get_authorize_params(redirect_uri,
                                                             scopes)
        # Launchpad does not respect the spec and do not append the
        # oauth_token to the callback url. So we do.
        params['oauth_callback'] += '?oauth_token=' + params['oauth_token']
        # Launchpad specific. We specify the asked scope
        params['allow_permission'] = ','.join(scopes)
        return params

    @property
    def signature_type(self):
        # For the access-token only, Launchpad use BODY signature. In order to
        # be thread-safe, we need to store the type to use in a thread local.
        return getattr(self._local, 'signature_type', SIGNATURE_TYPE_AUTH_HEADER)

    def callback(self, data, url_name):
        self._local.signature_type = SIGNATURE_TYPE_BODY
        try:
            return super(Launchpad, self).callback(data, url_name)
        finally:
            delattr(self._local, 'signature_type')

    def api(self, key, domain, path, method='GET', **kwargs):
        if method == 'GET' and path.rstrip('/') == '/1.0/people/+me':
            # This url will do a redirect, but, due to OAuth headers reused,
            # the redirection will fail. We anticipe and return the correct
            # redirection directly.
            r = requests.models.Response()
            r.status_code = 302
            r.raw = StringIO.StringIO('')
            r.headers['location'] = '/{0}/1.0/~{1}'.format(domain, key.service_user_id)
            return r

        return super(Launchpad, self).api(key, domain, path, method, **kwargs)
