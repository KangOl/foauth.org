import os
from oauthlib.common import add_params_to_uri
from werkzeug.urls import url_decode
import foauth.providers


class StackExchange(foauth.providers.OAuth2):
    # General info about the provider
    name = 'Stack Exchange'
    provider_url = 'https://stackexchange.com/'
    docs_url = 'https://api.stackexchange.com/docs'
    category = 'Support'

    # URLs to interact with the API
    authorize_url = 'https://stackexchange.com/oauth'
    access_token_url = 'https://stackexchange.com/oauth/access_token'
    api_domain = 'api.stackexchange.com'

    available_permissions = [
        (None, 'read your user information'),
        ('read_inbox', 'read your global inbox'),
    ]

    def bearer_type(service, token, r):
        params = [((u'access_token', token)), ((u'key', service.app_key))]
        r.url = add_params_to_uri(r.url, params)
        return r

    def __init__(self, *args, **kwargs):
        super(StackExchange, self).__init__(*args, **kwargs)

        # StackExchange also uses an application key
        self.app_key = os.environ.get('STACKEXCHANGE_APP_KEY', '').decode('utf8')

    def get_authorize_params(self, redirect_uri, scopes):
        # Always request a long-lasting token
        scopes.append('no_expiry')
        return super(StackExchange, self).get_authorize_params(redirect_uri, scopes)

    def parse_token(self, content):
        data = url_decode(content)
        data['expires_in'] = data.get('expires', None)
        return data

    def get_user_id(self, key):
        r = self.api(key, self.api_domain, u'/2.0/me/associated')
        return unicode(r.json()[u'items'][0][u'account_id'])
