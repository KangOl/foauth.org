from oauthlib.common import add_params_to_uri
import foauth.providers


class SoundCloud(foauth.providers.OAuth2):
    # General info about the provider
    provider_url = 'http://soundcloud.com'
    docs_url = 'http://developers.soundcloud.com/docs/api/reference'
    category = 'Music'

    # URLs to interact with the API
    authorize_url = 'https://soundcloud.com/connect'
    access_token_url = 'https://api.soundcloud.com/oauth2/token'
    api_domain = 'api.soundcloud.com'

    available_permissions = [
        (None, 'read and post sounds to the cloud'),
    ]

    def bearer_type(self, token, r):
        r.url = add_params_to_uri(r.url, [((u'oauth_token', token))])
        return r

    def get_user_id(self, key):
        r = self.api(key, self.api_domain, u'/me.json')
        return unicode(r.json()[u'id'])
