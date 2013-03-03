import foauth.providers


class Readmill(foauth.providers.OAuth2):
    # General info about the provider
    provider_url = 'http://readmill.com/'
    docs_url = 'https://github.com/Readmill/api/wiki'
    category = 'Books'

    # URLs to interact with the API
    authorize_url = 'http://readmill.com/oauth/authorize'
    access_token_url = 'http://readmill.com/oauth/token'
    api_domain = 'api.readmill.com'

    available_permissions = [
        (None, 'read and write to your reading history'),
        ('non-expiring', 'access your data indefinitely'),
    ]

    bearer_type = foauth.providers.BEARER_URI

    def get_user_id(self, key):
        r = self.api(key, self.api_domain, u'/me')
        return unicode(r.json()[u'id'])
