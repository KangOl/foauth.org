from xml.dom import minidom

import foauth.providers


class TripIt(foauth.providers.OAuth1):
    # General info about the provider
    provider_url = 'http://www.tripit.com/'
    docs_url = 'http://tripit.github.com/api/doc/v1/'
    category = 'Travel'

    # URLs to interact with the API
    request_token_url = 'https://api.tripit.com/oauth/request_token'
    authorize_url = 'https://www.tripit.com/oauth/authorize'
    access_token_url = 'https://api.tripit.com/oauth/access_token'
    api_domain = 'api.tripit.com'

    available_permissions = [
        (None, 'read, create and modify your trips'),
    ]

    def get_user_id(self, key):
        r = self.api(key, self.api_domain, u'/v1/get/profile')
        dom = minidom.parseString(r.content)
        return dom.getElementsByTagName('Profile')[0].getAttribute('ref')
