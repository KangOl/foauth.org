import foauth.providers


class GetSatisfaction(foauth.providers.OAuth1):
    # General info about the provider
    name = 'Get Satisfaction'
    provider_url = 'http://getsatisfaction.com/'
    docs_url = 'http://getsatisfaction.com/developers/api-resources'
    category = 'Support'

    # URLs to interact with the API
    request_token_url = 'http://getsatisfaction.com/api/request_token'
    authorize_url = 'http://getsatisfaction.com/api/authorize'
    access_token_url = 'http://getsatisfaction.com/api/access_token'
    api_domain = 'api.getsatisfaction.com'

    available_permissions = [
        (None, 'access your support requests'),
    ]

    def get_user_id(self, key):
        r = self.api(key, self.api_domain, u'/me.json')
        return unicode(r.json()[u'id'])
