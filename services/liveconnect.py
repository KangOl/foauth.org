import foauth.providers


class LiveConnect(foauth.providers.OAuth2):
    # General info about the provider
    provider_url = 'https://www.live.com/'
    docs_url = 'http://msdn.microsoft.com/en-us/library/hh243648.aspx'
    category = 'Productivity'

    # URLs to interact with the API
    authorize_url = 'https://oauth.live.com/authorize'
    access_token_url = 'https://oauth.live.com/token'
    api_domain = 'apis.live.net'

    available_permissions = [
        ('wl.basic', 'read your basic info and contacts'),
        ('wl.offline_access', "access your information while you're not logged in"),
        ('wl.birthday', 'access your complete birthday'),
        ('wl.calendars', 'read your calendars and events'),
        ('wl.calendars_update', 'write to your calendars and events'),
        ('wl.contacts_birthday', "access your contacts' birthdays"),
        ('wl.contacts_create', 'add new contacts to your address book'),
        ('wl.contacts_calendars', "read your contacts' calendars"),
        ('wl.contacts_photos', "read your contacts' photos and other media"),
        ('wl.contacts_skydrive', 'read files your contacts have shared with you'),
        ('wl.emails', 'read your email addresses'),
        ('wl.events_create', 'create events on your default calendar'),
        ('wl.messenger', 'chat with your contacts using Live Messenger'),
        ('wl.phone_numbers', 'read your phone numbers'),
        ('wl.photos', 'read your photos and other media'),
        ('wl.postal_addresses', 'read your postal addresses'),
        ('wl.share', 'update your status message'),
        ('wl.skydrive', "read files you've stored in SkyDrive"),
        ('wl.skydrive_update', "write to files you've stored in SkyDrive"),
        ('wl.work_profile', 'read your employer and work position information'),
        ('wl.applications', 'access the client IDs you use to interact with Live services'),
        ('wl.applications_create', 'create new client IDs to interact with Live services'),
    ]

    bearer_type = foauth.providers.BEARER_URI

    def get_user_id(self, key):
        r = self.api(key, self.api_domain, u'/v5.0/me')
        return r.json()[u'id']
