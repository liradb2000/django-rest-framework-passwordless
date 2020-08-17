from django.utils.module_loading import import_string
from drfpasswordless.settings import api_settings
from drfpasswordless.utils import (
    create_callback_token_for_user,
)


class TokenService(object):
    @staticmethod
    def send_token(to_alias, alias_type, token_type, **message_payload):
        token = create_callback_token_for_user(to_alias, alias_type, token_type)
        send_action = None

        if alias_type == 'email':
            send_action = import_string(api_settings.PASSWORDLESS_EMAIL_CALLBACK)
        elif alias_type == 'mobile':
            send_action = import_string(api_settings.PASSWORDLESS_SMS_CALLBACK)
        # Send to alias
        success = send_action(to_alias, token, **message_payload)
        return success
