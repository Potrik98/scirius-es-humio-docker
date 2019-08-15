from __future__ import unicode_literals

# This command is used purely to create a static token key for 
# the scirius user used by the development setup.
# This file is not part of scirius, and is based on:
# https://github.com/encode/django-rest-framework/blob/ec1b14174f8717337fc4402c7cea43f647e2586e/rest_framework/authtoken/models.py#L25


from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from rest_framework.authtoken.models import Token

UserModel = get_user_model()


class Command(BaseCommand):
    help = 'Create default DRF Token for the scirius user'

    def create_user_token(self):
        user = UserModel._default_manager.get_by_natural_key('scirius')
        token = Token.objects.update_or_create(user=user, key='d292d0af257f5887c1404f73ad50bd36d27ca3f1')
        return token[0]


    def handle(self, *args, **options):
        try:
            token = self.create_user_token()
        except UserModel.DoesNotExist:
            raise CommandError(
                'Cannot create the Token: user {} does not exist'.format(
                    username)
            )
        self.stdout.write(
            'Generated token {} for user {}'.format(token.key, 'scirius'))
