# -*- coding: utf-8 -*-
"""
Authentication backend for handling firebase user.idToken from incoming
Authorization header, verifying, and locally authenticating
"""
from typing import Tuple, Dict
import logging

from firebase_admin import auth as firebase_auth
from django.utils.encoding import smart_text
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from rest_framework import (
    authentication,
    exceptions
)
import random

# from .settings import api_settings
from .models import (
    FirebaseUser,
    FirebaseUserProvider
)
from .utils import get_firebase_user_email, map_firebase_email_to_username, map_firebase_uid_to_username
from . import __title__

log = logging.getLogger(__title__)
User = get_user_model()


FIREBASE_AUTH_HEADER_PREFIX = "JWT"
FIREBASE_CHECK_JWT_REVOKED = True
FIREBASE_AUTH_EMAIL_VERIFICATION = False
FIREBASE_CREATE_LOCAL_USER = True
FIREBASE_ATTEMPT_CREATE_WITH_DISPLAY_NAME = True
FIREBASE_USERNAME_MAPPING_FUNC = map_firebase_email_to_username

class FirebaseAuthentication(authentication.TokenAuthentication):
    """
    Token based authentication using firebase.
    """
    keyword = FIREBASE_AUTH_HEADER_PREFIX


    def authenticate_credentials(
        self,
        token: str
    ) -> Tuple[AnonymousUser, Dict]:
        try:
            decoded_token = self._decode_token(token)
            firebase_user = self._authenticate_token(decoded_token)
            local_user = self._get_or_create_local_user(firebase_user)
            self._create_local_firebase_user(local_user, firebase_user)
            return (local_user, decoded_token)
        except Exception as e:
            raise exceptions.AuthenticationFailed(e)

    def _decode_token(self, token: str) -> Dict:
        """
        Attempt to verify JWT from Authorization header with Firebase and
        return the decoded token
        """
        try:
            decoded_token = firebase_auth.verify_id_token(
                token,
                check_revoked=FIREBASE_CHECK_JWT_REVOKED
            )
            # log.info(f'_decode_token - decoded_token: {decoded_token}')
            return decoded_token
        except Exception as e:
            # log.error(f'_decode_token - Exception: {e}')
            raise Exception(e)

    def _authenticate_token(
        self,
        decoded_token: Dict
    ) -> firebase_auth.UserRecord:
        """ Returns firebase user if token is authenticated """
        try:
            uid = decoded_token.get('uid')
            # log.info(f'_authenticate_token - uid: {uid}')
            firebase_user = firebase_auth.get_user(uid)
            # log.info(f'_authenticate_token - firebase_user: {firebase_user}')
            if FIREBASE_AUTH_EMAIL_VERIFICATION:
                if not firebase_user.email_verified:
                    raise Exception(
                        'Email address of this user has not been verified.'
                    )
            return firebase_user
        except Exception as e:
            log.error(f'_authenticate_token - Exception: {e}')
            raise Exception(e)

    def _get_or_create_local_user(
        self,
        firebase_user: firebase_auth.UserRecord
    ) -> User:
        """
        Attempts to return or create a local User from Firebase user data
        """
        created = False
        email = get_firebase_user_email(firebase_user)
        log.info(f'_get_or_create_local_user - email: {email}')
        user = None
        try:
            user = User.objects.get(email=email)
            # log.info(
            #     f'_get_or_create_local_user - user.is_active: {user.is_active}'
            # )
            if not user.is_active:
                raise Exception(
                    'User account is not currently active.'
                )
            user.last_login = timezone.now()
            user.save()
        except User.DoesNotExist as e:
            log.error(
                f'_get_or_create_local_user - User.DoesNotExist: {email}'
            )

            first_name = ""
            last_name = ""
            if firebase_user.display_name is not None:
                display_name = firebase_user.display_name.split(' ')
                if len(display_name) == 2:
                    first_name = display_name[0]
                    last_name = display_name[1]

            if not first_name:
                first_name = email.split('@')[0].title()

            base_username = email.split('@')[0]
            username = base_username
            while True:
                if not User.objects.filter(username=username).exists():
                    break
                username = f"{base_username}{random.randint(1, 1000)}"

            try:
                user = User.objects.create_user(
                    first_name=first_name,
                    last_name=last_name,
                    username=username,
                    email=email,
                    needs_nux=True
                )
                created = True
                user.last_login = timezone.now()

                user.save()
            except Exception as e:
                raise Exception(e)
        return user, created

    def _create_local_firebase_user(
        self,
        user: User,
        firebase_user: firebase_auth.UserRecord
    ):
        """ Create a local FireBase model if one does not already exist """
        # pylint: disable=no-member
        local_firebase_user = FirebaseUser.objects.filter(
            user=user
        ).first()

        if not local_firebase_user:
            new_firebase_user = FirebaseUser(
                uid=firebase_user.uid,
                user=user
            )
            new_firebase_user.save()
            local_firebase_user = new_firebase_user

        if local_firebase_user.uid != firebase_user.uid:
            local_firebase_user.uid = firebase_user.uid
            local_firebase_user.save()

        # store FirebaseUserProvider data
        for provider in firebase_user.provider_data:
            local_provider = FirebaseUserProvider.objects.filter(
                provider_id=provider.provider_id,
                firebase_user=local_firebase_user
            ).first()
            if not local_provider:
                new_local_provider = FirebaseUserProvider.objects.create(
                    provider_id=provider.provider_id,
                    uid=provider.uid,
                    firebase_user=local_firebase_user,
                )
                new_local_provider.save()

        # catch locally stored providers no longer associated at Firebase
        local_providers = FirebaseUserProvider.objects.filter(
            firebase_user=local_firebase_user
        )
        if len(local_providers) != len(firebase_user.provider_data):
            current_providers = \
                [x.provider_id for x in firebase_user.provider_data]
            for provider in local_providers:
                if provider.provider_id not in current_providers:
                    FirebaseUserProvider.objects.filter(
                        id=provider.id
                    ).delete()
