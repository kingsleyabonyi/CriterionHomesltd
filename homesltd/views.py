from urllib.parse import urlencode
from typing import Any
import logging
import time
import json
import os

import requests

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from .serializers import UserSerializer

logger = logging.getLogger(__name__)


def generate_authorization_code_url() -> str:
    params = {
        'prompt': 'consent',
        'response_type':'code',
        'access_type': 'offline',
        'client_id': os.environ.get('ZOHO_CLIENT_ID'),
        'access_token': os.environ.get('ZOHO_ACCESS_TOKEN'),
        'redirect_uri': os.environ.get('ZOHO_REDIRECT_URI'),
        'scope':','.join(['ZohoSheet.dataAPI.UPDATE', 'ZohoSheet.dataAPI.READ']),
    }

    return f'https://accounts.zoho.com/oauth/v2/auth?{urlencode(params)}'


def generate_initial_access_refresh_pair(code: str) -> dict[str, str | int]:
    url = 'https://accounts.zoho.com/oauth/v2/token'
    data = {
        "code": code,
        "grant_type": "authorization_code",
        'client_id': os.environ.get('ZOHO_CLIENT_ID'),
        "redirect_uri": os.environ.get('ZOHO_REDIRECT_URI'),
        'client_secret': os.environ.get('ZOHO_CLIENT_SECRET'),
    }
    response = requests.post(url, data=data)
    if not response.ok:
        raise Exception(response.text)
    
    return response.json()


def generate_access_token_from_refresh(refresh: str) -> dict[str, Any]:
    url = 'https://accounts.zoho.com/oauth/v2/token'
    params = {
        'refresh_token': refresh,
        'grant_type': 'refresh_token',
        'client_id': os.environ.get('ZOHO_CLIENT_ID'),
        'client_secret': os.environ.get('ZOHO_CLIENT_SECRET'),
    }
    response = requests.post(url, params=params)
    if not response.ok:
        raise Exception(response.text)
    
    return response.json()


def fetch_access_token(refresh: str) -> str:
    url = 'https://accounts.zoho.com/oauth/v2/token'
    params = {
        'refresh_token': refresh,
        'grant_type': 'refresh_token',
        'client_id': os.environ.get('ZOHO_CLIENT_ID'),
        'client_secret': os.environ.get('ZOHO_CLIENT_SECRET'),
    }
    response = requests.post(url, params=params)
    if not response.ok:
        raise Exception(response.text)
    
    return response.json()


class UserCreateView(APIView):
    permission_classes = [AllowAny]
    access_token_info = {'token': '', 'expires_at': 0}

    def get_access_token(self, refresh_token: str):
        now = int(time.time())

        if self.access_token_info['expires_at'] <= now:
            auth_info = fetch_access_token(refresh_token)
            self.access_token_info = {
                'token': auth_info['access_token'],
                'expires_at': now + auth_info['expires_in']
            }

        return self.access_token_info['token']


    # def get(self, request):
    #     auth_url = generate_authorization_code_url()
    #     # the `code` is retrieved from the url of the completed auth flow from above.
    #     auth_info = generate_initial_access_refresh_pair('1000.5e08a08f4200b7144cf4a8b98f4a4876.d8506382f4927605b90e64a854a5c312')
    #     return Response({'auth_info': auth_info, 'auth_url': auth_url})

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = {
            'method': 'worksheet.records.add',
            'worksheet_name': 'CriterionHomestld',
            'json_data': json.dumps([{
                'message': serializer.validated_data['message'],
                'fullname': serializer.validated_data['fullname'],
                'phone_number': serializer.validated_data['phone_number'],
                'email_address': serializer.validated_data['email_address'],
            }])
        }
        access_token = self.get_access_token(os.environ.get('ZOHO_REFRESH_TOKEN'))

        try:
            response = requests.post(
                url=f"https://sheet.zoho.com/api/v2/{os.environ.get('ZOHO_WORKBOOK_ID')}",
                headers={
                    'Authorization': f'Zoho-oauthtoken {access_token}', 
                    'Content-Type': 'application/x-www-form-urlencoded'        
                }, 
                data=data
            )
            if not response.ok:
                raise Exception(response.text)
            
            return Response({'data': serializer.data, 'message': 'Information stored successfully!'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error updating Zoho sheet: {str(e)}")
            return Response({"error": "Failed to update Zoho sheet"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
