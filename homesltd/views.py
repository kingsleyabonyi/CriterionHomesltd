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

from .serializers import UserSerializer, EmailSerializer

logger = logging.getLogger(__name__)


def generate_authorization_code_url() -> str:
    params = {
        'prompt': 'consent',
        'response_type':'code',
        'access_type': 'offline',
        'client_id': os.environ.get('ZOHO_CLIENT_ID'),
        'access_token': os.environ.get('ZOHO_ACCESS_TOKEN'),
        'redirect_uri': os.environ.get('ZOHO_REDIRECT_URI'),
        'scope':','.join(['ZohoSheet.dataAPI.UPDATE', 'ZohoSheet.dataAPI.READ', 'ZohoMail.messages.ALL', 'ZohoMail.accounts.ALL']),
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
        'client_id': os.environ.get('INFO_ZOHO_CLIENT_ID'),
        'client_secret': os.environ.get('INFO_ZOHO_CLIENT_SECRET'),
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

    def send_mail(self, access_token: str, validated_data: dict) -> dict:
        message_builder = f"Name: {validated_data['fullname']} \nPhone: {validated_data['phone_number']} \nEmail: {validated_data['email_address']} \nMessage: {validated_data['message']}"
        mail_data = {
            "fromAddress": "info@criterionhomesltd.com",
            "toAddress": "inquiries@criterionhomesltd.com",
            "subject": f"New Contact Message from {validated_data['fullname']}",
            "content": message_builder,
        }
        
        try:
            response = requests.post(
                url=f"https://mail.zoho.com/api/accounts/{os.environ.get('ACCOUNT_ID')}/messages",
                headers={
                    'Authorization': f'Zoho-oauthtoken {access_token}'
                },
                json=mail_data
            )
            if not response.ok:
                raise Exception(response.text)

            return {'message': 'Mail sent successfully!', "status": status.HTTP_201_CREATED}
        except Exception as e:
            logger.error(f"Error sending mail: {str(e)}")
            return {"message": str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR}

    def update_zoho_sheet(self, access_token: str, validated_data: dict) -> dict:
        sheet_data = {
            'method': 'worksheet.records.add',
            'worksheet_name': 'Sheet1',
            'json_data': json.dumps([{
                'Message': validated_data['message'],
                'Name': validated_data['fullname'],
                'Phone Number': validated_data['phone_number'],
                'Email Address': validated_data['email_address'],
            }])
        }
        
        try:
            response = requests.post(
                url=f"https://sheet.zoho.com/api/v2/{os.environ.get('CONTACT_WORKBOOK_ID')}",
                headers={
                    'Authorization': f'Zoho-oauthtoken {access_token}', 
                    'Content-Type': 'application/x-www-form-urlencoded'        
                }, 
                data=sheet_data
            )
            response.raise_for_status()
            return {'message': 'Sheet updated successfully!', "status": status.HTTP_201_CREATED}
        except requests.RequestException as e:
            logger.error(f"Error updating Zoho sheet: {str(e)}")
            return {"message": str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR}

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        access_token = self.get_access_token(os.environ.get('INFO_ZOHO_REFRESH_TOKEN'))
        
        mail_result = self.send_mail(access_token, serializer.validated_data)
        if mail_result['status'] != status.HTTP_201_CREATED:
            return Response({"error": mail_result['message']}, status=mail_result['status'])
        
        sheet_result = self.update_zoho_sheet(access_token, serializer.validated_data)
        if sheet_result['status'] != status.HTTP_201_CREATED:
            return Response({"error": sheet_result['message']}, status=sheet_result['status'])
        
        return Response({
            'data': serializer.data, 
            'message': 'Information stored successfully!'
        }, status=status.HTTP_201_CREATED)


class EmailSubmitView(APIView):
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

    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        access_token = self.get_access_token(os.environ.get('INFO_ZOHO_REFRESH_TOKEN'))

        data = {
            'method': 'worksheet.records.add',
            'worksheet_name': 'Sheet1',
            'json_data': json.dumps([{
                'Email': serializer.validated_data['email_address'],
            }])
        }

        try:
            response = requests.post(
                url=f"https://sheet.zoho.com/api/v2/{os.environ.get('EMAIL_WORKBOOK_ID')}",
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
