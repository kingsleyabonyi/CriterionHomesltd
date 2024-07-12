from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSerializer
from rest_framework.permissions import AllowAny
from django.conf import settings
import requests
import json
import logging
import os

logger = logging.getLogger(__name__)

class UserCreateView(APIView):
    permission_classes = [AllowAny]

    def get_access_token(self):
        refresh_url = f"https://accounts.zoho.com/oauth/v2/token?refresh_token={os.environ.get('ZOHO_REFRESH_TOKEN')}&client_id={os.environ.get('ZOHO_CLIENT_ID')}&client_secret={os.environ.get('ZOHO_CLIENT_SECRET')}&grant_type=refresh_token"
        print(refresh_url)
        refresh_payload = {
            'grant_type': 'refresh_token',
            'client_id': os.environ.get('ZOHO_CLIENT_ID'),
            'client_secret': os.environ.get('ZOHO_CLIENT_SECRET'),
            'refresh_token': os.environ.get('ZOHO_REFRESH_TOKEN'),
            'access_token': os.environ.get('ZOHO_ACCESS_TOKEN'),
            'access_type': os.environ.get9('ACCESS_TYPE'),
            'prompt': os.environ.get('PROMPT')
            
        }
        # print(refresh_payload)

    def post(self, request):
        serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
           
            user = list(serializer.data.values())

            #This helps to insert a new worksheet
            paramMap = {}
            paramMap['method'] = 'worksheet.list'

            paramMap['method'] = 'worksheet.insert'

            # This helps to updates records on the sheet
            paramMap['method'] = 'worksheet.records.update'
            paramMap['header_row'] = 1
            paramMap['criteria'] = '"fullname"="Nnamdi Abonyi"'
            paramMap['worksheet_name'] = 'CriterionHomestld'

            dataObj = {}
            dataObj['fullname']='Nnamdi Abonyi'
            dataObj['phone_number']=50

            dataObj = json.dumps(dataObj)
            paramMap['data']=dataObj
            
            #This helps to update the namedrange
            paramMap = {}
            paramMap['method'] = 'namedrange.update'
            paramMap['name_of_range'] = 'homes'
            paramMap['worksheet_name'] = 'CriterionHomestld'
            paramMap['range'] = 'A1:D1'

            headers = {
                'Authorization': f'Zoho-oauthtoken {os.environ.get("ZOHO_ACCESS_TOKEN")}', 
                'Content-Type': 'application/x-www-form-urlencoded'
                
            }

            

            # Make the API call to Zoho Sheets
            url = f"https://sheet.zoho.com/api/v2/{os.environ.get('ZOHO_WORKBOOK_ID')}"
            # print(url)
            response = requests.post(url = url, headers=headers, data=paramMap)

            if response.status_code in [200, 201]:
                # Return success response
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                logger.error(f"Error from Zoho API: {response.json()}")
                # Handle errors from Zoho API
                return Response(response.json(), status=response.status_code)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)