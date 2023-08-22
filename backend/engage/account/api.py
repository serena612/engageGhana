# coding: utf-8

from datetime import datetime
from socket import timeout

from django.contrib.auth import get_user_model, login
from django.db import transaction
from django.db.models import Q,Count, F
from django.shortcuts import redirect
from django.utils import timezone
from django.core.paginator import Paginator
from ipaddress import ip_address
from engage.settings.base import API_SERVER_URL, USER_EXCEPTION_LIST, VAULT_SERVER_URL, ENABLE_VAULT, INTEGRATION_DISABLED, TRUSTED_IP, DISABLE_PIN
import requests
from rest_framework import mixins, viewsets, status, exceptions
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework import permissions
from engage.operator.models import RedeemPackage, SubConfiguration
from uuid import uuid4
from drf_yasg.utils import swagger_auto_schema
from drf_yasg.openapi import Schema, TYPE_ARRAY, TYPE_OBJECT, TYPE_STRING
from engage.core.models import HTML5Game
import sys, base64, hvac, json
from django.utils.translation import ugettext_lazy as _
from engage.account.middlewares import LastSeenMiddleware


from .constants import (
    FriendStatus,
    SectionLog,
    SubscriptionPlan,
    SubscriptionPackages,
    Transaction,
    CoinTransaction
)
from engage.core.constants import WinAction, NotificationTemplate
from engage.core.models import Notifications, BattlePassMission, BattlePass,Avatar
from engage.mixins import PaginationMixin
from . import serializers
from .models import (
    FriendList,
    User,
    UserNotification,
    UserBattlePassMission,
    UserFavoriteFriend,
    SendCoinsHistory,
    UserGamePlayed,
    UserBattlePass,
    UserTransactionHistory,
    UserSectionLog
)
from .serializers import EditProfileSerializer
from ..core.serializers import TrophySerializer, StickerSerializer
from ..services import notify_when
from ..tournament.models import Tournament, TournamentPrize
from ..tournament.serializers import TournamentSerializer
from .constants import (	
    FriendStatus,	
    SubscriptionPlan	
)
from engage.operator.models import RedeemPackage
from .exceptions import AdLimitReached, AdAlreadyClicked, SelfAd
from engage.core.models import HTML5Game

import logging
from logging.handlers import TimedRotatingFileHandler
from django.shortcuts import render, redirect

#logging.basicConfig(filename="log.txt", format='%(asctime)s %(message)s',level=logging.DEBUG)

log_filename = "logs/engagelog.log"
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Create a timed rotating file handler
file_handler = TimedRotatingFileHandler(log_filename, when="midnight", interval=1, backupCount=10)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# Add the file handler to the root logger
logging.getLogger("").addHandler(file_handler)


UserModel = get_user_model()
OWN_CREATIVES = ['6178477617', '6180000871', '6180646283', '6180545204']


class EncryptedMessageSender:
    def __init__(self, server=API_SERVER_URL, vault_url=VAULT_SERVER_URL,
     keys=['b533da693758f52b5a44042405770597ac750a000bb429847dd83911a58ad8fe1c',
      'ab60773e5e855baae8b7d23ae92855bfa78863ff4b086b19c55c140610a437eafd',
       '6ac6401cb7879f86777bfb4e79ca6da98cabf83c9fdbbde98c23204921775bf85f'], username='mighty', password='P@mpl0P@ssw!RD') -> None:
        # self.command = command
        self.server = server
        # self.request_url = request_url
        # self.headers = headers
        # self.data = data
        self.client = hvac.Client(url=vault_url, timeout=2)
        self.keys = keys
        self.username = username
        self.password = password
        print("Client Initiated !")

    def is_initialized(self):
        return self.client.sys.is_initialized()

    def is_sealed(self):
        return self.client.sys.is_sealed()

    def is_authenticated(self):
        return self.client.is_authenticated()

    def base64ify(bytes_or_str):
        if sys.version_info[0] >= 3 and isinstance(bytes_or_str, str):
            input_bytes = bytes_or_str.encode('utf8')
        else:
            input_bytes = bytes_or_str

        output_bytes = base64.urlsafe_b64encode(input_bytes)
        if sys.version_info[0] >= 3:
            return output_bytes.decode('ascii')
        else:
            return output_bytes

    def base64decode(base64str):
        output_bytes=base64.urlsafe_b64decode(base64str)
        if sys.version_info[0] >= 3:
            return output_bytes.decode('ascii')
        else:
            return output_bytes

    def unseal_vault(self):
        try:
            unseal_response = self.client.sys.submit_unseal_keys(self.keys)
            print(unseal_response)
            return self.is_sealed()
        except:
            return False

    def authenticate(self):
        try:
            login_response = self.client.auth.userpass.login(
                username=self.username,
                password=self.password  
            )
            print(login_response)
            return self.is_authenticated()
        except:
            return False

    def decrypt(self, ciphetext):
        ciphertext = ciphetext['message']
        decrypt_data_response = self.client.secrets.transit.decrypt_data(
            name='hvac-key',
            ciphertext=ciphertext,
        )
        return self.base64decode(decrypt_data_response['data']['plaintext'])


    def send(self, command, headers={}, data={}):
        url = self.server+command
        if not self.is_initialized():
            return 'Vault not initialized!', 567
        if self.is_sealed():
            if not self.unseal_vault():
                return 'Vault could not be unsealed!', 568
        if not self.is_authenticated():
            if not self.authenticate():
                return 'Could not authenticate to Vault!', 569

        if headers:
            headers = json.dumps(headers)
            print(headers)
            print(headers.encode())
            encrypt_data_response = self.client.secrets.transit.encrypt_data(
            name='hvac-key',
            plaintext=self.base64ify(headers.encode()),
        )
            enc_headers = encrypt_data_response['data']['ciphertext']
        else:
            enc_headers = headers
        if data:
            data = json.dumps(data)
            encrypt_data_response = self.client.secrets.transit.encrypt_data(
            name='hvac-key',
            plaintext=self.base64ify(data.encode()),
        )
            enc_data = encrypt_data_response['data']['ciphertext']
        else:
            enc_data = data
        
        try:
            api_call = requests.post(url, headers={'message': enc_headers}, json={'message': enc_data}, timeout=2)
        except requests.exceptions.RequestException as e:
            print(e)
            return 'Server error', 555
        if api_call.status_code==200:
            res = api_call.json()
            try:
                response = self.decrypt(res)
            except Exception as e:
                print(e)
                return 'Error decrypting reply!', 596
            
            res = response['statusCode']
            if 'LoadData' in self.command and(res['code'] == 76 or res['code'] == 77 or res['code'] == 79): # 76 pending sub - 77 pending unsub - 79 sub
                    return response['profile'], res['code']
            else:
                return res['message'], res['code']
        else:
            return api_call.content, api_call.status_code


def send_pincode(phone_number, idnetwork="1", vault=None):
    headers = {'msisdn': phone_number,
                'idnetwork': idnetwork} # post data
    command = '/api/User/SendPincode'
    print(phone_number)
    if vault:
        return vault.send(command=command, headers=headers)
    url = API_SERVER_URL+command
    
    try:
        api_call = requests.post(url, headers=headers, data={}, timeout=2)
    except requests.exceptions.RequestException as e:
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        # print(api_call)
        res = api_call.json()['statusCode']
        return res['message'], res['code']
    else:
        return api_call.content, api_call.status_code


def verify_pincode(phone_number, pincode, vault=None):
    command = '/api/User/ValidatePincode'
    pincode = str(pincode)
    print("Verifying pincode", pincode, "for number", phone_number)
    headers = {
        'Content-type':'application/json', 
        'accept': 'text/plain',
        'msisdn': phone_number
    }
    data = {
            'pincode': pincode,
            } 
    if vault:
        return vault.send(command=command, headers=headers, data=data)       
    url = API_SERVER_URL+command
    
    try:
        api_call = requests.post(url, headers=headers, json=data, timeout=2)
    except requests.exceptions.RequestException as e:  
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()['statusCode']
        return res['message'], res['code']
    else:
        return api_call.content, api_call.status_code


def load_data_api(phone_number, idnetwork, vault=None):  
    command = '/api/User/LoadData'
    headers = {'msisdn': phone_number, 
            'idnetwork': idnetwork
            } 
    
    url = API_SERVER_URL+command
    if vault:
        return vault.send(command=command, headers=headers)
    try:
        api_call = requests.post(url, headers=headers, data={}, timeout=2)
    except requests.exceptions.RequestException as e:  
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        
        apijson = api_call.json()
        print(apijson)
        res = apijson['statusCode']
        if res['code'] == 76 or res['code'] == 77 or res['code'] == 79: # 76 pending sub - 77 pending unsub - 79 sub
            return apijson['profile'], res['code']
        else:
            return res['message'], res['code']
    else:
        return api_call.content, api_call.status_code


def subscribe_api(phone_number, idbundle, idservice, referrer=None, idchannel=2, vault=None):  # default channel id is web
    print("Subscribing", phone_number, "to", idbundle, "service", idservice)
    command = '/api/User/Subscribe'
    uniqueid = str(uuid4())
    data = {'msisdn': phone_number, 
            'idChannel': idchannel,
            'idBundle':idbundle,
            'idService':idservice.upper(),
            'transactionId':uniqueid,
            }
    if referrer:
        print("Referrer by:", referrer)
        data['inviteeId'] = str(referrer)
    if vault:
        return vault.send(command=command, data=data)       
    url = API_SERVER_URL+command
    try: 
        print(data)
        api_call = requests.post(url, headers={}, json=data, timeout=3)
        print(api_call)
        print(api_call.content)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        # raise SystemExit(e)
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()['statusCode']
        return res['message'], res['code']
    else:
        print(api_call.content, api_call.status_code)
        return api_call.content, api_call.status_code

def upgrade_api(phone_number, idbundle, idservice, referrer=None, idchannel=2, vault=None):  # default channel id is web
    print("Subscribing", phone_number, "to", idbundle, "service", idservice)
    command = '/api/User/Upgrade'
    uniqueid = str(uuid4())
    data = {'msisdn': phone_number, 
            'idChannel': idchannel,
            'idBundle':idbundle,
            'idService':idservice.upper(),
            'transactionId':uniqueid,
            }
    if referrer:
        print("Referrer by:", referrer)
        data['inviteeId'] = str(referrer)
    if vault:
        return vault.send(command=command, data=data)       
    url = API_SERVER_URL+command
    try: 
        print(data)
        api_call = requests.post(url, headers={}, json=data, timeout=3)
        print(api_call)
        print(api_call.content)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        # raise SystemExit(e)
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()['statusCode']
        return res['message'], res['code']
    else:
        print(api_call.content, api_call.status_code)
        return api_call.content, api_call.status_code
    
def write_cdr(phone_number,vault=None):
    command = '/api/User/InfoLog'
    data = {'msisdn': phone_number, 
            'type': 'secured',
            'idservice':'P50',
            'responsecode':0,
            'description':'Success',
            }
    
    if vault:
        return vault.send(command=command, data=data)       
    url = API_SERVER_URL+command
    try: 
        api_call = requests.post(url, headers={}, json=data, timeout=3)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        # raise SystemExit(e)
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()['statusCode']
        return res['message'], res['code']
    else:
        return api_call.content, api_call.status_code

def grant_referral_gift(user, referrer):
    print("User", user, "being referred by", referrer, "instead of", user.referrer)
    refgift = 50
    if not user.referrer:
        user.referrer = referrer
        user.save()
        transaction = UserTransactionHistory.objects.create(
            user=referrer,
            amount=refgift, # amount of coins to grant
            action=CoinTransaction.REFER,
            info=Transaction.REFER
        )
        # if transaction.actual_amount == 0:  # handle here if want to add limit to referrals
        #     raise CoinLimitReached()
        # else:
        #     return Response({'coins': new_coins})
        print("Transaction succeeded", transaction.actual_amount)
        # Send Notification of successful referral to referrer (can add refered too if needed)
        stri_repl = {}
        stri_repl['FRIEND'] = user.username
        stri_repl['FR_MOBILE'] = user.mobile
        stri_repl['AMOUNT'] = str(refgift)
        @notify_when(events=[NotificationTemplate.FRIEND_REFER],
                         is_route=False, is_one_time=False, str_repl=stri_repl)
        def notify(user, user_notifications):
            """ extra logic if needed """
        notify(user=referrer)
    # if 'refid' in request.session:
    #     referrer = request.session['refid']
        ## TODO: give coins here - add as referrer permanently if needed ?? - send notification of successful referral


def do_register(self, request, username, subscription):
    print("inside do_register")
    is_active = False
    is_billed = False
    if 'refid' in request.session:
        print('referral id found in cookie', request.session['refid'])
        ref = User.objects.filter(id=request.session['refid']).first()
        if ref:
            referrer = ref.uid
        else:
            referrer = None
    else:
        referrer=None
    if subscription == SubscriptionPlan.FREE:
        idbundle = 1
        idservice = SubscriptionPackages.FREE
    elif subscription == SubscriptionPlan.PAID1:
        idbundle = 2
        idservice = SubscriptionPackages.PAID1
        is_billed = True
    elif subscription == SubscriptionPlan.PAID2:
        idbundle = 3
        idservice = SubscriptionPackages.PAID2
        is_billed = True
    else:
        print("unknown subscription", subscription)
        return Response({'error': 'Unknown Subscription'}, status=577)

    print("self",self)
    if self:
        response2, code2 = load_data_api(username, "1", self.client)  # 1 for wifi
        print("self response",code2)
    else:
        response2, code2 = load_data_api(username, "1")  # 1 for wifi
        print("else response",code2)

    if code2==76 or code2==77 or code2==79 or code2==75:  # here we set subscription to idbundle since user already has subscribed somehow using another mean
        if response2['idbundle'] == 1:
            subscription = SubscriptionPlan.FREE
        elif response2['idbundle'] == 2:
            subscription = SubscriptionPlan.PAID1
            is_billed = True
        elif response2['idbundle'] == 3:
            subscription = SubscriptionPlan.PAID2
            is_billed = True
    if code2==56 or code2==80 or code2==76 or code2==77 or code2==79 or code2==75 or INTEGRATION_DISABLED or username.startswith('234102'):  # 56 profile does not exist - 76 pending sub - 79 pending unsub - 77 sub - 75 under process
        if code2==56 or code2==80:  # profile does not exist so we send subscription request
            print("subscription request", subscription)
            print("self",self)
            if self:
                response3, code3 = subscribe_api(username, idbundle, idservice, referrer=referrer, vault=self.client)
                print("self response",response3)
            else:
                response3, code3 = subscribe_api(username, idbundle, idservice, referrer=referrer, vault=None)
                print("else response",response3)
                
        if code2==76 or code2==77 or code2==75 or code2==79 or (code2==56 and code3 ==0) or (code2==80 and code3 ==0) or INTEGRATION_DISABLED or username.startswith('234102'): # profile does exist so we create local record based on it
            # request.session.pop('renewing', None)
            if code2==77 or INTEGRATION_DISABLED or username.startswith('234102'):
                is_active=True
            
            avatar = Avatar.objects.order_by('?').first()
            user, created =  User.objects.get_or_create(
                    mobile = username,
                    defaults={
                        'is_superuser': False,
                        'first_name': '',
                        'last_name': '',
                        'email': '',
                        'is_active': is_active,
                        'is_staff': False,
                        'subscription': subscription,
                        'date_joined': datetime.now(),
                        'modified' : datetime.now(),
                        'newsletter_subscription': True,
                        'timezone': '',
                        'country': request.region.code,
                        'region_id': request.region.id,
                        'is_billed' : is_billed,
                        'password': 'pbkdf2_sha256$260000$aMwTW2Wr3K2J2WmodFFd5W$pZUAfNohO77wQbo4oRgMYybD8Vph9HdUSoeWOHkwT9w='
                    },
                )
            if created:
                user.username= _('player'+str(user.id))
                user.nickname= _('player'+str(user.id))
                
                if avatar :
                    user.avatar = avatar
                user.save()
            if is_active:
                if 'refid' in request.session:
                    referr = User.objects.filter(id=request.session['refid']).first()
                    if referr:
                        grant_referral_gift(user, referr)

                @notify_when(events=[NotificationTemplate.LOGIN],
                            is_route=False, is_one_time=False)
                def notify(user, user_notifications):
                    """ extra logic if needed """
                notify(user=user)
            
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            request.session['user_id'] = user.pk
            print('request.session user_id',user.pk)
            if request.user.is_authenticated:
                LastSeenMiddleware.update_last_seen(request.user)
                #@notify_when(events=[NotificationTemplate.DAILY],
                #            is_route=False, is_one_time=False)
                #def notify(user, user_notifications):
            request.session.save()
                #notify(user=user)
            return redirect('/home')
            # return Response({'message': response2}, status=514)
        
        elif code2==56:
            if code3<100:
                code3+=400
            return Response({'error': response3}, status=code3)
    else:
        if code2<100:
            code2+=400
        return Response({'error': response2}, status=code2)

class AuthViewSet(viewsets.GenericViewSet):
    serializer_class = None
    permission_classes = (permissions.AllowAny,)
    def __init__(self, **kwargs):
        super(AuthViewSet, self).__init__(**kwargs)
        if ENABLE_VAULT:
            self.client = EncryptedMessageSender()
        else:
            self.client = None

    @action(methods=['POST'], detail=False)
    def reload_data(self, request):
        
        username = request.data.get('msisdn')
        print("reloading data for",username)
        try:
            user = UserModel.objects.filter(
            mobile__iexact=username,
            region=request.region,
            is_superuser=False,
            is_staff=False
            ).first()
            if not user :
                return Response({'error': 'Invalid Number'}, status=472)
        except UserModel.DoesNotExist:
            return Response({'error': 'Invalid Number'}, status=472)
        mobile = username
        print("user", user.username)
        print("mobile", mobile)
        if mobile is not None:
            print("refreshing subscriber status for", mobile)
            response, code = load_data_api(str(mobile), '1', self.client)
            print(response, code)
            if code==77:
                request.session['subscribed']=response['idbundle']
                return Response({}, status=status.HTTP_200_OK)
            else:
                # if code==80:
                #     request.session['renewing']=True
                if code < 100:
                    code += 400
                return Response({'error': response}, status=code)
        else:  # do you want to login if none ? here we assume yes
            return Response({}, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False)
    def verify_mobile(self, request):
        username = request.data.get('phone_number')
        print("verifying", username)
        try:
            # user = UserModel.objects.get(
            #     username__iexact=username,
            #     region=request.region
            # )
            user = UserModel.objects.filter(
                username__iexact=username,
                region=request.region,
                is_superuser=False,
                is_staff=False
            ).first()
            if not user :
                user = UserModel.objects.filter(
                mobile__iexact=username,
                region=request.region,
                is_superuser=False,
                is_staff=False
                ).first()
                if not user :
                   #return Response({'error': 'Invalid Number'}, status=472)
                   mobile = username
        except UserModel.DoesNotExist:
            # return Response({'error': 'Invalid Number'}, status=472)
            mobile = username
        if user:
            mobile = user.mobile
        if mobile is not None:
            print("sending pincode to", mobile)
            response, code = send_pincode(str(mobile), vault=self.client)
            print(response, code)
            if code==70 or username in USER_EXCEPTION_LIST or INTEGRATION_DISABLED or str(mobile).startswith('234102'):
                return Response({}, status=status.HTTP_200_OK)
            else:
                if code < 100:
                    code += 400
                return Response({'error': response}, status=code)
        else:  # do you want to login if none ? here we assume yes
            return Response({}, status=status.HTTP_200_OK)
    
    @action(methods=['POST'], detail=False)
    def reg_verify_mobile(self, request):
        username = request.data.get('phone_number')
        # subscription = request.data.get('subscription')
      
        try:
            user = UserModel.objects.filter(
                username__iexact=username,
                region=request.region
            )
            if user and user.first().is_active:
                return Response({}, status=status.HTTP_306_RESERVED)
                
            user = UserModel.objects.filter(
                mobile__iexact=username,
                region=request.region
            )
            
            if user and user.first().is_active:
                return Response({}, status=status.HTTP_306_RESERVED)
        except UserModel.DoesNotExist:
            return Response({}, status=status.HTTP_200_OK)
        response, code = send_pincode(username, vault=self.client)
        print(response, code)
        if code==70 or INTEGRATION_DISABLED or username.startswith('234102') or DISABLE_PIN:
            return Response({}, status=status.HTTP_200_OK)
        else:
            if code < 100:
                code += 400
            return Response({'error': response}, status=code)


    @action(methods=['POST'], detail=False)
    def login(self, request):
        username = request.POST.get('mobile')
        # get real mobile if it is username
        try:
            user = UserModel.objects.filter(
                username__iexact=username,
                region=request.region
            ).first()
            if user:
                usermob = str(user.mobile)
            else:
                usermob = username
        except UserModel.DoesNotExist:
            usermob = username
        
        otp = request.POST.get('code')
        if usermob:
            response, code = verify_pincode(usermob, otp, vault=self.client)  # what if he is registered on api but not here and loaddata check if pendingsub
        if (usermob and code==0) or username in USER_EXCEPTION_LIST or INTEGRATION_DISABLED or usermob.startswith('234102') or DISABLE_PIN:
            response2, code2 = load_data_api(usermob, "1", self.client)  # 1 for wifi
            
            if code2==56 or code2==75 or code2==76 or code2==77 or code2==79 or username in USER_EXCEPTION_LIST or INTEGRATION_DISABLED or usermob.startswith('234102'):  # 56 profile does not exist - 76 pending sub - 77 pending unsub - 79 sub
                
                try:
                    user = UserModel.objects.filter(
                        username__iexact=username,
                        region=request.region,
                        is_superuser=False,
                        is_staff=False
                    ).first()
                    if not user :
                        user = UserModel.objects.filter(
                                mobile__iexact=username,
                                region=request.region,
                                is_superuser=False,
                                is_staff=False
                                ).first()
                        if not user :
                            # raise exceptions.ValidationError({'error':'Invalid Mobile Number'})  
                            ## TODO: do you want to subscribe the user automatically if not found ? uncomment  this part
                            # if code2==56:  # profile does not exist so we send subscription request
                            #     if user.subscription=='free':
                            #         idbundle = 1
                            #         idservice = 'FREE'
                            #     elif user.subscription=='paid1':
                            #         idbundle = 2
                            #         idservice = 'P30'
                            #     elif user.subscription=='paid2':
                            #         idbundle = 3
                            #         idservice = 'P50'
                            #     response3, code3 = subscribe_api(usermob, idbundle, idservice, vault=self.client)


                            # if the user has already sent a subscription via other means but does not have a profile registered on the website
                            if code2==76 or code2==77 or code2==79 or code2==75:  # here we set subscription to idbundle since user already has subscribed somehow using another mean
                                if response2['idbundle'] == 1:
                                    subscription = SubscriptionPlan.FREE
                                    is_billed = False
                                elif response2['idbundle'] == 2:
                                    subscription = SubscriptionPlan.PAID1
                                    is_billed = True
                                elif response2['idbundle'] == 3:
                                    subscription = SubscriptionPlan.PAID2
                                    is_billed = True
                                if not user:  # attempt to create a profile
                                    if code2==77:
                                        is_active=True
                                        
                                    else:
                                        is_active=False
                                    avatar = Avatar.objects.order_by('?').first()
                                    user, created =  User.objects.get_or_create(
                                            mobile = username,
                                            defaults={
                                                'is_superuser': False,
                                                'first_name': '',
                                                'last_name': '',
                                                'email': '',
                                                'is_active': is_active,
                                                'is_staff': False,
                                                'subscription': subscription,
                                                'date_joined': datetime.now(),
                                                'modified' : datetime.now(),
                                                'newsletter_subscription': True,
                                                'timezone': '',
                                                'country': request.region.code,
                                                'region_id': request.region.id,
                                                'is_billed' : is_billed,
                                                'password': 'pbkdf2_sha256$260000$aMwTW2Wr3K2J2WmodFFd5W$pZUAfNohO77wQbo4oRgMYybD8Vph9HdUSoeWOHkwT9w='
                                            },
                                        )
                                    if created:
                                        user.username= 'player'+str(user.id)
                                        user.nickname= 'player'+str(user.id)
                                        
                                        if avatar :
                                            user.avatar = avatar

                                        user.save()
                                    if is_active:
                                        if 'refid' in request.session:
                                            referr = User.objects.filter(id=request.session['refid']).first()
                                            grant_referral_gift(user, referr)

                                        @notify_when(events=[NotificationTemplate.LOGIN],
                                                    is_route=False, is_one_time=False)
                                        def notify(user, user_notifications):
                                            """ extra logic if needed """
                                        notify(user=user)
                                        
                                    request.session['msisdn'] = user.mobile
                                    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                                    request.session['user_id'] = user.pk
                                    # return redirect('/')
                                    return Response({'message': response2}, status=514)
                        else :
                            user = UserModel.objects.get(
                                mobile__iexact=username,
                                region=request.region,
                                is_superuser=False,
                                is_staff=False
                                )         
                    else :
                        user = UserModel.objects.get(
                            username__iexact=username,
                            region=request.region,
                            is_superuser=False,
                            is_staff=False
                            )
                except UserModel.DoesNotExist:
                    raise exceptions.ValidationError({'error':'Invalid Mobile Number'})
                if not user:
                    raise exceptions.ValidationError({'error':'Invalid Mobile Number'})
                if code2==76 or code2==79 or code2==75 or not user.is_active:
                    print("user", user, "is not active redirect to wait page")
                    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                    request.session['user_id'] = user.pk
                    request.session['msisdn'] = user.mobile
                    # return redirect('/wait')
                    return Response({'message': response2}, status=514)
                if user.is_active:
                    @notify_when(events=[NotificationTemplate.LOGIN],
                                is_route=False, is_one_time=False)
                    def notify(user, user_notifications):
                        """ extra logic if needed """
                    notify(user=user)

                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                request.session['msisdn'] = user.mobile
                return redirect('/home')
            else:
                if code2<100:
                    code2+=400
                return Response({'error': response2}, status=code2)
        else:
            if code<100:
                code+=400
            return Response({'error': response}, status=code)

    
    @action(methods=['POST'], detail=False)
    def register(self, request):
        
        username = request.POST.get('phone_number')
        subscription = request.POST.get('subscription')
        request.session['phone_number'] = username
        request.session['subscription'] = subscription
        otp = request.POST.get('code')
        response, code = verify_pincode(username, otp, vault=self.client)
        if code==0 or username in USER_EXCEPTION_LIST or INTEGRATION_DISABLED or username.startswith('234102') or DISABLE_PIN:
            return do_register(self, request, username, subscription)
        else:
            if code<100:
                code+=400
            return Response({'error': response}, status=code)

    @action(methods=['POST'], detail=False)
    def register2(self, request):
        
        username = request.session['msisdn']
        subscription = request.POST.get('subscription')
        request.session['phone_number'] = username
        request.session['subscription'] = subscription
        return do_register(self, request, username, subscription)
        

    @action(methods=['POST'], detail=False)
    def register3(self, request):
        
        if 'phone_number' in request.session and 'subscription' in request.session:
            username = request.session['phone_number']
            subscription = request.session['subscription']
            print("Calling Re-reg function")
        else:
            return redirect('/register')
        return do_register(self, request, username, subscription)   
        
        

class UserViewSet(mixins.ListModelMixin,
                  mixins.RetrieveModelMixin,
                  viewsets.GenericViewSet):
    queryset = UserModel.objects.all()
    serializer_class = serializers.UserSerializer
    permission_classes = (permissions.AllowAny,)
    lookup_field = 'uid'
    search_fields = ('nickname','mobile',)

    def get_queryset(self):
        user = self.request.user

        queryset = self.queryset.filter(region=self.request.region,is_staff=False)
        if self.action == 'send_coins':
            if user.is_authenticated:
                return queryset.exclude(id=user.id)
        return queryset.filter(region=self.request.region)

    def get_serializer_class(self):
        if self.action == 'send_coins':
            return serializers.SendCoinsSerializer
        elif self.action == 'last_played_games':
            return serializers.UserGamePlayedSerializer
        elif self.action == 'joined_tournaments':
            return TournamentSerializer
        elif self.action == 'upcoming_tournaments':
            return TournamentSerializer
        elif self.action == 'previous_tournaments':
            return TournamentSerializer
        elif self.action == 'trophies':
            return TrophySerializer
        elif self.action == 'stickers':
            return StickerSerializer
        elif self.action == 'profile':
            return EditProfileSerializer   
        elif self.action == 'friends':
            return serializers.FriendSerializer
        elif self.action == 'update_user_substatus':
            return serializers.UpdateSubscriptionSerializer
        elif self.action == 'remove_user_subscription':
            return serializers.RemoveSubscriptionSerializer
        elif self.action == 'disable_user_subscription':
            return serializers.DisableSubscriptionSerializer
        elif self.action == 'expiry_on_renewal':
            return serializers.ExpiryOnRenewalSerializer
        return serializers.UserSerializer

    @action(['POST'], detail=False, permission_classes=[permissions.IsAuthenticated])
    def unlock_battlepass_vip(self, request, uid):
        battlepass = BattlePass.objects.get_active().first()
        if not battlepass:
            raise exceptions.APIException('No active battle pass found')

        user_bp, created = UserBattlePass.objects.get_or_create(
            user=request.user,
            battlepass=battlepass,
            defaults={
                'is_vip': True,
                'vip_date': timezone.now()
            }
        )
        if not created and user_bp.is_vip:
            raise exceptions.ValidationError({"error":"User has already unlocked vip"})
        else:
            user_bp.is_vip = True
            user_bp.vip_date = timezone.now()
            user_bp.save()

        return Response()


    @swagger_auto_schema(responses={
        200: Schema(type=TYPE_OBJECT,
        properties={
           'message': Schema(
                type=TYPE_STRING, enum=['User subscription has been successfully updated!'],
                read_only=True,
                default='User subscription has been successfully updated!'
           ),
           'subscription': Schema(
                type=TYPE_STRING, enum=[SubscriptionPlan.FREE, SubscriptionPlan.PAID1, SubscriptionPlan.PAID2],
                read_only=True,
                default='free'
           ),
           'username': Schema(
                type=TYPE_STRING,
                read_only=True,
                default='player1'
           ),
           'refmsisdn': Schema(
                type=TYPE_STRING,
                read_only=True,
                default='2345685589245565'
           ),
        }), 
        403: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING, enum=['Request not Allowed!'], read_only=True, default='Request not Allowed!'
           )
        }), 
        400: Schema(type=TYPE_OBJECT,
        properties={
           'new_substatus': Schema(
              type=TYPE_STRING, read_only=True, default='The subscription plan provided is not valid!',
              enum=['The subscription plan provided is not valid!', 'User already has subscription paid1']
           ),
           'refid': Schema(
              type=TYPE_STRING, read_only=True, default='No referring user with the provided id was found!',
              enum=['No referring user with the provided id was found!']
           )
        }), 
        474: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING,
              enum=['Error in creating new user profile!'],
              read_only=True, default='Error in creating new user profile!'
           )
        }), 
        473: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING,
              enum=['Error in updating user subscription!'],
              read_only=True, default='Error in updating user subscription!'
           )
        })})
    @action(['POST'], detail=False)  # , permission_classes=[permissions.IsAuthenticated]
    def update_user_substatus(self, request): 
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        msisdn = serializer.validated_data['msisdn']
        resp = {}
        is_billed = False
        refexist = False
        try:
            refid = serializer.validated_data['refid']
        except:
            refid = None
        new_substatus = serializer.validated_data['new_substatus']
        if new_substatus.lower() == SubscriptionPackages.PAID1:
            subscription = SubscriptionPlan.PAID1
            is_billed = True
        elif new_substatus.lower() == SubscriptionPackages.PAID2:
            subscription = SubscriptionPlan.PAID2
            is_billed = True
        else:
            subscription = SubscriptionPlan.FREE
        
        print(request.META.get('HTTP_X_FORWARDED_FOR'))
        ip = ip_address(request.META.get('HTTP_X_FORWARDED_FOR').split(",")[0])
        if str(ip) != TRUSTED_IP: # not ip.is_private:
            raise exceptions.PermissionDenied('Request not Allowed!')
        userexist = User.objects.filter(mobile=msisdn)
        print("refid", refid)
        if subscription not in SubscriptionPlan.values:
            raise exceptions.ValidationError({'new_substatus':'The subscription plan provided is not valid!'})
        elif userexist and userexist.first().subscription==subscription:
            if subscription==SubscriptionPlan.PAID2 and userexist.first().is_billed==1:
                raise exceptions.ValidationError({'new_substatus': 'User already has subscription '+ new_substatus})
        
        else:
            if refid and refid != "" and refid != None:
                refexist = User.objects.filter(uid=refid)
                if not refexist:
                    raise exceptions.ValidationError({'refid':'No referring user with the provided uid was found!'})
            if not userexist:
                # a subscription is received from operator thus we can create a new profile instead of exception
                # raise exceptions.ValidationError({'msisdn':'No user with the provided phone number was found!'})
                avatar = Avatar.objects.order_by('?').first()
                user, created =  User.objects.get_or_create(
                        mobile = msisdn,
                        defaults={
                            'is_superuser': False,
                            'first_name': '',
                            'last_name': '',
                            'email': '',
                            'is_active': True,
                            'is_staff': False,
                            'subscription': subscription,
                            'date_joined': datetime.now(),
                            'modified' : datetime.now(),
                            'newsletter_subscription': True,
                            'timezone': '',
                            'country': request.region.code,
                            'region_id': request.region.id,
                            'is_billed' : is_billed,
                            'password': 'pbkdf2_sha256$260000$aMwTW2Wr3K2J2WmodFFd5W$pZUAfNohO77wQbo4oRgMYybD8Vph9HdUSoeWOHkwT9w='
                        },
                    )
                if created:
                    user.username= 'player'+str(user.id)
                    user.nickname= 'player'+str(user.id)
                    
                    if avatar :
                        user.avatar = avatar

                    user.save()
                    resp['message'] = 'Unexisting user profile has been created!'
                    resp['subscription'] = new_substatus
                    resp['username'] = user.username
                    if refexist:
                        resp['refuid'] = refexist.first().uid
                        grant_referral_gift(user, refexist.first())
                    return Response(resp, status=status.HTTP_200_OK)
                else:
                    # raise exceptions.APIException("Error in creating new user profile!")
                    return Response({'error': 'Error in creating new user profile!'}, status=474)
                
            else:
                num = userexist.update(subscription=subscription, is_billed=is_billed)
                #print ("init is_billed ",str(userexist.first().is_billed))
                #print ("init subscription ",str(userexist.first().subscription))
                #print ("init msisdn ",str(userexist.first().mobile))
                #print ("init modified ",str(userexist.first().modified))
                
                #print ("userexist.query ",str(userexist.query))
                num = userexist.update(subscription=str(subscription), is_billed=is_billed)
                
                
                #user.nickname = 'carol'
                #user.save()
                
                #print("after update",userexist.first().subscription)
                #print("after update",str(userexist.first().is_billed))
                #print("after update",str(userexist.first().modified))
                #print ("num. ",str(num))
                
                #query = 'UPDATE public.account_user SET subscription='+subscription+', is_billed=true where mobile = '+msisdn
                #print(str(query))
                #updated_obj = User.objects.raw(query, [User.mobile])
                
                #conn = psycopg2.connect(
                #database="engage", user='dba', password='Va5T5cyu8t2zQcd2', host='10.114.0.3', port= '5432'
                #)

                #Setting auto commit false
                #conn.autocommit = True

                #Creating a cursor object using the cursor() method
                #cursor = conn.cursor()

                #Fetching all the rows before the update
                #print("Contents of the Employee table: ")
                #sql = "UPDATE public.account_user SET subscription= 'paid2', is_billed=true where mobile = '2341020000001'"
                #sql = "UPDATE public.account_user SET username= 'antonio', nickname = 'antonio' where mobile = '2341020000001'"
                #cursor.execute(sql)
                #conn.commit()
                #result=cursor.fetchone()
                #umber_of_rows=result[0]
                #print("number_of_rows ",str(number_of_rows))
                #print("Table updated...... ")
                
                
                #sql1 = "select nickname from public.account_userrr where mobile = '2341020000001'"
                #cursor.execute(sql1)
                #conn.commit()
                #print(cursor.fetchall())
                
                #afteruserexist = User.objects.filter(mobile=msisdn)
                #print("afteruserexist subscription ",afteruserexist.first().subscription)
                #print("afteruserexist is_billed ",str(afteruserexist.first().is_billed))
                #print("afteruserexist modified ",str(afteruserexist.first().modified))
                #print("afteruserexist nickname ",str(afteruserexist.first().nickname))
                num = 1
                if num >0:
                    resp['message'] = 'User subscription has been successfully updated!'
                    resp['subscription'] = new_substatus
                    resp['username'] = userexist.first().username
                    if refexist:
                        resp['refuid'] = refexist.first().uid
                        grant_referral_gift(userexist.first(), refexist.first())
                    return Response(resp, status=status.HTTP_200_OK)
                else:
                    # raise exceptions.APIException("Error in updating user subscription!")
                    return Response({'error': 'Error in updating user subscription!'}, status=473)

        print("update_user_substatus is_authenticated",request.user.is_authenticated)
    @swagger_auto_schema(responses={
        200: Schema(type=TYPE_OBJECT,
        properties={
           'message': Schema(
                type=TYPE_STRING, enum=['User subscription has been successfully cancelled!'],
                read_only=True,
                default='User subscription has been successfully cancelled!'
           ),
           'username': Schema(
                type=TYPE_STRING,
                read_only=True,
                default='player1'
           ),
        }), 
        403: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING, enum=['Request not Allowed!'], read_only=True, default='Request not Allowed!'
           )
        }), 
        400: Schema(type=TYPE_OBJECT,
        properties={
           'msisdn': Schema(
              type=TYPE_STRING, read_only=True, default='No User exists with the number 25465849449949'
           )
        }), 
        474: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING,
              enum=['User\'s subscription is already cancelled!'],
              read_only=True, default='User\'s subscription is already cancelled!'
           )
        }), 
        475: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING,
              enum=['Error in cancelling user subscription!'],
              read_only=True, default='Error in cancelling user subscription!'
           )
        })})
    @action(['POST'], detail=False)  # , permission_classes=[permissions.IsAuthenticated]
    def remove_user_subscription(self, request): 
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        msisdn = serializer.validated_data['msisdn']
        resp = {}
                
        # print(request.META.get('HTTP_X_FORWARDED_FOR'))
        ip = ip_address(request.META.get('HTTP_X_FORWARDED_FOR').split(",")[0])
        print(ip, str(ip)!=TRUSTED_IP)
        if str(ip) != TRUSTED_IP: # not ip.is_private:
            raise exceptions.PermissionDenied('Request not Allowed!')
        userexist = User.objects.filter(mobile=msisdn)
        if not userexist:
            raise exceptions.ValidationError({'msisdn': 'No User exists with the number '+ msisdn})
        elif not userexist.first().is_active:
            return Response({'error': 'User\'s subscription is already cancelled!'}, status=474)
        else:
            num = userexist.update(is_billed=False, subscription='free')
            if num >0:
                resp['message'] = 'User subscription has been successfully cancelled!'
                resp['username'] = userexist.first().username
                return Response(resp, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Error in cancelling user subscription!'}, status=475)


    @swagger_auto_schema(responses={
        200: Schema(type=TYPE_OBJECT,
        properties={
           'message': Schema(
                type=TYPE_STRING, enum=['User subscription has been successfully disabled!'],
                read_only=True,
                default='User subscription has been successfully disabled!'
           ),
           'username': Schema(
                type=TYPE_STRING,
                read_only=True,
                default='player1'
           ),
        }), 
        403: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING, enum=['Request not Allowed!'], read_only=True, default='Request not Allowed!'
           )
        }), 
        400: Schema(type=TYPE_OBJECT,
        properties={
           'msisdn': Schema(
              type=TYPE_STRING, read_only=True, default='No User exists with the number 25465849449949'
           )
        }), 
        474: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING,
              enum=['User\'s subscription is already disabled!'],
              read_only=True, default='User\'s subscription is already disabled!'
           )
        }), 
        475: Schema(type=TYPE_OBJECT,
        properties={
           'error': Schema(
              type=TYPE_STRING,
              enum=['Error in disabling user subscription!'],
              read_only=True, default='Error in disabling user subscription!'
           )
        })})
    @action(['POST'], detail=False)  # , permission_classes=[permissions.IsAuthenticated]
    def disable_user_subscription(self, request): 
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        msisdn = serializer.validated_data['msisdn']
        resp = {}
        # print(request.META.get('HTTP_X_FORWARDED_FOR'))
        ip = ip_address(request.META.get('HTTP_X_FORWARDED_FOR').split(",")[0])
        print(ip, str(ip)!=TRUSTED_IP)
        if str(ip) != TRUSTED_IP: # not ip.is_private:
            raise exceptions.PermissionDenied('Request not Allowed!')
        userexist = User.objects.filter(mobile=msisdn)
        if not userexist:
            raise exceptions.ValidationError({'msisdn': 'No User exists with the number '+ msisdn})
        elif not userexist.first().is_billed:
            return Response({'error': 'User\'s subscription is already disabled!'}, status=474)
        else:
            num = userexist.update(is_billed=False,subscription='free')
            if num >0:
                resp['message'] = 'User subscription has been successfully disabled!'
                resp['username'] = userexist.first().username
                return Response(resp, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Error in disabling user subscription!'}, status=475)
    
    @action(['POST'], detail=False)  # , permission_classes=[permissions.IsAuthenticated]
    def expiry_on_renewal(self, request): 
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        msisdn = serializer.validated_data['msisdn']
        resp = {}
        # print(request.META.get('HTTP_X_FORWARDED_FOR'))
        ip = ip_address(request.META.get('HTTP_X_FORWARDED_FOR').split(",")[0])
        print(ip, str(ip)!=TRUSTED_IP)
        if str(ip) != TRUSTED_IP: # not ip.is_private:
            raise exceptions.PermissionDenied('Request not Allowed!')
        userexist = User.objects.filter(mobile=msisdn)
        if not userexist:
            raise exceptions.ValidationError({'msisdn': 'No User exists with the number '+ msisdn})
        elif not userexist.first().is_billed:
            return Response({'error': 'User\'s subscription is already disabled!'}, status=474)
        else:
            num = userexist.update(is_billed=False)
            if num >0:
                resp['message'] = 'User subscription has been successfully disabled!'
                resp['username'] = userexist.first().username
                return Response(resp, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Error in disabling user subscription!'}, status=475)
            

    @action(['GET'], detail=True)
    def friends(self, request, uid):
        queryset = self.get_queryset()

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        assert lookup_url_kwarg in self.kwargs, (
                'Expected view %s to be called with a URL keyword argument '
                'named "%s". Fix your URL conf, or set the `.lookup_field` '
                'attribute on the view correctly.' %
                (self.__class__.__name__, lookup_url_kwarg)
        )

        filter_kwargs = {self.lookup_field: self.kwargs[lookup_url_kwarg]}
        instance = get_object_or_404(queryset, **filter_kwargs)

        # May raise a permission denied
        self.check_object_permissions(self.request, instance)

        search = request.query_params.get('search')

        if search:
            queryset = instance.friends.filter(
                (~Q(friend=instance) & Q(friend__nickname__icontains=search)) |
                (~Q(user=instance) & Q(user__nickname__icontains=search))
            ).all()
        else:
            queryset = instance.friends.all()

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True, context={'request': request, 'user': instance})
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True, context={'request': request, 'user': instance})
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(['PUT'], detail=False, permission_classes=[permissions.IsAuthenticated])
    @transaction.atomic()
    def profile(self, request):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        is_complete_profile = user.is_complete_profile

        if serializer.validated_data.get('avatar'):
            user.avatar = serializer.validated_data['avatar']
        user.nickname = serializer.validated_data['name']
        user.email = serializer.validated_data['email']
        user.country = serializer.validated_data['country']
        user.save()

        user.profile.gender = serializer.validated_data['gender']
        if not user.profile.birthdate:
            user.profile.birthdate = serializer.validated_data['birthdate']
        user.profile.residency = serializer.validated_data['residency']
        user.profile.save()

        # if not is_complete_profile:
        #     @notify_when(events=[NotificationTemplate.COMPLETE_PROFILE],
        #                  is_route=False, is_one_time=True)
        #     def notify(user, user_notifications):
        #         """ extra logic if needed """
        #     notify(user=user)

        return Response(status=status.HTTP_200_OK)

    @action(['GET'], detail=True)
    def last_played_games(self, request, uid):
        instance = self.get_object()
        size = request.query_params.get('size')

        played_games = UserGamePlayed.objects.filter(
            user=instance,
            game__regions__in=[self.request.region]
        ).order_by('-last_played_at')
        if size:
            played_games = played_games[:int(size)]

        serializer = self.get_serializer(
            instance=played_games, many=True
        )

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(['GET'], detail=True)
    def joined_tournaments(self, request, uid):
        instance = self.get_object()
        size = request.query_params.get('size')

        tournaments = Tournament.objects.filter(
            tournamentparticipant__participant=instance,
            tournamentparticipant__is_waiting_list = False
        ).all()
        if size:
            tournaments = tournaments[:int(size)]

        serializer = self.get_serializer(instance=tournaments, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(['GET'], detail=True)
    def upcoming_tournaments(self, request, uid):
        instance = self.get_object()
        size = request.query_params.get('size')

        now = timezone.now()

        # tournaments = Tournament.objects.filter(
        #     tournamentparticipant__participant=instance,
        #     start_date__gt=now
        # ).all()
        tournaments = Tournament.objects.filter(
            tournamentparticipant__participant=instance,
            end_date__gt=now,
            tournamentparticipant__is_waiting_list = False
        ).all()
        if size:
            tournaments = tournaments[:int(size)]

        serializer = self.get_serializer(instance=tournaments, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(['GET'], detail=True)
    def previous_tournaments(self, request, uid):
        instance = self.get_object()
        size = request.query_params.get('size')

        now = timezone.now()
        tournaments = Tournament.objects.filter(
            tournamentparticipant__participant=instance,
            end_date__lte=now
        ).all()
        if size:
            tournaments = tournaments[:int(size)]
        serializer = self.get_serializer(instance=tournaments, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(['GET'], detail=True)
    def stickers(self, request, uid):
        size = request.query_params.get('size')
        instance = self.get_object()
        if size:
            query = instance.stickers.all()[:int(size)]
        else:
            query = instance.stickers.all()
        serializer = self.get_serializer(instance=query, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(['GET'], detail=True)
    def trophies(self, request, uid):
        size = request.query_params.get('size')
        instance = self.get_object()
        if size:
            query = instance.trophies.all()[:int(size)]
        else:
            query = instance.trophies.all()
        serializer = self.get_serializer(instance=query, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

    @action(['GET'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def sections_log(self, request, uid):
        user = request.user
        new_tournament = None
        new_game = None
        new_prize = None
        new_redeem = None
        new_winner = None
        tournament_exist = UserSectionLog.objects.filter(user=user,
                                                         section_name=SectionLog.TOURNAMENT).first() 
        if tournament_exist :
            new_tournament = Tournament.objects.filter(created__gt=tournament_exist.created,regions__in=[self.request.region]).first()                                                  
             
        game_exist = UserSectionLog.objects.filter(user=user,
                                                   section_name=SectionLog.GAME).first() 
        if game_exist :
            new_game = HTML5Game.objects.filter(created__gt=game_exist.created,regions__in=[self.request.region]).first()  

        prize_exist =  UserSectionLog.objects.filter(user=user,section_name=SectionLog.PRIZE).first()
        if prize_exist :
            new_prize = TournamentPrize.objects.select_related('tournament').exclude(image='').filter(
                                                                tournament__regions__in=[self.request.region],
                                                                created__gt=prize_exist.created).first() 
        
        redeem_exist =  UserSectionLog.objects.filter(user=user,section_name=SectionLog.REDEEM).first()
        if redeem_exist :
             new_redeem = RedeemPackage.objects.filter(operator__region=request.region,created__gt=redeem_exist.created).first()

        winners_exist = UserSectionLog.objects.filter(user=user,section_name=SectionLog.WINNERS).first()
        if winners_exist :
            new_winner = TournamentPrize.objects.filter(
                winner__isnull=False,
                tournament__regions__in=[request.region],
                created__gt=winners_exist.created
            ).values('winner').annotate(
                winner_name=F('winner__nickname'),
                win_count=Count('winner')
            ).values('winner_name').order_by('-win_count').first() 

        return Response({
            'newTournamentExist':(True if new_tournament or not tournament_exist else False),
            'newPriceExist':(True if new_prize or not prize_exist else False),
            'newGameExist':(True if new_game or not game_exist else False),
            'newRedeemExist':(True if new_redeem or not redeem_exist else False),
            'newWinnerExist':(True if new_winner or not winners_exist else False)}, status=status.HTTP_200_OK)

    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def update_log(self, request,uid):
        user = request.user
        section = request.data.get('section_name')

        user_section_log, created = UserSectionLog.objects.get_or_create(user=user,
                                    section_name=section)                            
        if not created :
            user_section_log.created = timezone.now()
            user_section_log.save()                                             
        return Response(status=status.HTTP_200_OK)
    

    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def check_userstatus(self, request,uid):
        redFlag  = False
        user = User.objects.get(uid=uid)
        return Response({'status':user.subscription},status=status.HTTP_200_OK)
      
    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def check_usercoin(self, request,uid):
        redFlag  = False
        new_user = User.objects.get(uid=uid)
        coins = new_user.coins
        old_coins = new_user.old_coins
        if new_user.seen_coins != True :
            new_user.seen_coins = True
            new_user.old_coins =  old_coins
            new_user.save()     
            redFlag = True                                        
        return Response({'redFlag':redFlag},status=status.HTTP_200_OK)
    
    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def remove_friend(self, request, uid):
        instance = self.get_object()

        try:
            friend = FriendList.objects.get(
                (Q(user=request.user) & Q(friend=instance)) |
                (Q(user=instance) & Q(friend=request.user))
            )
        except FriendList.DoesNotExist:
            raise exceptions.ValidationError({'error':'User is not on your friends list'})

        if request.user == friend.user:
            other = friend.friend
        else:
            other = friend.user

        friend.delete()

        # notify the other user when friend request removed
        @notify_when(
            events=[NotificationTemplate.FRIEND_REMOVE],
            is_route=False, is_one_time=False,
            extra={
                "nickname": request.user.nickname,
                "friend": other.nickname
            }
        )
        def notify(user, user_notifications):
            """ extra logic if needed """

        notify(request.user)

        return Response(status=status.HTTP_200_OK)

    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def upgrade_subscription(self, request, uid):
        user = request.user
        idservice = SubscriptionPackages.PAID2

        is_sub = SubConfiguration.objects.filter(subThroughUssd=True).values_list('subThroughUssd', flat=True)
        
        if is_sub:
            upgrade_api(request.user.mobile, 3, SubscriptionPackages.PAID2, referrer=None, vault=None)
            return Response(status=status.HTTP_200_OK)
        else:
            write_cdr(request.user.mobile,vault=None)
            return Response({'is_sub' : 'false'},status=status.HTTP_200_OK)
       

    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def update_joined_tournaments(self, request, uid):
        print('-----update_joined_tournaments')
        user = User.objects.filter(
                uid=uid
            ).first()
        if user:
            user.tournament_joined_today = True
            user.save()
        return Response(status=status.HTTP_200_OK)

        

    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def add_new_friend(self, request, uid):
        instance = self.get_object()

        if request.user == instance:
            raise exceptions.ValidationError('Users cannot be friends with themselves')

        try:
            obj = FriendList.objects.get(
                (Q(user=request.user) & Q(friend=instance)) |
                (Q(user=instance) & Q(friend=request.user))
            )
        except FriendList.DoesNotExist:
            FriendList.objects.create(
                user=request.user,
                friend=instance,
                status=FriendStatus.PENDING
            )
            return Response(status=status.HTTP_200_OK)

        raise exceptions.ValidationError('User is already on your friends list')

    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    @transaction.atomic()
    def send_coins(self, request, uid):
        instance = self.get_object()

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        SendCoinsHistory.objects.create(
            user=request.user,
            receiver=instance,
            amount=serializer.validated_data['amount']
        )

        return Response(status=status.HTTP_200_OK)

    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def set_favorite(self, request, uid):
        instance = self.get_object()

        favorite_friend, created = UserFavoriteFriend.objects.get_or_create(
            user=request.user,
            friend=instance
        )

        if not created:
            is_favorite = False
            favorite_friend.delete()
        else:
            is_favorite = True

        return Response({'is_favorite': is_favorite}, status=status.HTTP_200_OK)
    
    @action(['POST'], detail=False, permission_classes=[permissions.IsAuthenticated])
    def get_ad_reward(self, request):
        user = request.user
        ad_type = request.data.get('reward_type')
        ad_id = request.data.get('adid')
        now_date = timezone.now().date()
        if 'ad_date' in request.session:
            print("request.session['ad_date']", request.session['ad_date'], "now_date", now_date, "inequality", now_date!=request.session['ad_date'])
            if now_date!=datetime.strptime(request.session['ad_date'], "%d/%m/%Y").date():
                request.session.pop('ad_date', None)
                if 'ad_id' in request.session:
                    request.session.pop('ad_id', None)
                request.session.modified = True
        if ad_id in OWN_CREATIVES:
            raise SelfAd()
        if 'ad_id' in request.session and ad_type=="click":
            if ad_id == request.session['ad_id']:
                raise AdAlreadyClicked()
        else:
            request.session['ad_id'] = ad_id
            request.session['ad_date'] = now_date.strftime('%d/%m/%Y')
            request.session.modified = True
            print("request.session['ad_date']", request.session['ad_date'])

        print("User", user, "ad type", ad_type, "ad id", ad_id)
        if ad_type=="click":
            transaction = UserTransactionHistory.objects.create(
                user=user,
                amount=50, # amount of coins to grant
                action=CoinTransaction.AD_CLICK,
                info=Transaction.AD_CLICK
            )
            print("Transaction succeeded", transaction.actual_amount)
            if transaction.actual_amount == 0:  # handle here if want to add limit to referrals
                raise AdLimitReached()
            else:
                return Response({'coins': 50})
            
        elif ad_type=="view":
            transaction = UserTransactionHistory.objects.create(
                user=user,
                amount=5, # amount of coins to grant
                action=CoinTransaction.AD_VIEW,
                info=Transaction.AD_VIEW
            )
            print("Transaction succeeded", transaction.actual_amount)
            if transaction.actual_amount == 0:  # handle here if want to add limit to referrals
                raise AdLimitReached()
            else:
                return Response({'coins': 5})

        #handle engage ads, call google api to reward engage videos
        elif ad_type != 'engage' and ad_type=="engage":
            transaction = UserTransactionHistory.objects.create(
                user=user,
                amount=0, # amount of coins to grant
                action=CoinTransaction.ENGAGE_VIEW,
                info=Transaction.ENGAGE_VIEW
            )
            print("Transaction succeeded", transaction.actual_amount)
           
            return Response({'coins': 0})

        else:
            raise exceptions.ValidationError({'error':'Invalid arguments'})
            
    @action(['POST'], detail=True, permission_classes=[permissions.IsAuthenticated])
    def update_go_premium_flag(self, request, uid):
        if 'msisdn' in request.session:
            user = User.objects.filter(
                mobile=request.session['msisdn']
            ).first()
            if user:
                user.go_premium_sent = True
                user.save()
        else:
            user = User.objects.filter(
                uid=uid
            ).first()
            if user:
                user.go_premium_sent = True
                user.save()

        

        return Response(status=status.HTTP_200_OK)



class FriendViewSet(mixins.ListModelMixin,
                    viewsets.GenericViewSet):
    queryset = FriendList.objects.all()
    serializer_class = serializers.FriendSerializer
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request, *args, **kwargs):
        user = self.request.user
        search = self.request.query_params.get('search')
        if search:
            queryset = user.friends.filter(
                (~Q(friend=user) & Q(friend__nickname__icontains=search)) |
                (~Q(user=user) & Q(user__nickname__icontains=search)),
            ).order_by('friend__username')
        else:
            
            queryset = user.friends.order_by('friend__username')

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def get_serializer_context(self):
        if self.action == 'list':
            return {
                'user': self.request.user,
                **super().get_serializer_context()
            }
        return super().get_serializer_context()

    @action(['POST'], detail=False)
    def accept_friend_request(self, request):
        friend_uid = request.POST.get('friend', None)

        try:
            friend = UserModel.objects.filter(
                uid=friend_uid,
                region=request.region
            ).first()
        except UserModel.DoesNotExist:
            raise exceptions.ValidationError({'error':'User not found'})

        get_friend = FriendList.objects.filter(
            user=friend,
            friend=request.user,
            status=FriendStatus.PENDING
        ).first()

        if get_friend:
            get_friend.status = FriendStatus.ACCEPTED
            get_friend.save()

            get_notification = UserNotification.objects.filter(
                friend_uid=friend_uid,
                user=request.user
            ).first()

            if get_notification: get_notification.delete()

        return Response(status=status.HTTP_200_OK)

    @action(['POST'], detail=False)
    def reject_friend_request(self, request):
        friend_uid = request.POST.get('friend', None)

        try:
            friend = UserModel.objects.filter(
                uid=friend_uid,
                region=request.region
            ).first()
        except UserModel.DoesNotExist:
            raise exceptions.ValidationError({'error':'User not found'})

        get_friend = FriendList.objects.filter(
            user=friend,
            friend=request.user,
            status=FriendStatus.PENDING
        ).first()

        if get_friend:
            get_friend.delete()

            get_notification = UserNotification.objects.filter(
                friend_uid=friend_uid,
                
            ).first()

            if get_notification: get_notification.delete()

        return Response(status=status.HTTP_200_OK)


class FCMViewSet(mixins.ListModelMixin, viewsets.GenericViewSet, PaginationMixin):
    queryset = None
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        if self.action == 'list':
            user = self.request.user
            return UserNotification.objects.filter(user=user).all()

    def get_serializer_class(self):
        return serializers.UserNotificationSerializer

    @action(detail=False, methods=['post'])
    def set_web_token(self, request):
        user = request.user
        fcm_token = request.data.get('fcm_token', '')

        user.web_fcm_token = fcm_token
        user.save()

        return Response({'status': 'success'}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def get_new_notifications(self, request):
       recent_notifications = UserNotification.objects.select_related(
           'notification'
       ).filter(
           user=request.user,
           last_read__isnull=True
       ).all().order_by('-created')
       serializer = self.get_serializer(recent_notifications, many=True)
       return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def get_new_early_notifications(self, request):
        recent_notifications = UserNotification.objects.select_related(
            'notification'
        ).filter(
            user=request.user
        ).all().order_by('-created')
        serializer = self.get_serializer(recent_notifications, many=True)
        return Response(serializer.data)
    
    
    @action(detail=False, methods=['get'])
    def get_user_notifications(self, request):
        recent_notification = UserNotification.objects.select_related(
            'notification'
        ).filter(
            user=request.user,
            last_read__isnull=True,
            notification__title=self.request.query_params.get('title'),
            notification__text=self.request.query_params.get('body'),

        ).all().order_by('-created').first()
        if recent_notification : 
            package_ids = [x.id for x in recent_notification.notification.package.all()] 
        else :
            package_ids = []    
        user=request.user
        serializer = self.get_serializer(recent_notification)
        return Response({"data":serializer.data,"subscription":user.subscription,'package_ids':package_ids})


    @action(detail=False, methods=['get'])
    def get_early_notifications(self, request):
        recent_notifications = UserNotification.objects.select_related(
            'notification'
        ).filter(
            user=request.user, last_read__isnull=False
        ).all().order_by('-created')

        page_number = self.request.query_params.get('page', 1)
        page_size = self.request.query_params.get('size', 10)

        paginator = Paginator(recent_notifications, page_size)

        try:
            notifications = paginator.page(int(page_number))
        except:
            notifications = paginator.page(1)

        serializer = self.get_serializer(notifications, many=True)

        return Response({
            "data": serializer.data,
            "pagination": {
                "has_next": notifications.has_next()
            }
        })

    @action(detail=False, methods=['post'])
    def set_notification_status(self, request):
        notification_id = request.POST.get('id', None)

        try:
            notification = UserNotification.objects.get(
                user=request.user,
                id=notification_id
            )
        except UserNotification.DoesNotExist:
            return Response({'status': 'fail'}, status=status.HTTP_304_NOT_MODIFIED)

        notification.last_read = timezone.now()
        notification.save()

        return Response({'status': 'success'}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['post'])
    def read_all_notifications(self, request):
        # notification_id = request.POST.get('id', None)
        total_claimed = 0
        try:
            notification1 = UserNotification.objects.filter(
                user=request.user,
                last_read__isnull=True
            )
        except UserNotification.DoesNotExist:
            return Response({'status': 'fail'}, status=status.HTTP_304_NOT_MODIFIED)
        #check if there are coins to claim
        # gifts = notification1.filter(is_gift=True)
        for notification_id in notification1:
            try:
                notification = Notifications.objects.get(id=notification_id.notification.id,
                                                        is_gift=True)
            except Notifications.DoesNotExist:
                notification = False
                # return Response({'status': 'fail'},
                #                 status=status.HTTP_304_NOT_MODIFIED)

            if notification and notification.video:
                now = datetime.now(tz=timezone.utc)

                today_battlepass = BattlePassMission.objects.filter(
                    date__year=now.year,
                    date__month=now.month,
                    date__day=now.day,
                    mission__action__in=[WinAction.WATCH_VIDEO, WinAction.WATCH_2_VIDEOS]
                ).first()

                if today_battlepass:
                    if today_battlepass.mission.action == WinAction.WATCH_VIDEO:
                        obj, created = UserBattlePassMission.objects.select_related(
                            'user',
                            'bp_mission',
                            'bp_mission__mission'
                        ).get_or_create(
                            bp_mission=today_battlepass,
                            user=request.user,
                            is_completed=True
                        )
                    else:
                        obj, created = UserBattlePassMission.objects.select_related(
                            'user',
                            'bp_mission',
                            'bp_mission__mission'
                        ).get_or_create(
                            bp_mission=today_battlepass,
                            user=request.user,
                        )

                        obj.count += 1

                        if not created:
                            obj.is_completed = True

                        obj.save()

            # try:
            #     user_notification = UserNotification.objects.get(
            #         user=request.user,
            #         notification=notification_id,
            #         is_claimed=False
            #     )
            # except UserNotification.DoesNotExist:
            #     return Response({'status': 'fail'},
            #                     status=status.HTTP_304_NOT_MODIFIED)
            user_notification = notification_id
            if user_notification.notification.is_gift and user_notification.is_claimed == False:
                user_notification.is_claimed = True
                user_notification.save()

                UserTransactionHistory.objects.create(
                    user=request.user,
                    amount=user_notification.notification.gifted_coins,
                    info = Transaction.NOTIFICATION_CLAIM+' '+ user_notification.notification.title
                )
                total_claimed += user_notification.notification.gifted_coins
            # return Response({'status': 'success','coins':request.user.coins}, status=status.HTTP_200_OK)
                
        notification1.update(last_read = timezone.now())
        # notification1.save()
        return Response({'status': 'success','coins':request.user.coins, 'total_claimed':total_claimed}, status=status.HTTP_200_OK)
        # return Response({'status': 'success'}, status=status.HTTP_200_OK)



        
    @action(detail=False, methods=['post'])
    def claim_gift(self, request):
        notification_id = request.POST.get('id', None)

        try:
            notification = Notifications.objects.get(id=notification_id,
                                                     is_gift=True)
        except Notifications.DoesNotExist:
            return Response({'status': 'fail'},
                            status=status.HTTP_304_NOT_MODIFIED)

        if notification.video:
            now = datetime.now(tz=timezone.utc)

            today_battlepass = BattlePassMission.objects.filter(
                date__year=now.year,
                date__month=now.month,
                date__day=now.day,
                mission__action__in=[WinAction.WATCH_VIDEO, WinAction.WATCH_2_VIDEOS]
            ).first()

            if today_battlepass:
                if today_battlepass.mission.action == WinAction.WATCH_VIDEO:
                    obj, created = UserBattlePassMission.objects.select_related(
                        'user',
                        'bp_mission',
                        'bp_mission__mission'
                    ).get_or_create(
                        bp_mission=today_battlepass,
                        user=request.user,
                        is_completed=True
                    )
                else:
                    obj, created = UserBattlePassMission.objects.select_related(
                        'user',
                        'bp_mission',
                        'bp_mission__mission'
                    ).get_or_create(
                        bp_mission=today_battlepass,
                        user=request.user,
                    )

                    obj.count += 1

                    if not created:
                        obj.is_completed = True

                    obj.save()

        try:
            user_notification = UserNotification.objects.get(
                user=request.user,
                notification=notification_id,
                is_claimed=False
            )
        except UserNotification.DoesNotExist:
            return Response({'status': 'fail'},
                            status=status.HTTP_304_NOT_MODIFIED)

        if user_notification.notification.is_gift:
            user_notification.is_claimed = True
            user_notification.save()

            UserTransactionHistory.objects.create(
                user=request.user,
                amount=user_notification.notification.gifted_coins,
                info = Transaction.NOTIFICATION_CLAIM+' '+ user_notification.notification.title
            )
        return Response({'status': 'success','coins':request.user.coins}, status=status.HTTP_200_OK)


    @action(detail=False, methods=['get'])
    def get_my_coins(self, request):
        return Response({
            'data': {
                'coins': request.user.coins
            },
            'status': 'success'
        }, status=status.HTTP_200_OK)
