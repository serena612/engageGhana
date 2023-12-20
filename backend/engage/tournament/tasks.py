from pydoc import cli
import requests
from celery import shared_task
from django.conf import settings
from django.db.models import F, OuterRef, Subquery
from django.utils import timezone
from engage.services import notify_when
from engage.account.models import UserGameLinkedAccount, User
from engage.tournament.models import TournamentPrizeList
from engage.core.constants import SupportedGame
from engage.tournament.game.clash_royale import ClashRoyaleClient
from engage.core.constants import NotificationTemplate
from engage.settings.base import API_SERVER_URL, PRIZE_SERVER_URL
from uuid import uuid4
from django.db import transaction
from engage.tournament.models import (
    TournamentMatch
)
from engage.account.models import User
from datetime import datetime, timedelta
from engage.account.constants import SubscriptionPackages, SubscriptionPlan
from ..celery import block_multiple_celery_task_execution

def get_prize_list(vault=None):
    headers = {'Content-type':'application/json', 
                'accept': 'text/plain'} # post data
    command = '/api/Features/get_data_plan_details'
    
    if vault:
        return vault.send(command=command, headers=headers)
    url = PRIZE_SERVER_URL+command
    
    try:
        api_call = requests.get(url, timeout=2) # , headers=headers
    except requests.exceptions.RequestException as e:
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        # print(api_call)
        res = api_call.json()
        return res['plan_list'], res['code']
    else:
        return api_call.content, api_call.status_code


def send_sms(user, message, vault=None):
    headers = {'Content-type':'application/json', 
                'accept': 'text/plain'} # post data
    command = '/api/User/SendSms'
    if user.subscription==SubscriptionPlan.FREE:
        subs = SubscriptionPackages.FREE
    elif user.subscription==SubscriptionPlan.PAID1:
        subs = SubscriptionPackages.PAID1
    elif user.subscription==SubscriptionPlan.PAID2:
        subs = SubscriptionPackages.PAID2
    else:
        subs = SubscriptionPackages.PAID3
    data = {
            'msisdn': user.mobile,
            'message': message.replace('<br/>', ''),
            'message_id': str(uuid4()),
            'service_id': subs
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
        # print(api_call)
        res = api_call.json()['statusCode']
        return res['message'], res['code']
    else:
        return api_call.content, api_call.status_code

@shared_task(bind=True)
def check_active_matches_winners(self):
    prefix = "check_active_matches_winners"
    if block_multiple_celery_task_execution(self, prefix):
        return
    now = datetime.now(tz=timezone.utc)
    matches = TournamentMatch.objects.filter(
        start_date__gt=now,
        winners__isnull=True
    ).all()
    if len(matches) > 0 :
        for match in matches:
            fetch_match_details.delay(match.id)


@transaction.atomic
@shared_task(bind=True)
def fill_prize_list(self):
    prefix = "fill_prize_list"
    if block_multiple_celery_task_execution(self, prefix):
        return
    prize_list, code = get_prize_list()
    if code==0:
        packages = [package['DATA_PLAN'] for package in prize_list]
        items_by_pk = TournamentPrizeList.objects.in_bulk(packages)
        all_items_by_pk = TournamentPrizeList.objects.in_bulk()
        for package in prize_list:
            if package['DATA_PLAN'] in items_by_pk:
                item = items_by_pk[package['DATA_PLAN']]
                for key in package:
                    if key == 'DATAPLAN_DESC':
                        setattr(item, 'data_plan_desc', package[key])
                    else:
                        setattr(item, key.lower(), package[key])
                    setattr(item, 'prize_type', 'data')
                item.save()
            else:
                m = TournamentPrizeList(operator=package['OPERATOR'],
                    amount=package['AMOUNT'],
                    data_plan=package['DATA_PLAN'],
                    data_plan_desc=package['DATAPLAN_DESC'],
                    prize_type='data'
                    )
                m.save()
        # get all packages that have been removed and delete them
        items_to_delete = [k for k in all_items_by_pk if k not in items_by_pk]
        TournamentPrizeList.objects.filter(pk__in=items_to_delete).delete()
    else:
        print("An error has occured", code)

@shared_task(bind=True)
def fetch_match_details(self, match_id):
    prefix = "fetch_match_details_"+ str(match_id)
    # if block_multiple_celery_task_execution(self, prefix):
    #     return
    match = TournamentMatch.objects.get(
        id=match_id
    )
    now = datetime.now(tz=timezone.utc)
    started_date = (match.start_date  - now - timedelta(minutes=match.inform_participants))
    print(match.start_date, now, started_date.total_seconds())
    if int(started_date.total_seconds()) >=0  and  int(started_date.total_seconds()) < 30:
        participants = User.objects.filter(participanto=match)
        print("participants",participants)
        stri_repl = {}
        if match.start_date:
            if match.tournament.time_compared_to_gmt:               
                stri_repl['STARTDATE'] = (match.start_date+timedelta(hours=int(match.tournament.time_compared_to_gmt))).strftime("%H:%M")
            else:
                stri_repl['STARTDATE'] = match.start_date.strftime("%H:%M")
            if match.tournament.label_next_time:
                stri_repl['STARTDATE'] = stri_repl['STARTDATE'] + " " + match.tournament.label_next_time
        else:
            stri_repl['STARTDATE'] = ''
        stri_repl['MATCH_NAME'] = match.match_name
        stri_repl['TOURNAMENT_NAME'] = match.tournament.name
        stri_repl['NBR'] = str(match.inform_participants)
        stri_repl['GAMENAME'] = match.tournament.game.name
        stri_repl['MATCHID'] = str(match.match_id) if match.match_id else ''
        stri_repl['PASSWORD'] = match.password if match.password else ''

        
        # print(participants)
        if len(participants) > 0 :
            for participant in participants :
                
                @notify_when(events=[NotificationTemplate.BEFORE_MATCH_INFORMATIVE], is_route=False, is_one_time=False, str_repl=stri_repl, lnk_repl="/tournaments/"+str(match.tournament.id))
                def notify(user,user_notifications):
                    """ extra logic if needed """
                    
                    for notificationi in user_notifications:
                        if match.start_date:
                            if match.tournament.label_next_time and match.tournament.time_compared_to_gmt:
                                date_time = (match.start_date+timedelta(hours=int(match.tournament.time_compared_to_gmt))).strftime("%H:%M") + " "+ match.tournament.label_next_time
                            else:
                                date_time = match.start_date.strftime("%H:%M")
                        else:
                            date_time = ''
                        print(notificationi.text)
                        notificationi.text=notificationi.notification.text.replace('MATCH_NAME',match.match_name).replace('TOURNAMENT_NAME',match.tournament.name).replace('NBR', str(match.inform_participants)).replace('GAMENAME',match.tournament.game.name).replace('MATCHID',str(match.match_id) if match.match_id else '').replace('PASSWORD',match.password if match.password else '').replace('STARTDATE',date_time)
                        print(notificationi.text)
                        notificationi.link = "/tournaments/"+str(match.tournament.id)  
                        notificationi.save()
                        print(notificationi.text)
                        print(notificationi.link)
                        #resp, code = send_sms(user, notificationi.text)
                        sms_text = "Match Reminder !! The match MATCH_NAME in TOURNAMENT_NAME tournament will start in NBR minutes. Be prepared and join GAMENAME game with following details: Room: MATCHID, Pass: PASSWORD, Start time: STARTDATE time. Good Luck and don't be late!!"
                        sms_text_replaced = sms_text.replace('MATCH_NAME',match.match_name).replace('TOURNAMENT_NAME',match.tournament.name).replace('NBR', str(match.inform_participants)).replace('GAMENAME',match.tournament.game.name).replace('MATCHID',str(match.match_id) if match.match_id else '').replace('PASSWORD',match.password if match.password else '').replace('STARTDATE',date_time)
                        resp, code = send_sms(user,sms_text_replaced)
                        print(resp, code)
        
                
                notify(user=participant)



    
 

# @shared_task
# def fetch_match_details(match_id):
#     match = TournamentMatch.objects.select_related(
#         'tournament',
#         'tournament__game',
#         'tournament__game__gameapi'
#     ).get(
#         id=match_id
#     )

#     game = match.tournament.game.support_game

#     client = None
#     if game == SupportedGame.CLASH_ROYALE:
#         client = ClashRoyaleClient(
#             token=settings.GAME_CLIENTS_TOKENS[SupportedGame.CLASH_ROYALE]
#         )
#     else:
#         return

#     tournament = client.retrieve_tournament(match.match_id)
#     if client :
#         winners = client.fetch_winners(
#             tournament,
#             tournament.tournamentprize_set.all().count()
#         )
#         user_game_account = UserGameLinkedAccount.objects.filter(
#             user=OuterRef('participant')
#         )
#         participants = match.tournament.tournamentparticipant_set.annotate(
#             game_account=Subquery(user_game_account.values('account')[:1])
#         ).all()
#         match.winners = ''
#         for participant in participants:
#             if client.is_winner(winners, participant.game_account):
#                 match.winners += f'{participant.participant.nickname}\n'

#     match.match_data = tournament
#     match.save()
