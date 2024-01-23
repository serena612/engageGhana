# coding; utf-8

from datetime import datetime
from gettext import NullTranslations
from turtle import position
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db.models.signals import post_save, post_delete, m2m_changed,pre_save
from django.dispatch import receiver
from django.db.models import  Q
from django_celery_beat.models import CrontabSchedule, PeriodicTask
import re
from engage.account.models import UserBattlePassMission
from engage.core.constants import NotificationTemplate, WinAction
from engage.core.models import BattlePassMission
from engage.services import notify_when
from engage.account.models import User
from engage.tournament.models import (
    TournamentMatch,
    TournamentParticipant,
    TournamentInvitation,
    TournamentPrize,
    Tournament
)
from ..core.models import Sticker
from django.utils.translation import gettext_lazy as _
from engage.account.constants import SubscriptionPackages, SubscriptionPlan
from uuid import uuid4
from engage.settings.base import API_SERVER_URL
import requests
from datetime import datetime, timedelta

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


@receiver(post_save, sender=TournamentMatch)
def post_match_save(sender, instance, created, **kwargs):
    now = datetime.now(tz=timezone.utc)
    if instance.winners or instance.start_date  < now:
        return
    
    schedule, _ = CrontabSchedule.objects.get_or_create(
        minute=1,
        hour='*',
        day_of_week='*',
        day_of_month='*',
        month_of_year='*',
    )
    started_date = instance.start_date -  timedelta(minutes=instance.inform_participants)

    #Delete task
    exist = PeriodicTask.objects.filter(name=f'Send Notification Before Match {instance.id}')
    if exist:
        exist.update(enabled=False)
        exist.delete()
    
    # PeriodicTask.objects.create(
    #     crontab=schedule,
    #     name=f'Send Notification Before Match {instance.id}',
    #     task='engage.tournament.tasks.fetch_match_details',
    #     args=f'[{instance.id}]',
    #     start_time=started_date
    # )

@receiver(m2m_changed, sender=TournamentMatch.winners.through)
def winners_changed(sender, instance, **kwargs):   
    # print("Winners Changed signal !!")
    # # print("instance", instance.__dict__)
    # print("kwargs", kwargs)
    # print("action", kwargs['action'])
    print("instance.tournament.rounds_number",instance.tournament.rounds_number,"instance.round_number",instance.round_number)
    if kwargs['action'] == 'post_add' and instance.tournament.rounds_number!=instance.round_number:
        new_winners_pk = kwargs['pk_set']
        # print("winners added:", new_winners_pk)
        # print("tournament", instance.tournament)
        print("instance", instance)
        stri_repl = {}
        if instance.start_date:
            if instance.tournament.time_compared_to_gmt:
                stri_repl['STARTDATE'] = (instance.start_date+timedelta(hours=int(instance.tournament.time_compared_to_gmt))).strftime("%H:%M")
            else:
                stri_repl['STARTDATE'] = instance.start_date.strftime("%H:%M")
            if instance.tournament.label_next_time:
                stri_repl['STARTDATE'] = stri_repl['STARTDATE'] + " " + instance.tournament.label_next_time
        else:
            stri_repl['STARTDATE'] = ''
        stri_repl['MATCH_NAME'] = instance.match_name
        stri_repl['TOURNAMENT_NAME'] = instance.tournament.name
        stri_repl['NBR'] = str(instance.inform_participants)
        stri_repl['GAMENAME'] = instance.tournament.game.name
        stri_repl['MATCHID'] = str(instance.match_id) if instance.match_id else ''
        stri_repl['PASSWORD'] = instance.password if instance.password else ''
        for winner in new_winners_pk :
            winnerr = User.objects.get(pk=winner)
            @notify_when(events=[NotificationTemplate.WIN_MATCH_INFORMATIVE], is_route=False, is_one_time=False, str_repl=stri_repl, lnk_repl="/tournaments/"+str(instance.tournament.id))
            def notify(user,user_notifications):
                """ extra logic if needed """
                for notificationi in user_notifications:
                    if instance.start_date:
                        if instance.tournament.label_next_time and instance.tournament.time_compared_to_gmt:
                            date_time = (instance.start_date+timedelta(hours=int(instance.tournament.time_compared_to_gmt))).strftime("%H:%M") + " "+ instance.tournament.label_next_time
                        else:
                            date_time = instance.start_date.strftime("%H:%M")
                    else:
                        date_time = instance.start_date.strftime("%H:%M")
                    print(notificationi.text)
                    notificationi.text=notificationi.notification.text.replace('MATCH_NAME',instance.match_name) \
                        .replace('TOURNAMENT_NAME',instance.tournament.name).replace('NBR', str(instance.inform_participants)) \
                        .replace('GAMENAME',instance.tournament.game.name).replace('MATCHID',str(instance.match_id) \
                        if instance.match_id else '').replace('PASSWORD', instance.password if instance.password else '') \
                        .replace('STARTDATE', date_time if instance.start_date else '')
                    # print(notificationi.text)
                    notificationi.link = "/tournaments/"+str(instance.tournament.id)  
                    notificationi.save()
                    print(notificationi.text)
                    print(notificationi.link)
    
            
            notify(user=winnerr)

@receiver(post_delete, sender=TournamentMatch)
def post_match_save(sender, instance, **kwargs):
    pass

# @receiver(post_save, sender=Tournament)
# def post_match_save(sender, instance, created, **kwargs):
#     tournament_prizes = TournamentPrize.objects.filter(
#         tournament=instance
#     )

#     tournament_winners= tournament_prizes.values_list('winner', flat=True)
#     failed_participants_ids = TournamentParticipant.objects.filter(
#         tournament=instance,
#     ).exclude(participant__id__in=tournament_winners).values_list('participant', flat=True)
#     failed_participants = User.objects.filter(id__in=failed_participants_ids)

#     if  not created :
#         now = timezone.now()
#         print('HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH')
#         print('HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH')
#         print('HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH')
#         print(instance.tracker.has_changed('end_date'))
#         if instance.end_date < now and instance.started_on  and instance.tracker.has_changed('end_date'):
#             for prize in tournament_prizes :
#             # USER_FIRST_TOURNAMENT
#                 if prize.position == 1 :
#                     @notify_when(events=[NotificationTemplate.USER_FIRST_TOURNAMENT], is_route=False, is_one_time=False)
#                     def notify(user, user_notifications):
#                         """ extra logic if needed """
#                         for notificationi in user_notifications:
#                             notificationi.link=instance.name+";"+prize.title+";"+str(prize.image)
#                             notificationi.save()


#                     notify(prize.winner)

#             # USER_SECOND_THIRD_TOURNAMENT >> Users who are second, third or positions that win a prize.
#                 elif  prize.position >= 2 :
#                     print(prize.winner)
#                     @notify_when(events=[NotificationTemplate.USER_SECOND_THIRD_TOURNAMENT], is_route=False, is_one_time=False)
#                     def notify(user, user_notifications):
#                         """ extra logic if needed """
#                         for notificationi in user_notifications:
#                             notificationi.link=instance.name+";"+prize.title+";"+str(prize.image)
#                             notificationi.save()
#                     notify(prize.winner)

#             if failed_participants :
#                 for participant in  failed_participants :
#                     sticker = Sticker.objects.filter(
#                                 ~Q(id__in=participant.stickers.all())
#                             ).order_by('?').first()
#                     if instance.give_sticker:
#                         if sticker :
#                             participant.stickers.add(sticker)
#                             participant.save()
#                     if instance.coins_per_participant > 0 :
#                         if participant.stickers.all() :
#                             participant.coins = participant.coins + instance.coins_per_participant
#                             participant.save()            
                
#                     @notify_when(events=[NotificationTemplate.USER_OUTSIDE_THE_WINNING_POSITIONS], is_route=False, is_one_time=False)
#                     def notify(user, user_notifications):
#                         """ extra logic if needed """
#                         for notificationi in user_notifications:
#                             notificationi.link=("1" if instance.give_sticker else "0")+";"+(str(instance.coins_per_participant) if instance.coins_per_participant else "0")+";"+(str(sticker.image) if instance.give_sticker and sticker and sticker.image  else "-")
#                             notificationi.save()
#                             print(notificationi.link)

#                     notify(participant)



@receiver(post_save, sender=TournamentParticipant)
def post_match_save(sender, instance, created, **kwargs):
    now = datetime.now(tz=timezone.utc)
    
    tournament_count = TournamentParticipant.objects.filter(
        tournament=instance.tournament,
        prize__isnull=False
    ).count()

    if created:
        # user battle pass >>  WinAction (join_tournament)
        today_battlepass = BattlePassMission.objects.filter(
            date__year=now.year,
            date__month=now.month,
            date__day=now.day,
            mission__action=WinAction.JOIN_TOURNAMENT
        ).first()

        if today_battlepass:
            obj, created = UserBattlePassMission.objects.select_related(
                'user',
                'bp_mission',
                'bp_mission__mission'
            ).get_or_create(
                bp_mission=today_battlepass,
                user=instance.participant,
                is_completed=True
            )

            # if created >> send a notification for this user telling him that he has finished his battle pass mission for today

        if instance.prize:
           
            today_battlepass = BattlePassMission.objects.filter(
                date__year=now.year,
                date__month=now.month,
                date__day=now.day,
                mission__action=WinAction.WIN_TOURNAMENT
            ).first()

            if today_battlepass:
                obj, created = UserBattlePassMission.objects.select_related(
                    'user',
                    'bp_mission',
                    'bp_mission__mission'
                ).get_or_create(
                    bp_mission=today_battlepass,
                    user=instance.participant,
                    is_completed=True
                )

                # if created >> send a notification for this user telling him that he has finished his battle pass mission for today

        # USER_REGISTER_FOR_TOURNAMENT
        else:
            @notify_when(events=[NotificationTemplate.USER_REGISTER_FOR_TOURNAMENT], is_route=False, is_one_time=False)
            def notify(user, user_notifications):
                """ extra logic if needed """
                for notificationi in user_notifications:
                    notificationi.link = "/tournaments/"+str(instance.tournament.id)
                    notificationi.text = notificationi.notification.text.replace('tournament_name',instance.tournament.name)
                    notificationi.save()
                    #resp, code = send_sms(user, notificationi.text)
                    sms_text = "You have successfully registered to play tournament_name tournament. Practice your skills to win the big prize."
                    sms_text_replaced = sms_text.replace('tournament_name',instance.tournament.name) 
                    resp, code = send_sms(user,sms_text_replaced)
                    print(resp, code)
            notify(instance.participant)

        

    else:

        if instance.tracker.has_changed('prize'):
            # user battle pass >>  WinAction (win_tournament)
            if instance.prize:
                today_battlepass = BattlePassMission.objects.filter(
                    date__year=now.year,
                    date__month=now.month,
                    date__day=now.day,
                    mission__action=WinAction.WIN_TOURNAMENT
                ).first()

                if today_battlepass:
                    obj, created = UserBattlePassMission.objects.select_related(
                        'user',
                        'bp_mission',
                        'bp_mission__mission'
                    ).get_or_create(
                        bp_mission=today_battlepass,
                        user=instance.participant,
                        is_completed=True
                    )

                  

           
@receiver(post_save, sender=TournamentInvitation)
def tournament_invite_friend(sender, instance, created, **kwargs):
    if created:
        now = datetime.now(tz=timezone.utc)

        today_battlepass = BattlePassMission.objects.filter(
            date__year=now.year,
            date__month=now.month,
            date__day=now.day,
            mission__action=WinAction.INVITE_FRIEND
        ).first()

        if today_battlepass:
            obj, created = UserBattlePassMission.objects.select_related(
                'user',
                'bp_mission',
                'bp_mission__mission'
            ).get_or_create(
                bp_mission=today_battlepass,
                user=instance.participant,
                is_completed=True
            )


@receiver(post_delete, sender=TournamentParticipant)
def delete_participant_from_tournament(sender, instance, **kwargs):
    if instance.is_waiting_list:
        return

    first_waiting = TournamentParticipant.objects.filter(
        tournament=instance.tournament,
        is_waiting_list=True
    ).order_by('created').first()

    if first_waiting:
        first_waiting.is_waiting_list = False
        first_waiting.save()

#
# @receiver(m2m_changed, sender=TournamentMatch.winners.through)
# def tournament_match_winners(sender, ):
#     pass

# @receiver(m2m_changed, sender=TournamentMatch.winners.through)
# def tournament_match_winners(sender, **kwargs):
#     instance = kwargs.pop('instance', None)
#     if instance.winners.exists() and not instance.tournament.started_on:
#         raise ValidationError({
#             'winners': _('winners can\'t be selected without starting the tournament!')
#         })


      

