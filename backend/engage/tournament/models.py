from ckeditor.fields import RichTextField
import datetime
from datetime import timedelta
from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from model_utils import FieldTracker
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from engage.account.models import PhonyNumberField
from common.models import TranslatableTimeStampedModel,TimeStampedModel
from parler.models import TranslatedFields
from .constants import (
    ParticipantStatus,
    BracketFormat,
    TournamentPrizeType
)
from engage.core.constants import (
     GameMode
)
from engage.account.constants import (
     SubscriptionPackages,
     SubscriptionPlan
)
from django.db.models import Count, F, Q, Prefetch
from .managers import TournamentQuerySet, TournamentTranslatableQuerySet
from django import forms
from engage.account.models import User
from engage.core.constants import NotificationTemplate
from engage.services import notify_when
from ..core.models import Sticker
import requests
from engage.settings.base import PRIZE_SERVER_URL


def request_data_prize(tournamentid,phone_number, dataplan, subscription, vault=None):  # default channel id is web
    print("Requesting for", phone_number, "dataplan:", dataplan)
    command = '/api/Features/request_data_prize'
    data = {'msisdn': phone_number, 
            'dataplan': dataplan,
            'package': subscription,
            'tournamentid':tournamentid
            }
    if vault:
        return vault.send(command=command, data=data)       
    url = PRIZE_SERVER_URL+command
    try: 
        api_call = requests.post(url, headers={}, json=data, timeout=3)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        # raise SystemExit(e)
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()
        return res['description'], res['code']
    else:
        return api_call.content, api_call.status_code


def request_cash_prize(tournamentid,phone_number, amount, subscription, vault=None):  # default channel id is web
    print("Requesting cash for", phone_number, "amount:", amount)
    command = '/api/Features/request_cash_prize'
    data = {'msisdn': phone_number, 
            'amount': str(amount),
            'package': subscription,
            'tournamentid':tournamentid
            }
    if vault:
        return vault.send(command=command, data=data)       
    url = PRIZE_SERVER_URL+command
    try: 
        api_call = requests.post(url, headers={}, json=data, timeout=3)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        # raise SystemExit(e)
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()
        return res['description'], res['code']
    else:
        return api_call.content, api_call.status_code

def request_airtime_prize(tournamentid,phone_number, amount, subscription, vault=None):  # default channel id is web
    print("Requesting airtime for", phone_number, "amount:", amount)
    command = '/api/Features/request_airtime_prize'
    data = {'msisdn': phone_number, 
            'amount': str(amount),
            'package': subscription,
            'tournamentid':tournamentid
            }
    if vault:
        return vault.send(command=command, data=data)       
    url = PRIZE_SERVER_URL+command
    try: 
        api_call = requests.post(url, headers={}, json=data, timeout=3)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        # raise SystemExit(e)
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()
        return res['description'], res['code']
    else:
        return api_call.content, api_call.status_code
    
def check_pending_requests_data(phone_number, vault=None):  # default channel id is web
    print("Checking pending requests", phone_number)
    command = '/api/Features/check_pending_specific_requests'
    data = {'msisdn': phone_number}
    if vault:
        return vault.send(command=command, data=data)       
    url = PRIZE_SERVER_URL+command
    try: 
        api_call = requests.post(url, headers={}, json=data, timeout=3)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        # raise SystemExit(e)
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()
        return res['prize_list'], res['code']
    else:
        return api_call.content, api_call.status_code


def confirm_request_data(phone_number, idbundle, vault=None):  # default channel id is web
    print("Confirming data prize request", phone_number, "id:", idbundle)
    command = '/api/Features/confirm_request'
    data = {'msisdn': phone_number, 
            'id':idbundle,
            }
    if vault:
        return vault.send(command=command, data=data)       
    url = PRIZE_SERVER_URL+command
    try: 
        api_call = requests.post(url, headers={}, json=data, timeout=3)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        # raise SystemExit(e)
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        print(api_call.json())
        res = api_call.json()
        return res['description'], res['code']
    else:
        return api_call.content, api_call.status_code

def get_prize(phone_number, dataplan, prize_type, subscription,tournamentid):
    print("Attempting to grant", prize_type, dataplan, "to", phone_number)
    if subscription == SubscriptionPlan.FREE:
        subs = SubscriptionPackages.FREE
    elif subscription == SubscriptionPlan.PAID1:
        subs = SubscriptionPackages.PAID1
    elif subscription == SubscriptionPlan.PAID2:
        subs = SubscriptionPackages.PAID2
    elif subscription == SubscriptionPlan.PAID3:
        subs = SubscriptionPackages.PAID3
    subs = subs.upper()
    print("subs", subs)
    if prize_type == 'data':
        reply, code = request_data_prize(tournamentid,phone_number, dataplan.data_plan, subs)
        print(reply, code)
        if code==0:
            # pending, code2 = check_pending_requests_data(phone_number)
            # print(pending, code2)
            # if code2==0:
            #     msg, code3 = confirm_request_data(phone_number, pending[0]['prizeProcessId'])
            #     print(msg, code3)
            #     if code3==0: # success
            return True
    elif prize_type == 'cash':
        # reply, code = request_cash_prize(tournamentid,phone_number, dataplan, subs)
        # print(reply, code)
        # if code==0:
        return True
    elif prize_type == 'others':
        return True
    elif prize_type == 'airtime':
        reply, code = request_airtime_prize(tournamentid,phone_number, dataplan.data_plan, subs)
        print(reply, code)
        if code==0:
            return True
        
    return False


class Tournament(TranslatableTimeStampedModel): #TimeStampedModel
    translations = TranslatedFields(
        nameTran = models.CharField(max_length=512),
        imageTran = models.ImageField(upload_to='tournaments/', null=True),
        top_imageTran = models.ImageField(upload_to='tournaments/', null=True,verbose_name='Detail Image'),
        label_next_timeTran =  models.CharField(max_length=250,blank=True,null=True,verbose_name='Label Next to Time'),
        descriptionTran = RichTextField(null=True),
        rulesTran = RichTextField(blank=True, null=True),
        pool_prizeTran = RichTextField(null=True,blank=True),
     )

    game = models.ForeignKey('core.Game', on_delete=models.PROTECT)
    name = models.CharField(max_length=512)
    slug = models.SlugField(unique=True)
    image = models.ImageField(upload_to='tournaments/', null=True)
    top_image = models.ImageField(upload_to='tournaments/', null=True,verbose_name='Detail Image')
    

    live_link = models.URLField(blank=True, null=True)
    leader_board_link = models.URLField(blank=True, null=True)
    
    minimum_profile_level = models.PositiveIntegerField(default=0)
    give_sticker = models.BooleanField('Give stickers to participants?',
                                       default=False)
    coins_per_participant = models.PositiveIntegerField(null=True) 
    max_participants = models.PositiveIntegerField(default=1)
    rounds_number = models.PositiveIntegerField(null=True)    
    regions = models.ManyToManyField('operator.Region')
    format = models.CharField(max_length=24, choices=BracketFormat.choices)

    
   
    time_compared_to_gmt = models.IntegerField(default=0,verbose_name='Time compared to GMT (+ or -)')
    label_next_time =  models.CharField(max_length=250,blank=True,null=True,verbose_name='Label Next to Time')
    open_date = models.DateTimeField(null=True,verbose_name = 'VIP Open Date (in GMT)')
    
    free_open_date = models.DateTimeField(null=True,verbose_name = 'Public Open Date (in GMT)')
    close_date = models.DateTimeField(null=True,verbose_name = 'Registration closes (in GMT)')

    start_date = models.DateTimeField(null=True, verbose_name = 'Tournament starts (in GMT)')
    end_date = models.DateTimeField(null=True,verbose_name = 'Tournament ends (in GMT)')

    description = RichTextField(null=True)
    rules = RichTextField(blank=True, null=True)
    pool_prize = RichTextField(null=True,blank=True)
    pool_prize_amount = models.CharField(max_length=250,blank=True,null=True)
                                  
    is_sponsored = models.BooleanField(default=False)
    sponsored_by = models.ImageField(upload_to='tournaments/', null=True,blank=True)
    allow_free_users = models.BooleanField(default=False)
   
    

    

    started_on = models.DateTimeField(blank=True, null=True)
    job_id = models.CharField(max_length=64, blank=True, null=True)
    created_by = models.ForeignKey('account.User', on_delete=models.SET_NULL,
                                   null=True)
    #objects = TournamentQuerySet.as_manager()
    objects = TournamentTranslatableQuerySet.as_manager()
    tracker = FieldTracker(fields=['end_date'])
    closed_on = models.DateTimeField(blank=True, null=True)

    def save(self, *args, **kwargs):
        self.slug = f'{slugify(self.name)}_{self.start_date.strftime("%Y_%m_%d")}'
        super().save(*args, **kwargs)


    def __str__(self):
        return self.name


    def is_sold_out(self):
        if not self.max_participants:
            return False

        return self.tournamentparticipant_set.count() >= self.max_participants
    
    def is_closed(self):
        now = timezone.now()
        if self.close_date < now:
            return True

        return False
    
    def get_top_winners(self):
       return self.tournamentprize_set.filter(
            winner__isnull=False,
        ).values('winner').annotate(
            winner_name=F('winner__nickname'),
            win_count=Count('winner')
        ).values('winner_name','win_count').order_by('position').all()[:3]	
           


    def is_expired(self):
        now = timezone.now()
        if self.end_date < now:
            return True

        return False
    
    def game_name(self):
        return self.game.name

    def send_notification_close(self):
        print("Triggered on close")
        tournament_prizes = TournamentPrize.objects.filter(
        tournament__id=self.id
         )
        tournament_winners= tournament_prizes.values_list('winner', flat=True)
        failed_participants_ids = TournamentParticipant.objects.filter(
            tournament__id=self.id,
        ).exclude(participant__id__in=tournament_winners).values_list('participant', flat=True)
        failed_participants = User.objects.filter(id__in=failed_participants_ids)

        # print(failed_participants)
        for prize in tournament_prizes :
            # USER_FIRST_TOURNAMENT

            if prize.position == 1 :
                @notify_when(events=[NotificationTemplate.USER_FIRST_TOURNAMENT], is_route=False, is_one_time=False)
                def notify(user, user_notifications):
                    """ extra logic if needed """
                    for notificationi in user_notifications:
                        notificationi.link=self.name+";"+prize.title+";"+str(prize.image)
                        notificationi.save()
                notify(prize.winner)

        # USER_SECOND_THIRD_TOURNAMENT >> Users who are second, third or positions that win a prize.
            elif  prize.position >= 2 :

                @notify_when(events=[NotificationTemplate.USER_SECOND_THIRD_TOURNAMENT], is_route=False, is_one_time=False)
                def notify(user, user_notifications):
                    """ extra logic if needed """
                    for notificationi in user_notifications:
                        notificationi.link=self.name+";"+prize.title+";"+str(prize.image)
                        notificationi.save()
                notify(prize.winner)
 
        print("failed participants", failed_participants)
        if failed_participants :
            for participant in  failed_participants :
                print("processing sticker for", participant)
                sticker = Sticker.objects.filter(  # .select_for_update()
                            ~Q(id__in=participant.stickers.all())
                        ).order_by('?').first()
                print("sticker", sticker)
                if self.give_sticker:
                    if sticker :
                        participant.stickers.add(sticker)
                        if not participant.stickers.all():
                            participant.stickers.create()
                            participant.stickers.add(sticker)                        
                        #participant.refresh_from_db()
                        # participant.save()
                        print("sticker added !")
                        print("stickers after save", participant.stickers.all())
                print("coins per participant", self.coins_per_participant)
                print("weird condition", participant.stickers.all())
                if self.coins_per_participant > 0 :
                    if participant.stickers.all() :
                        participant.old_coins = participant.coins
                        print("adding", self.coins_per_participant, "coins to", participant.coins)
                        participant.coins = participant.coins + self.coins_per_participant
                        participant.seen_coins = False
                        participant.save()            
            
                @notify_when(events=[NotificationTemplate.USER_OUTSIDE_THE_WINNING_POSITIONS], is_route=False, is_one_time=False)
                def notify(user, user_notifications):
                    """ extra logic if needed """
                    for notificationi in user_notifications:
                        notificationi.link=("1" if self.give_sticker else "0")+";"+(str(self.coins_per_participant) if self.coins_per_participant else "0")+";"+(str(sticker.image) if self.give_sticker and sticker and sticker.image  else "-")
                        notificationi.save()
                        # print(notificationi.link)
                notify(participant)

    def clean(self):
        super().clean()
        if self.close_date and self.open_date and self.close_date <= self.open_date:
            raise ValidationError({
                'close_date': _('Close Date must be greater than Open Date')
            })

        if self.start_date and self.start_date.date() < datetime.date.today() and not self.started_on:
            raise ValidationError({
                'start_date': _("Start Date can't be in the past")
            })
        if self.end_date and self.end_date.date()  < datetime.date.today() and not self.closed_on :
            raise ValidationError({
                'end_date': _("End Date can't be in the past")
            })
        if self.start_date and self.end_date and self.end_date <= self.start_date :
            raise ValidationError({
                'end_date': _('End Date must be greater than Start Date')
            })    
        if self.start_date and self.close_date :    
            delta = self.start_date - self.close_date 
            # hours = delta.total_seconds() / 3600
            if delta < timedelta(hours=2):
                raise ValidationError({
                    'close_date': _('Close Date must be at least 2 hours earlier than Start Date')
                })
        if self.open_date and self.free_open_date and self.free_open_date < self.open_date:
            raise ValidationError({
                'free_open_date': _('Public open date cannot be smaller than VIP open date')
            })
        if self.close_date and self.free_open_date and self.free_open_date > self.close_date:
            raise ValidationError({
                'free_open_date': _('Close date cannot be smaller than public open date')
            })

        

    @property
    def state(self):
        now = timezone.now()
        if self.start_date > now:
            return 'upcoming'
        if self.end_date and self.start_date < now and self.end_date > now:
            return 'ongoing'
        if self.end_date and now > self.end_date:
            return 'past'

    @property
    def starts_in_full(self):
        now = timezone.now()
        starts_in = self.start_date - now

        hours = starts_in.total_seconds()//3600

        if starts_in.days:
            if starts_in.days < 0 and not self.started_on : 
                return f'0 days'  
            elif not self.started_on and  starts_in.days > 0:
                return f'{ starts_in.days} days'
            else :    
                return f'In Progress'
        elif not hours:
            return f'{int((starts_in.total_seconds()//60)%60)} minutes'
        else:
            return f'{int(hours)} hours'

    def participants(self):
        return self.tournamentparticipant_set.filter(is_waiting_list=False)

    def current_participants(self):
        return self.participants().count()

    def waiting_participants(self):
        return self.tournamentparticipant_set.filter(is_waiting_list=False)

    def get_participant(self, user):
        return self.tournamentparticipant_set.filter(participant=user).first()


class TournamentPrizeList(TimeStampedModel):
    operator = models.CharField(max_length=30, blank=False)
    amount = models.PositiveIntegerField()
    data_plan = models.CharField(max_length=30, primary_key=True)
    data_plan_desc = models.TextField()
    prize_type = models.CharField(max_length=20, null=True,
                                  choices=TournamentPrizeType.choices) 
    def __str__(self):
        return f'{self.data_plan} - {self.data_plan_desc} - {self.prize_type}'   


class TournamentPrize(TranslatableTimeStampedModel): #TimeStampedModel
    translations = TranslatedFields(
        imageTran = models.ImageField(upload_to='prizes/', null=True),
        titleTran = models.CharField(max_length=256, null=True),
        prizeTran = models.TextField(blank=True, null=True, verbose_name='Prize Description')
    )

    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE)
    position = models.PositiveSmallIntegerField()
    prize_type = models.CharField(max_length=20, null=True,
                                  choices=TournamentPrizeType.choices)

    image = models.ImageField(upload_to='prizes/', null=True)
    title = models.CharField(max_length=256, null=True)
    prize = models.TextField(blank=True, null=True, verbose_name='Prize Description')
    actual_data_package = models.ForeignKey(TournamentPrizeList, null=True, blank=True, on_delete=models.SET_NULL)
    cash_amount = models.PositiveIntegerField(blank=True, null=True)
    # category = models.CharField('Winner Category', max_length=10,
    #                             choices=WinnerCategory.choices,
    #                             null=True)
    winner = models.ForeignKey('account.User', on_delete=models.SET_NULL,
                               blank=True, null=True)

    def clean(self):
        if self.prize_type == 'data' and not self.actual_data_package:
            raise ValidationError('A package must be selected if prize type is data.')
        elif (self.prize_type == 'cash' or self.prize_type == 'airtime') and not self.cash_amount:
            raise ValidationError('A cash amount must be entered if prize type is cash.')
        


    class Meta:
        verbose_name = 'prize'
        verbose_name_plural = 'tournament prizes'
        unique_together = (('tournament', 'position'),
                           ('tournament', 'winner'))

    def __str__(self):
        return f'{self.position} - {self.prize_type}'


class TournamentModerator(TimeStampedModel):
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE)
    moderator = models.ForeignKey('account.User', on_delete=models.CASCADE)

    class Meta:
        unique_together = (('tournament', 'moderator'),)


class TournamentParticipant(TranslatableTimeStampedModel): #TimeStampedModel
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE)
    participant = models.ForeignKey('account.User', on_delete=models.CASCADE)
    status = models.CharField(max_length=32, choices=ParticipantStatus.choices, default=ParticipantStatus.ACCEPTED)
    rank = models.IntegerField(default=0)
    points = models.IntegerField(default=0)
    notify_before_game = models.BooleanField(default=True)
    mobile_number = PhonyNumberField(max_length=15, blank=True, null=True, unique=True)
    prize = RichTextField(blank=True, null=True)
    is_waiting_list = models.BooleanField(default=False)
    # is_informed = models.BooleanField(default=False)
    matches_informed = models.ManyToManyField('tournament.TournamentMatch', blank=True)
    tracker = FieldTracker()

    def __str__(self):
        return self.participant.username

    class Meta:
        verbose_name = 'participant'
        verbose_name_plural = 'tournament participants'
        unique_together = (('tournament', 'participant'),)


class TournamentTeam(TimeStampedModel):
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE)
    team = models.CharField(max_length=128)
    members = models.ManyToManyField(TournamentParticipant)
    class Meta:
        unique_together = (('tournament', 'team'),)


class TournamentBracket(TimeStampedModel):
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE)
    bracket_name = models.CharField(max_length=256)
    bracket_format = models.CharField(max_length=24, choices=BracketFormat.choices)


class Bracket(TimeStampedModel):
    name = models.CharField(max_length=128)
    slug = models.SlugField(unique=True)

    number_of_matches = models.PositiveIntegerField(default=1)

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super().save(*args, **kwargs)


class TournamentMatch(TranslatableTimeStampedModel): #TimeStampedModel
    translations = TranslatedFields(
        match_nameTrans = models.CharField(max_length=256, null=True)
    )
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE)
    match_name = models.CharField(max_length=256, null=True)
    match_id = models.CharField(max_length=128, null=True, blank=True)
    password = models.CharField(max_length=16, null=True, blank=True)

    # round_number = models.IntegerField(choices=RoundNumber.choices,
    #                                    blank=True, null=False)
    RoundsNumber=(
    (1, '1st Round'),
    (2, '2nd Round'),
    (3, '3rd Round'),
    (4, '4th Round'),
    (5, '5th Round'),
    (6, '6th Round'),
    (7, '7th Round'),
    (8, '8th Round'),
    (9, '9th Round'),
    (10, '10th Round'),
    (11, '11th Round'),
    (12, '12th Round'),
    (13, '13th Round'),
    (14, '14th Round'),
    (15, '15th Round'),
    (16, '16th Round'),
    (17, '17th Round'),
    (18, '18th Round'),
    (19, '19th Round'),
    (20, '20th Round')
    )

    round_number = models.IntegerField(null=True,choices=RoundsNumber)
    start_date = models.DateTimeField(null=True,verbose_name = 'Start Date (in GMT)')
    inform_participants = models.PositiveIntegerField(help_text='in minutes',
                                                      null=True)

    match_data = models.JSONField(null=True)
    participants = models.ManyToManyField('account.User', blank=True, related_name='participants', related_query_name='participanto')
    winners = models.ManyToManyField('account.User', blank=True) # account.User, through='tournament.SerialUserGameLinkedAccount')
    image = models.ImageField(upload_to='winners/', null=True, blank=True)

    class Meta:
        verbose_name = 'match'
        verbose_name_plural = 'Tournament Matches'

        
    def __str__(self):
        return self.match_name

    def clean(self):
        super().clean()
        if self.round_number is not None and self.tournament.rounds_number is not None and self.round_number and self.round_number > self.tournament.rounds_number and  self.tournament.game.game_model != GameMode.TEAM_BASED :
            raise ValidationError({
                'round_number': _('This round number selection is above the rounds numbers set in the tournament settings')
            })
        if self.start_date and self.tournament.start_date and self.tournament.end_date and (self.start_date < self.tournament.start_date or self.start_date > self.tournament.end_date):
            raise ValidationError({
                'start_date': _('Match date must be between tournament start date and tournament end date')
            })
        

 
       
class TournamentInvitation(TimeStampedModel):
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE, null=True)
    participant = models.ForeignKey(TournamentParticipant,
                                    on_delete=models.CASCADE)
    invitee = models.ForeignKey('account.User', on_delete=models.CASCADE)
    status = models.CharField(max_length=32, choices=ParticipantStatus.choices,
                              default=ParticipantStatus.PENDING)

    class Meta:
        unique_together = (('tournament', 'participant', 'invitee'),)
