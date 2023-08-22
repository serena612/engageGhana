import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models, transaction
from django.db.models import Q, Sum
from django.db.models.functions import Coalesce
from django.utils import timezone
from engage.core.models import Game
from django_countries.fields import CountryField
from django.templatetags.static import static
from model_utils import FieldTracker
from phonenumber_field.modelfields import PhoneNumberField
from timezone_field import TimeZoneField
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _

from common.models import TimeStampedModel
from .constants import (
    Gender,
    FriendStatus,
    CoinTransaction,
    SubscriptionPlan,
    Transaction
)
from .managers import (
    CustomUserManager,
    UserActivityManager
)
# def validate_phone(value):
#     print("Validating", value, "length", len(value))
#     if len(value)!=10:
#         raise ValidationError(
#             _('%(value)s is not a valid phone number'),
#             params={'value': value},
#         )
class PhonyNumberField(models.CharField):
    

    def clean(self, value, *args, **kwargs):
        
        cleaned_data = super().clean(value, *args, **kwargs)
        subdata = cleaned_data
        prefs1 = [703, 704, 706, 803, 806, 810, 813, 814, 816, 903, 906,913,916, 102] # added 102 exception
        prefs2 = [7025, 7026]
        if len(cleaned_data)==15 and cleaned_data.startswith("00"):
            cleaned_data = cleaned_data[2:]
        elif len(cleaned_data)==14 and cleaned_data.startswith("+"):
            cleaned_data = cleaned_data[1:]
        if len(cleaned_data) == 13 and cleaned_data.startswith("234"):
            cleaned_data = cleaned_data[3:]
        elif len(cleaned_data)==11 and cleaned_data.startswith("0"):
            cleaned_data = cleaned_data[1:]
        if len(cleaned_data)==10:
            if int(cleaned_data[0:3]) in prefs1 or int(cleaned_data[0:4]) in prefs2:
                print("Valid Number passing through")
                return '234'+cleaned_data
    
        raise ValidationError(
            _('%(subdata)s is not a valid MTN phone number!'),
            params={'subdata': subdata},
        )

class User(AbstractUser, TimeStampedModel):
    uid = models.UUIDField(default=uuid.uuid4, editable=False)
    avatar = models.ForeignKey('core.Avatar', on_delete=models.SET_NULL,
                               blank=True, null=True)
    nickname = models.CharField(max_length=64, blank=True, null=True)
    # mobile = models.CharField(max_length=15, blank=True, null=True,validators=[validate_phone])
    mobile = PhonyNumberField(max_length=15, blank=True, null=True, unique=True)
    app_fcm_token = models.CharField(max_length=256, blank=True, null=True)
    web_fcm_token = models.CharField(max_length=256, blank=True, null=True)

    newsletter_subscription = models.BooleanField(default=True)

    coins = models.PositiveIntegerField(default=0)
    country = CountryField(blank=True, null=True)
    timezone = TimeZoneField(null=True)

    level = models.PositiveIntegerField(default=1)
    stickers = models.ManyToManyField('core.Sticker', blank=True)
    trophies = models.ManyToManyField('core.Trophy', blank=True)

    subscription = models.CharField(choices=SubscriptionPlan.choices,
                                    default=SubscriptionPlan.FREE,
                                    max_length=50)

    last_login = models.DateTimeField(blank=True, null=True)

    last_seen = models.DateTimeField(blank=True, null=True)

    region = models.ForeignKey('operator.Region', on_delete=models.CASCADE,
                               null=True)
    is_billed = models.BooleanField(default=False)
    old_coins = models.PositiveIntegerField(default=0, null=True)
    seen_coins = models.BooleanField(default=False)
    referrer = models.ForeignKey('self', on_delete=models.SET_NULL,
                               blank=True, null=True)
    go_premium_sent = models.BooleanField(default=False)
    tournament_joined_today = models.BooleanField(default=False)
    
    def _get_nicknames(self) :
        result = ''
        games= Game.objects.filter(is_active=True)
        for game in games :
            user_game = UserGameLinkedAccount.objects.filter(user=self,game=game).order_by('-modified').first()
            print(user_game)
            if user_game :
                if result != '' :
                    result= result+" \n "+ game.name+": "+user_game.account    
                else :
                    result=  game.name+": "+user_game.account 
                        
        return result

    game_nicknames = property(_get_nicknames)


    def __str__(self):
        if self.is_staff:
            return self.username
        else:
            atrs = ['gnickname', 'mobile', 'nickname']
            disp = []
            for atr in atrs:
                if hasattr(self, atr):
                    ga = getattr(self, atr)
                    if ga is not None:
                        disp.append(str(getattr(self, atr)))
            disp.append(self.username)
            return " - ".join(disp)

    objects = CustomUserManager()
    tracker = FieldTracker(fields=['coins'])

    @property
    def is_subscriber(self):
        return self.subscription != SubscriptionPlan.FREE

    @property
    def is_complete_profile(self):
        if self.country and self.nickname and self.avatar and self.email and self.email!='':
            return True
        return False

    @property
    def profile_image(self):
        if self.subscription == SubscriptionPlan.PAID1:
            return static('img/pro2.png')
        elif self.subscription == SubscriptionPlan.PAID2:
            return static('img/pro3.png')
        else:
            return static('img/pro1.png')

    @property
    def friends(self):
        return FriendList.objects.filter(
            Q(user=self) | Q(friend=self),
            status=FriendStatus.ACCEPTED
        ).order_by('friend__username')

    @property
    def top_friends(self):
        return self.friends[:10]

    @property
    def mission_progress_ratio(self):
        if self.subscription == SubscriptionPlan.PAID1:
            return 0.2
        elif self.subscription == SubscriptionPlan.PAID2:
            return 0.3
        else:
            return 0


       
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    residency = models.CharField(max_length=128, blank=True, null=True)
    birthdate = models.DateField(blank=True, null=True)
    gender = models.CharField(max_length=6, choices=Gender.choices, blank=True,
                              null=True)
    instagram = models.CharField(max_length=128, blank=True, null=True)
    twitter = models.CharField(max_length=128, blank=True, null=True)


class UserFavoriteFriend(TimeStampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    friend = models.ForeignKey(User, on_delete=models.CASCADE,
                               related_name='+')

    class Meta:
        unique_together = (('user', 'friend'), )


class UserGameLinkedAccount(TimeStampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    game = models.ForeignKey('core.Game', on_delete=models.CASCADE)
    account = models.CharField(max_length=256)
    tournament = models.ForeignKey('tournament.Tournament', on_delete=models.CASCADE)

    class Meta:
        unique_together = (('user', 'game','tournament'),)
        
    def __str__(self):
        return f'{self.account}-{self.user.mobile if self.user.mobile else ""}'    
    

class FriendList(TimeStampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    friend = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
    status = models.CharField(max_length=16, choices=FriendStatus.choices,
                              default=FriendStatus.PENDING)

    tracker = FieldTracker(fields=['status'])

    
    class Meta:
        unique_together = (('user', 'friend'),)
        verbose_name_plural = 'Friends List'
       
    def __init__(self, args, *kwargs):
        super().__init__(*args, **kwargs)
        self.fields['friend'].widget.attrs['disabled'] = True
        
    def other(self, user):
        if self.user == user:
            return self.friend
        else:
            return self.user


class UserTransactionHistory(TimeStampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(choices=CoinTransaction.choices, max_length=12,
                              default=CoinTransaction.ADD)
    amount = models.IntegerField()
    actual_amount = models.IntegerField(null=True)
    info = models.CharField(null=True,blank=True,max_length=50)

    class Meta:
        verbose_name = 'Coins History'
        verbose_name_plural = 'Coins History'

    def total_coins_today(self):
        now = timezone.now()

        coins_history = UserTransactionHistory.objects.filter(
            user=self.user,
            action=CoinTransaction.ADD,
            created__date=now.date()
        ).aggregate(
            total_amount=Coalesce(Sum('amount'), 0)
        )
        return coins_history.get('total_amount', 0)

    def claimed(self):
        now = timezone.now()
        return UserTransactionHistory.objects.filter(
            user=self.user,
            action=CoinTransaction.RETRIEVE,
            created__date=now.date()
        ).exists()

    def ads_clicked(self):
        now = timezone.now()
        return UserTransactionHistory.objects.filter(
            user=self.user,
            action=CoinTransaction.AD_CLICK,
            created__date=now.date()
        ).count()

    def ads_viewed(self):
        now = timezone.now()
        return UserTransactionHistory.objects.filter(
            user=self.user,
            action=CoinTransaction.AD_VIEW,
            created__date=now.date()
        ).count()

    def engage_viewed(self):
        now = timezone.now()
        return UserTransactionHistory.objects.filter(
            user=self.user,
            action=CoinTransaction.ENGAGE_VIEW,
            created__date=now.date()
        ).count()
   
    @transaction.atomic()
    def save(self, *args, **kwargs):
        if self.id:
            super().save(*args, **kwargs)
            return

        self.user.old_coins = self.user.coins
        self.user.seen_coins = False
        if self.action == CoinTransaction.ADD:
            # coins_today = self.total_coins_today()
            # coins_diff = 100 - coins_today
            # if coins_diff >= self.amount:
            self.actual_amount = self.amount
            self.user.coins += self.amount

            # elif self.amount > coins_diff > 0:
            #     self.actual_amount = coins_diff
            #     self.user.coins += coins_diff
            # else:
                
            #     self.actual_amount = 0
        elif self.action == CoinTransaction.RETRIEVE:
            # check if already claimed today
            print("Claimed today", self.claimed())
            if not self.claimed():
                self.actual_amount = self.amount
                self.user.coins += self.amount
            else:
                self.actual_amount = 0
        elif self.action == CoinTransaction.REFER:
            # check if already claimed today
            print("Referral Claim")
            # can add limit to referrals here if needed
            self.actual_amount = self.amount
            self.user.coins += self.amount
            # else:
            #     self.actual_amount = 0
        elif self.action == CoinTransaction.AD_CLICK:
            # check if already claimed today
            print("ads clicked today", self.ads_clicked())
            if self.ads_clicked()+self.ads_viewed()<3:
                self.actual_amount = self.amount
                self.user.coins += self.amount
            else:
                self.actual_amount = 0

        elif self.action == CoinTransaction.AD_VIEW:
            # check if already claimed today
            print("ads viewed today", self.ads_viewed())
            if self.ads_clicked()+self.ads_viewed()<3:
                self.actual_amount = self.amount
                self.user.coins += self.amount
            else:
                self.actual_amount = 0
        
        elif self.action == CoinTransaction.ENGAGE_VIEW:
            # check if already claimed today
            print("engage ads viewed today", self.engage_viewed())
           
            self.actual_amount = self.amount
            self.user.coins += self.amount

        else:
            self.actual_amount = self.amount
            self.user.coins += self.amount
            
            if self.action == CoinTransaction.RECEIVE and self.amount >= 200:
                UserLevelHistory.objects.create(user=self.user, level=1)   
        self.user.save()        
        super().save(*args, **kwargs)


class UserFavoriteGame(TimeStampedModel):
    user = models.ForeignKey('account.User', on_delete=models.CASCADE)
    game = models.ForeignKey('core.Game', on_delete=models.CASCADE)

    class Meta:
        unique_together = (('user', 'game'),)


class UserNotification(models.Model):
    user = models.ForeignKey('account.User', related_name='notifications',
                             on_delete=models.CASCADE)
    notification = models.ForeignKey('core.Notifications', on_delete=models.CASCADE,
                                     null=True)

    title = models.TextField(blank=True, null=True)
    text = models.TextField(blank=True, null=True)

    friend_uid = models.TextField(blank=True, null=True)

    is_sent = models.BooleanField(default=False)
    is_claimed = models.BooleanField(default=False)

    last_read = models.DateTimeField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)
    link = models.TextField(blank=True, null=True)
    is_popup = models.BooleanField(default=False)

class UserGamePlayed(models.Model):
    user = models.ForeignKey('account.User', on_delete=models.CASCADE)
    game = models.ForeignKey('core.HTML5Game', on_delete=models.CASCADE)

    count = models.PositiveIntegerField(default=1)
    last_played_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (('user', 'game'),)


class UserActivity(models.Model):
    user = models.ForeignKey('account.User', on_delete=models.CASCADE)

    day = models.DateField()
    was_active = models.BooleanField(default=False)

    objects = UserActivityManager()

    class Meta:
        unique_together = ("day", "user")


class UserBattlePass(TimeStampedModel):
    user = models.ForeignKey('account.User', on_delete=models.CASCADE)
    battlepass = models.ForeignKey('core.BattlePass', on_delete=models.CASCADE)
    is_vip = models.BooleanField(default=False)
    vip_date = models.DateTimeField(blank=True, null=True)

    class Meta:
        unique_together = (('user', 'battlepass'),)


class UserBattlePassMission(TimeStampedModel):
    bp_mission = models.ForeignKey('core.BattlePassMission',
                                   on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    points = models.PositiveIntegerField(default=0)
    count = models.PositiveIntegerField(default=0)
    is_completed = models.BooleanField(default=False)

    tracker = FieldTracker(fields=['is_completed'])

    def save(self, *args, **kwargs):
        if (not self.id and self.is_completed) or (
                self.tracker.has_changed('is_completed') and self.is_completed):
            self.points = self.bp_mission.mission.total_points(self.user)

        super().save(*args, **kwargs)


class SendCoinsHistory(TimeStampedModel):
    user = models.ForeignKey('account.User', on_delete=models.CASCADE)
    receiver = models.ForeignKey('account.User', on_delete=models.CASCADE,
                                 related_name='received_coins')
    amount = models.PositiveIntegerField()

class UserSectionLog(models.Model):
    user = models.ForeignKey('account.User', on_delete=models.CASCADE)
    section_name =  models.CharField(max_length=200)
    created = models.DateTimeField(auto_now_add=True)


class UserLevelHistory(TimeStampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    level = models.IntegerField()

    @transaction.atomic()
    def save(self, *args, **kwargs):
        if not self.id:
            self.user.level += self.level
            self.user.save()

        super().save(*args, **kwargs)