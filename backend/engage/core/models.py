from ckeditor.fields import RichTextField
from django.db import models
from django.utils.text import slugify
from django.core.validators import FileExtensionValidator
from solo.models import SingletonModel
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from parler.models import TranslatedFields

from common.models import TranslatableTimeStampedModel, TimeStampedModel
from .constants import (
    WinAction,
    SupportedGame,
    EventType,
    HTML5GameType,
    HTML5GameOption,
    NotificationAction,
    NotificationTemplate, GameMode,Platform
)
from .managers import BattlePassManager
from ..account.constants import SubscriptionPlan
from ..operator.constants import SubscriptionType
from django.utils.translation import activate, get_language
from parler.models import TranslatableModel

#language = TranslatableModel.get_current_language()
#print("Language"+ language)

class Configuration(SingletonModel):
    commission_rate = models.DecimalField(max_digits=10, decimal_places=2,
                                          default=0)
    sponsor_tournament_cost = models.PositiveIntegerField(default=100)
    disqualification_time = models.IntegerField(default=1)

    a_party_invitation_reward = models.PositiveIntegerField(default=200)
    a_party_invitation_level = models.PositiveIntegerField(
        help_text='increase level', default=1)
    a_party_invitation_free_day = models.PositiveIntegerField(default=0)

    b_party_invitation_reward = models.PositiveIntegerField(default=100)
    b_party_invitation_level = models.PositiveIntegerField(
        help_text='increase level', default=0)
    b_party_invitation_free_day = models.PositiveIntegerField(default=1)

    class Meta:
        verbose_name_plural = 'Configuration'

    def __str__(self):
        return 'configuration'


class Avatar(models.Model):
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='avatars/')

    def __str__(self):
        return self.image.name


class Game(TranslatableTimeStampedModel): #TimeStampedModel
    translations = TranslatedFields(
        name = models.CharField(max_length=256),
        description = RichTextField(blank=True, null=True),
        logoTran = models.ImageField(upload_to='games/icons/'),
        header_imageTran = models.ImageField(upload_to='games/headers/', blank=True,
                                     null=True)

    )

    support_game = models.CharField('Supported Game',
                                    max_length=32,
                                    choices=SupportedGame.choices,
                                    null=True)
    name = models.CharField(max_length=256)
    slug = models.SlugField(unique=True, null=True)
    description = RichTextField(blank=True, null=True)
    logo = models.ImageField(upload_to='games/icons/')
    header_image = models.ImageField(upload_to='games/headers/', blank=True,
                                     null=True)
    average_game_duration = models.FloatField(blank=True, null=True)

    pc_link = models.CharField(max_length=512, null=True)
    android_link = models.CharField(max_length=512, null=True)
    ios_link = models.CharField(max_length=512, null=True)

    game_model = models.CharField(max_length=16, choices=GameMode.choices,
                                  null=True,blank=True)
    room_size = models.PositiveIntegerField(null=True)
    game_max_length = models.PositiveIntegerField(help_text='per minute',
                                                  null=True)

    has_api = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    platform = models.CharField(max_length=16, choices=Platform.choices,
                                  null=True,default=Platform.PC)
     

    def __str__(self):
        return f'[{self.get_game_model_display()}] {self.name}'

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super().save(*args, **kwargs)


class FeaturedGame(TranslatableTimeStampedModel): #TimeStampedModel
    translations = TranslatedFields(
        logoTran = models.ImageField(upload_to='games/icons/'),
        nameTran = models.CharField(max_length=256),
    )
    logo = models.ImageField(upload_to='games/icons/')

    name = models.CharField(max_length=256)
    pc_link = models.CharField(max_length=512, null=True)
    android_link = models.CharField(max_length=512, null=True)
    ios_link = models.CharField(max_length=512, null=True)
    nbr_of_coins = models.PositiveIntegerField(default=10)
    def __str__(self):
        return self.name


class Sticker(TranslatableTimeStampedModel): #TimeStampedModel
    translations = TranslatedFields(
        name = models.CharField(max_length=64),
        imageTran = models.ImageField(upload_to='stickers/')
    )
    name = models.CharField(max_length=64)
    image = models.ImageField(upload_to='stickers/')

    def __str__(self):
        return self.name


class Trophy(TimeStampedModel):
    name = models.CharField(max_length=64)
    image = models.ImageField(upload_to='trophies/')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = 'Trophies'


class HTML5Game(TranslatableTimeStampedModel): #TimeStampedModel
    translations = TranslatedFields(
        descriptionTrans = RichTextField(blank=True, null=True),
        imageTrans = models.ImageField(upload_to='html5_games/')
    )

    game = models.CharField(max_length=256, choices=HTML5GameOption.choices)
    slug = models.SlugField()
    game_type = models.CharField(max_length=12, choices=HTML5GameType.choices,
                                 null=True)
    image = models.ImageField(upload_to='html5_games/')
    description = RichTextField(blank=True, null=True)
    regions = models.ManyToManyField('operator.Region')
    include_inlanding_page = models.BooleanField(default=False,verbose_name="Include in landing page")

    def __str__(self):
        return self.game

    class Meta:
        verbose_name = 'HTML5 Game'
        verbose_name_plural = 'HTML5 Games'
        ordering = ('-created', )

    def save(self, *args, **kwargs):
        self.slug = slugify(self.game)
        super().save(*args, **kwargs)

    @property
    def is_free_game(self):
        return self.game_type == HTML5GameType.FREE

    @property
    def is_premium_game(self):
        return self.game_type == HTML5GameType.PREMIUM

    @property
    def is_exclusive_game(self):
        return self.game_type == HTML5GameType.EXCLUSIVE


class Event(TimeStampedModel):
    event_type = models.CharField(max_length=16, choices=EventType.choices)
    image = models.ImageField(upload_to='events/')
    title = models.CharField(max_length=64, blank=True, null=True)

    regions = models.ManyToManyField('operator.Region')

    def __str__(self):
        return self.image.name


class Mission(TimeStampedModel):
    name = models.CharField(max_length=512)
    image = models.ImageField(upload_to='missions/', null=True)
    action = models.CharField(max_length=64, choices=WinAction.choices,
                              unique=True)
    go_link = models.URLField('GO Link', null=True)
    free_user_points = models.PositiveIntegerField(null=True)
    paid1_user_points = models.PositiveIntegerField(null=True)
    paid2_user_points = models.PositiveIntegerField(null=True)

    def __str__(self):
        return self.name

    def total_points(self, user):
        if user.subscription == SubscriptionPlan.PAID1 and user.is_billed:
            return self.paid1_user_points
        if user.subscription == SubscriptionPlan.PAID2 and user.is_billed:
            return self.paid2_user_points
        else:
            return self.free_user_points if self.free_user_points else 0


class BattlePass(TimeStampedModel):
    icon = models.ImageField(upload_to='battlepass/', blank=True, null=True)
    name = models.CharField(max_length=128)
    starts_at = models.DateField()
    ends_at = models.DateField()
    coins_per_level = models.PositiveIntegerField(default=30)
    max_level = models.PositiveIntegerField()
    unlock_vip_cost = models.DecimalField('Unlock VIP price', max_digits=14,
                                          decimal_places=2, null=True)
    is_active = models.BooleanField(default=False)

    objects = BattlePassManager()

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Battle Pass'
        verbose_name_plural = 'Battle Pass'

    def is_user_vip(self, user):
        return self.userbattlepass_set.filter(
            user=user,
            is_vip=True
        ).exists()


class BattlePassLevel(models.Model):
    battle_pass = models.ForeignKey(BattlePass, on_delete=models.CASCADE)
    level = models.PositiveIntegerField()
    free_video = models.PositiveIntegerField(blank=True, null=True)
    free_coins = models.PositiveIntegerField(blank=True, null=True)
    free_data = models.PositiveIntegerField(blank=True, null=True)

    def __str__(self):
        return f'[{self.battle_pass.name}] level {self.level}'

    class Meta:
        unique_together = (('battle_pass', 'level'),)


class BattlePassMission(models.Model):
    battle_pass = models.ForeignKey(BattlePass, on_delete=models.CASCADE)
    mission = models.ForeignKey(Mission, on_delete=models.CASCADE)

    date = models.DateField()

    class Meta:
        unique_together = (('battle_pass', 'mission', 'date'),)

class Package(models.Model):
    name = models.TextField()
    def __str__(self):
        return self.name




class Notifications(TranslatableTimeStampedModel):
    translations = TranslatedFields(
        titleTran = models.TextField(null=True),
        textTran = models.TextField(blank=True), 
        imageTran = models.ImageField(upload_to='templates/', blank=True, null=True),
        videoTran = models.FileField(upload_to='videos_uploaded/',
                             blank=True,
                             null=True,
                             help_text="MOV, mp4 or webm supported",
                             validators=[
                                 FileExtensionValidator(allowed_extensions=[
                                     'MOV', 'avi', 'mp4', 'webm'
                                 ])
                             ])
     )
    template = models.CharField(choices=NotificationTemplate.choices,
                                null=True, max_length=40)
    action = models.CharField(choices=NotificationAction.choices,
                              default=NotificationAction.TEXT, max_length=20)
    title = models.TextField(null=True)
    text = models.TextField(blank=True, null=True)
    

    url = models.URLField(blank=True, null=True)
    image = models.ImageField(upload_to='templates/', blank=True, null=True)

    video = models.FileField(upload_to='videos_uploaded/',
                             blank=True,
                             null=True,
                             help_text="MOV, mp4 or webm supported",
                             validators=[
                                 FileExtensionValidator(allowed_extensions=[
                                     'MOV', 'avi', 'mp4', 'webm'
                                 ])
                             ])
    event_date = models.DateField(blank=True, null=True)
    gifted_coins = models.PositiveIntegerField(default=0)
    claim_instantly = models.BooleanField(default=False)
    is_gift = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_popup = models.BooleanField(default=False,verbose_name='display as popup') 
    package = models.ManyToManyField('core.package',verbose_name="Package")

                                    
    class Meta:
        verbose_name = 'Notification'
        verbose_name_plural = 'Notifications'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['Title'].widget.attrs.update({'class':'form-control'})

    def save(self, *args, **kwargs):
        self.is_gift = not not self.gifted_coins

        if self.action == NotificationAction.TEXT and self.gifted_coins > 0:
            self.claim_instantly = True
        

        super().save(*args, **kwargs)
    
    def clean(self):
        super().clean()

        if self.action == NotificationAction.TEXT and self.gifted_coins > 0:
            self.claim_instantly = True

        if self.action == NotificationAction.TEXT and not self.text:
            raise ValidationError({
                'text': _('This field is required.')
            })

        if self.action == NotificationAction.TEXT and self.gifted_coins \
                and not self.claim_instantly:
            raise ValidationError(
                _('Claim Instantly must be selected if coins '
                  'are set for a TEXT action')
            )

        if self.action == NotificationAction.IMAGE and not self.image:
            raise ValidationError({
                'image': _('This field is required.')
            })

        if self.action == NotificationAction.VIDEO and not self.video:
            raise ValidationError({
                'video': _('This field is required.')
            })

        if self.template == NotificationTemplate.EVENT and not self.event_date:
            raise ValidationError({
                'event_date': _('Event Date is required')
            })
    
    @property
    def image_url(self):
        if self.image and hasattr(self.image, 'url'):
            return self.translations.image.url

                         