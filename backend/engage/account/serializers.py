from django.contrib.auth import get_user_model
from django_countries.serializer_fields import CountryField
from rest_framework import serializers

from engage.core.models import Notifications, Avatar
from .constants import Gender, SubscriptionPlan
from .models import UserNotification, FriendList, UserFavoriteFriend, \
    UserGamePlayed
from ..core.serializers import HTML5GameSerializer
from parler_rest.serializers import TranslatableModelSerializer
from parler_rest.fields import TranslatedFieldsField

UserModel = get_user_model()


class NotificationSerializer(TranslatableModelSerializer):  #serializers.ModelSerializer
    translations = TranslatedFieldsField(shared_model=Notifications)
    title = serializers.SerializerMethodField()
    text = serializers.SerializerMethodField()

    class Meta:
        model = Notifications
        #fields = ('id', 'action', 'title', 'text', 'url', 'image', 'video', 'template',
        #          'is_gift', 'gifted_coins', 'created','is_popup','translations')
        fields = ('id','title', 'text', 'action','url','template',
                  'is_gift', 'gifted_coins', 'created','is_popup','translations')

    def get_title(self, obj):
        return obj.title #_safe_string_formatter(user=self.context['request'].user, data=obj.title)

    def get_text(self, obj):
        return obj.text #_safe_string_formatter(user=self.context['request'].user, data=obj.text)


class UserNotificationSerializer(serializers.ModelSerializer):
    notification = NotificationSerializer(read_only=True)

    class Meta:
        model = UserNotification
        #exclude = ('user', 'last_read', 'is_sent', )
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='nickname')
    profile_image = serializers.CharField(read_only=True)
    country = serializers.SerializerMethodField()
    flag = serializers.SerializerMethodField()
    avatar = serializers.SerializerMethodField()

    class Meta:
        model = UserModel
        fields = ('uid', 'username', 'country', 'flag', 'avatar', 'level',
                  'profile_image','nickname')

    def get_country(self, obj):
        return obj.country.name

    def get_flag(self, obj):
        return f'/static/flags/{obj.country.code}.png'

    def get_avatar(self, obj):
        return obj.avatar.image.url if obj.avatar else None


class UserFriendSerializer(UserSerializer):
    username = serializers.CharField(source='nickname')
    is_favorite = serializers.SerializerMethodField()
    profile_image = serializers.CharField(read_only=True)

    def get_is_favorite(self, obj):
        request = self.context.get('request')
        if request.user and request.user.is_authenticated:
            return UserFavoriteFriend.objects.filter(user=request.user, friend=obj).exists()
        else:
            return False

    class Meta:
        model = UserModel
        fields = ('uid', 'username', 'country', 'flag', 'avatar', 'level',
                  'is_favorite', 'profile_image')
        

class FriendSerializer(serializers.ModelSerializer):
    friend = serializers.SerializerMethodField()

    class Meta:
        model = FriendList
        exclude = ('user',)
    

    def get_friend(self, obj):
        user = self.context['user']

        if user == obj.friend:
            return UserFriendSerializer(instance=obj.user, context=self.context).data
        else:
            return UserFriendSerializer(instance=obj.friend, context=self.context).data


class SendCoinsSerializer(serializers.Serializer):
    amount = serializers.IntegerField(min_value=1)

    def validate(self, attrs):
        amount = attrs.get('amount')
        user = self.context['request'].user
        if amount > user.coins:
            raise serializers.ValidationError('The amount exceeds your balance')

        return attrs


class UpdateSubscriptionSerializer(serializers.Serializer):
    msisdn = serializers.CharField()
    refid = serializers.CharField(required=False)
    new_substatus = serializers.CharField() # serializers.ChoiceField(choices=SubscriptionPlan.choices)

    def validate(self, attrs):
        msisdn = attrs.get('msisdn')
        new_substatus = attrs.get('new_substatus')
        try:
            refid = attrs.get('refid')
        except:
            pass
        # if new_substatus not in SubscriptionPlan.choices:
        #     raise serializers.ValidationError('The subscription plan provided is not valid!')

        return attrs


class RemoveSubscriptionSerializer(serializers.Serializer):
    msisdn = serializers.CharField()
    # refid = serializers.CharField(required=False)
    # new_substatus = serializers.ChoiceField(choices=SubscriptionPlan.choices)

    def validate(self, attrs):
        msisdn = attrs.get('msisdn')
        return attrs

class DisableSubscriptionSerializer(serializers.Serializer):
    msisdn = serializers.CharField()
    
    def validate(self, attrs):
        msisdn = attrs.get('msisdn')
        return attrs
    
class ExpiryOnRenewalSerializer(serializers.Serializer):
    msisdn = serializers.CharField()
    
    def validate(self, attrs):
        msisdn = attrs.get('msisdn')
        return attrs


class UserGamePlayedSerializer(serializers.ModelSerializer):
    game = HTML5GameSerializer()

    class Meta:
        model = UserGamePlayed
        exclude = ('user',)


class EditProfileSerializer(serializers.Serializer):
    avatar = serializers.PrimaryKeyRelatedField(
        queryset=Avatar.objects.all(), required=False, allow_null=True
    )
    name = serializers.CharField(min_length=3)
    email = serializers.EmailField()
    birthdate = serializers.DateField()
    country = CountryField()
    gender = serializers.ChoiceField(choices=Gender.choices)
    residency = serializers.CharField()
