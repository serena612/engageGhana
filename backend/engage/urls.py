# coding: utf-8
import os
from datetime import datetime, timedelta
from django.shortcuts import redirect
from django.http import (
    HttpResponseForbidden,
    HttpResponseNotFound
)
from django.utils import timezone
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin

from django.urls import path, include, re_path
from drf_yasg import views, openapi
from rest_framework import permissions

from .account.constants import SubscriptionPlan
from .core.constants import HTML5GameType
from .services import XSendFile
from .account.models import UserGamePlayed
from .core.models import HTML5Game

from django.views.generic import TemplateView
from django.conf.urls import url
from django.contrib.auth.forms import AuthenticationForm

from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV3
from django.core.exceptions import ValidationError
from django.core.mail import send_mail

class AuthAdminForm(AuthenticationForm):
    
    #if not settings.DEBUG:
    captcha = ReCaptchaField(widget=ReCaptchaV3)
    # def confirm_login_allowed(self, user):  # override method to send mail
    #     if not user.is_active:
    #         raise ValidationError(
    #             self.error_messages["inactive"],
    #             code="inactive",
    #         )
    #     else:
    #         if user.is_staff:
    #             send_mail(  # send email function is success
    #                 'CMS Login',
    #                 'User '+user.get_username()+' has just logged in to CMS.',
    #                 'engagegames2023@outlook.com',  # engagetest4@outlook.com support@engageplaywin.com
    #                 ['engagegames2023@outlook.com'],  # engagetest4@outlook.com support@8zonegames.com
    #                 fail_silently=True,  # do not trigger errors
    #             )

  
admin.autodiscover()
admin.site.login_form = AuthAdminForm
admin.site.login_template = 'admin/captcha_login.html'
admin.site.index_template = 'admin/custom_index.html'
# admin.site.password_change_template = 'admin/change_passwordd.html'  

admin.site.site_url = None
admin.site.site_header = 'Engage'
admin.site.site_title = 'Engage'
admin.site.index_title = 'Engage'


handler404 = 'engage.core.views.view_404'
handler403 = 'engage.core.views.view_403'
schema_view = views.get_schema_view(
    openapi.Info(
        title="Engage API",
        default_version='v1',
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)


# TODO: temporary, must be placed in core
# @login_required(login_url='/')
def protected_games(request, path, *args, **kwargs):

    
    if path.split('/')[1]== '' :   
    
        user = request.user
       # print(user.is_authenticated)
        if not user.is_authenticated :
            return redirect('/')  
             
        now = datetime.now(tz=timezone.utc)    
        game = HTML5Game.objects.filter(
            game=path.split('/')[0],
            regions__in=[request.region]
        ).first()
        if not game:
            return HttpResponseNotFound('game not found')            
        
        if game.is_free_game:
            pass
        elif user.subscription == SubscriptionPlan.FREE or user.is_billed == False:
            today_user_game_played = UserGamePlayed.objects.filter(
                user=user,
                last_played_at__date=now.date(),
                game__game_type__in=[HTML5GameType.EXCLUSIVE]
            ).exclude(
                game=game
            ).first()

            if today_user_game_played:
                return HttpResponseForbidden(
                    'Upgrade your subscription to play this game'
                )
        else:
            today_user_game_played = UserGamePlayed.objects.filter(
                user=user,
                last_played_at__date=now.date(),
                game__game_type__in=[HTML5GameType.PREMIUM, HTML5GameType.EXCLUSIVE]
            ).exclude(
                game=game
            ).first()
        
            
            if today_user_game_played:
            
                return HttpResponseForbidden(
                    'You are only allowed to play one premium or exclusive game per day.',
                    status=410
                )

        obj, created = UserGamePlayed.objects.select_related('game').get_or_create(
            user=user,
            game=game,
        )

        if user.subscription == SubscriptionPlan.FREE or not user.is_billed:
            if not created and \
                    now - obj.last_played_at >= timedelta(seconds=15) and \
                    obj.game.game_type == HTML5GameType.EXCLUSIVE:
                return HttpResponseForbidden(
                    'You are only allowed to play this game 1 time'
                )

        if not created:
            obj.last_played_at = now
            obj.count += 1
            obj.save()

        return XSendFile.serve_file(
            file_path=path,
            redirect_path=settings.NGINX_GAMES_REDIRECT_PATH,
            games_path=settings.GAMES_URL
        )
    else :
        return XSendFile.serve_file(
            file_path=path,
            redirect_path=settings.NGINX_GAMES_REDIRECT_PATH,
            games_path=settings.GAMES_URL
        )   

 


urlpatterns = [
    path(f'api/docs/',
         schema_view.with_ui('swagger', cache_timeout=0),
         name='schema-swagger-ui'),
    path('', include('engage.core.urls')),
    path('', include('engage.tournament.urls')),
    path('', include('engage.account.urls')),
    path('', include('engage.operator.urls')),
    path('jet', include('jet.urls', 'jet')),
    path("select2/", include("django_select2.urls")),
    path('admin/', admin.site.urls),
    re_path(r'^games/(.*)$', protected_games),
    url(r'^sitemap\.xml$',TemplateView.as_view(template_name='sitemap.xml',content_type='text/xml')),
    path("ads.txt",TemplateView.as_view(template_name="ads.txt", content_type="text/plain")),
    path("robots.txt",TemplateView.as_view(template_name="robots.txt", content_type="text/plain")),
    path("google2f20d53d86be3675.html",TemplateView.as_view(template_name="google2f20d53d86be3675.html",content_type='text/html')),
    path('i18n/', include('django.conf.urls.i18n')),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

