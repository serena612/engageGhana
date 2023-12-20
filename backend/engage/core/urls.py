from django.urls import path, include
from rest_framework.routers import SimpleRouter

from . import api, views


router = SimpleRouter()
router.register('avatars', api.AvatarViewSet)
router.register('html5_games', api.HTML5GameViewSet)
router.register('contact', api.ContactViewSet, basename='contact')
router.register('featured_games', api.FeaturedGameViewSet)


urlpatterns = [
    path('', views.empty_view, name='empty'),
    path('home', views.home_view, name='home'),
    path('home_test', views.hometest_view, name='home_test'),
    path('no_winners', views.nowinners_view, name='no_winners'),
    path('secured', views.secured_view, name='secured'),
    path('about', views.about_view, name='about'),
    path('faq', views.faq_view, name='faq'),
    path('headers', views.header_view, name='headers'),
    path('terms', views.terms_view, name='terms'),
    path('privacy', views.privacy_view, name='privacy'),
    path('disclaimer', views.disclaimer_view, name='disclaimer'),
    path('html5/<str:game>', views.html5_game_view, name='html5game'),
    # path('register', views.register_view, name='register'),
    path('wait', views.waiting_view, name='wait'),
    path('clear', views.clear_session_view, name='clear'),
    path('newregister', views.new_register_view, name='new_register'),
    path('testregister', views.test_register_view, name='test_register'),
    path('report_prize', views.report_prize_view, name='report_prize'),
    path('report_cash', views.report_cash_view, name='report_cash'),
    path('report_datasync', views.report_datasync_view, name='report_datasync'),
    path('report_subunsub', views.report_subunsub_view, name='report_subunsub'),
    path('report_sms', views.report_sms_view, name='report_sms'),
    path('report_generalreport', views.report_generalreport_view, name='report_generalreport'),
    path('report_redeemedprizes', views.report_redeemedprizes_view, name='report_redeemedprizes'),
    # firebase
    path('firebase-messaging-sw.js', views.firebase_sw_view),
    path('api/', include(router.urls)),
]