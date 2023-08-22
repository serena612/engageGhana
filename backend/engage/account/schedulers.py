from datetime import timedelta

from celery import shared_task
from django.utils import timezone
from ..celery import block_multiple_celery_task_execution
from .models import User, Profile, UserActivity
from engage.services import notify_when
from engage.core.constants import NotificationTemplate
from ..core.models import Notifications

"""
    cases >>> HOW_TO_USE
        1. Day 1 of joining and 5 days later if user is still dormant
    
    RUN_EVERY >> 12 hours
"""
@shared_task(bind=True)
def how_to_use_notification(self):
    prefix = "how_to_use_notification"
    if block_multiple_celery_task_execution(self, prefix):
        return
    now = timezone.now()

    users = User.objects.filter(
        last_seen__range=[now - timedelta(days=5, hours=12), now - timedelta(days=5)]
    ).all()

    for user in users:

        was_active = UserActivity.objects.was_active_between(user, [(
            now - timedelta(days=day)).strftime('%Y-%m-%d') for day in range(1, 6)])

        if not was_active:
            # send the last 5 days was un active notifications
            @notify_when(events=[NotificationTemplate.HOW_TO_USE], is_route=False)
            def notify(user):
                """ extra logic if needed """

            notify(user)

"""
    cases >>> ACTIVE_X_DAYS
        1. 5 active days after joining	
        2. 10 active days after joining	
        3. 30 active days after joining	

    RUN_EVERY >> 24 hours
"""
@shared_task(bind=True)
def active_days_notification(self):
    prefix = "active_days_notification"
    if block_multiple_celery_task_execution(self, prefix):
        return
    active_templates = [
        {"name": NotificationTemplate.ACTIVE_5_DAYS, "active_days": 5},
        {"name": NotificationTemplate.ACTIVE_10_DAYS, "active_days": 10},
        {"name": NotificationTemplate.ACTIVE_30_DAYS, "active_days": 30},
    ]

    for active_template in active_templates:
        now = timezone.now()

        users = User.objects.filter(
            date_joined__range=[
                now - timedelta(days=active_template["active_days"], hours=12),
                now - timedelta(days=active_template["active_days"])
            ]
        ).all()

        for user in users:
            was_all_active = UserActivity.objects.was_all_active_between(user, [(
                now - timedelta(days=day)).strftime('%Y-%m-%d') for day in range(1, active_template["active_days"] + 1)])
            
            if was_all_active:
                @notify_when(events=[active_template["name"]], is_route=False)
                def notify(user):
                    """ extra logic if needed """

                notify(user)

"""
    cases >>> HAPPY_BIRTHDAY
        1. If user fills out exact DOB

    RUN_EVERY >> AFTER START OF DAY >> LET'S SAY (EVERY DAY ON 12:05 AM)
"""
@shared_task(bind=True)
def happy_birthday_notification(self):
    prefix = "happy_birthday_notification"
    if block_multiple_celery_task_execution(self, prefix):
        return
    now = timezone.now()

    users_profile = Profile.objects.select_related('user').filter(
        birthdate__month=now.month, birthdate__day=now.day
    ).all()

    # send happy birthday notification
    @notify_when(events=[NotificationTemplate.HAPPY_BIRTHDAY], is_route=False,
                 is_one_time=False)
    def notify(user, user_notifications):
        """ extra logic if needed """

    for user_profile in users_profile:
        notify(user=user_profile.user)

"""
    cases >>> ONCE_A_MONTH

    RUN_EVERY >> first day of month
"""
@shared_task(bind=True)
def once_a_month_notification(self):
    prefix = "once_a_month_notification"
    if block_multiple_celery_task_execution(self, prefix):
        return
    users = User.objects.all()

    @notify_when(events=[NotificationTemplate.ONCE_A_MONTH], is_route=False,
                 is_one_time=False)
    def notify(user, user_notifications):
        """ extra logic if needed """

    for user in users:
        notify(user=user)


@shared_task(bind=True)
def daily_event_check_notification(self):
    prefix = "daily_event_check_notification"
    if block_multiple_celery_task_execution(self, prefix):
        return
    now = timezone.now()

    notifications = Notifications.objects.filter(
        template=NotificationTemplate.EVENT,
        event_date__month=now.month,
        event_date__day=now.day,
        is_active=True,
    )
    users = User.objects.exclude(
        notifications__notification__in=notifications,
        notifications__created__day=now.day,
        notifications__created__month=now.month
    ).distinct().all()
    @notify_when(events=[NotificationTemplate.EVENT], is_route=False,
                 is_one_time=False, extra={'event_date': now})
    def notify(user, user_notifications):
        """ extra logic if needed """

    for user in users:
        notify(user)


@shared_task(bind=True)
def every_14_days_notifications(self):
    prefix = "every_14_days_notifications"
    if block_multiple_celery_task_execution(self, prefix):
        return
    now = timezone.now()

    pre_14_days = now - timedelta(days=14)

    users = User.objects.exclude(
        notifications__notification__template=NotificationTemplate.EVERY_14_DAYS,
        notifications__notification__is_active=True,
        notifications__created__lt=pre_14_days
    ).distinct().all()

    @notify_when(events=[NotificationTemplate.EVERY_14_DAYS],
                 is_route=False, is_one_time=False)
    def notify(user, user_notifications):
        """ extra logic if needed """

    for user in users:
        notify(user)



@shared_task(bind=True)
def check_users_level(self):
    prefix = "check_users_level"
    if block_multiple_celery_task_execution(self, prefix):
        return
    users = User.objects.all()
    for user in users:
        if user.is_billed == True:
            user.level+=1
            user.save()      

@shared_task(bind=True)
def update_joined_tournaments(self):
    prefix = "update_joined_tournaments"
    if block_multiple_celery_task_execution(self, prefix):
        return
    users = User.objects.all()
    for user in users:
        if user.tournament_joined_today == True:
            user.tournament_joined_today = False
            user.save()
