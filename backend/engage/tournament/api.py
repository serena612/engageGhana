import django_filters
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, F, Q, Prefetch, Case, When
from django.shortcuts import redirect
from django.utils import timezone
from rest_framework import mixins, viewsets, status, permissions, exceptions
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from django.db.models import Value
from engage.account.models import User
from engage.services import notify_when
from engage.core.constants import NotificationTemplate
from datetime import datetime, timedelta
from engage.account.constants import SubscriptionPackages, SubscriptionPlan
from uuid import uuid4
from engage.settings.base import API_SERVER_URL
import requests



from django.http import JsonResponse
from django.utils import timezone

from engage.account.exceptions import (
    GameAccountUnavailable,
    MinimumProfileLevelException
)
from .constants import TournamentState
from .exceptions import ParticipantExists, FreeUserCannotJoinTournament,TournamentCloseException,TournamentFirstException,TournamentStartException,UserInformException,UnbilledUserCannotJoinTournament,TournamentGetPrizeException
from .models import (
    Tournament,
    TournamentParticipant,
    TournamentPrize,
    TournamentMatch
)
from .serializers import (
    TournamentSerializer,
    TournamentParticipantSerializer,
    TournamentPrizeSerializer,
    TournamentWinnerSerializer
)
from ..tournament.models import get_prize
from ..core.models import Sticker
from ..operator.constants import SubscriptionType

import logging 


def send_sms(user, message, vault=None):
    headers = {'Content-type':'application/json', 
                'accept': 'text/plain'} # post data
    command = '/api/User/SendSms'
    if user.subscription==SubscriptionPlan.FREE:
        subs = SubscriptionPackages.FREE
    elif user.subscription==SubscriptionPlan.PAID1:
        subs = SubscriptionPackages.PAID1
    else:
        subs = SubscriptionPackages.PAID2
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

def test_page():
    headers = {'Content-type':'application/json', 
                'accept': 'text/plain'} # post data
    command = '/api/User/test'
    url = API_SERVER_URL+command
    
    try:
        api_call = requests.post(url, headers=headers,timeout=2)
    except requests.exceptions.RequestException as e:
        print(e)
        return 'Server error', 555
    if api_call.status_code==200:
        res = api_call.json()['statusCode']
        return res['message'], res['code']
    else:
        return api_call.content, api_call.status_code
    
class TournamentFilter(django_filters.FilterSet):
    state = django_filters.ChoiceFilter(choices=TournamentState.choices,
                                        method='filter_state')

    def filter_state(self, queryset, name, value):

        if value == TournamentState.UPCOMING:
            return queryset.upcoming()
        elif value == TournamentState.PAST:
            return queryset.past()
        elif value == TournamentState.ONGOING:
            return queryset.ongoing()

    class Meta:
        model = Tournament
        fields = ('state',)


class TournamentViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin,
                        viewsets.GenericViewSet):
    queryset = Tournament.objects.select_related('game').prefetch_related(
        'tournamentparticipant_set',
        Prefetch(
            'tournamentprize_set',
            queryset=TournamentPrize.objects.order_by('position')
        )
    )
    serializer_class = TournamentSerializer
    permission_classes = (permissions.AllowAny,)
    search_fields = ('name',)
    ordering_fields = ['created', 'start_date']
    lookup_field = 'slug'


    def get_queryset(self):
        user = self.request.user
        now = timezone.now()
        queryset = self.queryset.filter(regions__in=[self.request.region])


        if self.action in ['start', 'join', 'close']:
            return queryset.all()

        state = self.request.query_params.get('state', TournamentState.UPCOMING)
        game = self.request.query_params.get('game', 0)
        if game != '0' :
            queryset = queryset.filter(game__id=int(game))
        
              # if user.is_authenticated :
            # queryset = queryset.filter(Q(open_date__lte=now) |
            #                            Q(Q(minimum_profile_level__lte=user.level) | Q(minimum_profile_level__isnull=True))
                                       
            # ).order_by('open_date')
        
        if not user.is_authenticated:
            queryset = queryset.filter(
                free_open_date__lte=now,
            ).order_by('free_open_date')
            
        # if not user.is_subscriber:
        else :
            queryset = queryset.annotate(
                is_min_level=Case(
                    When(Q(minimum_profile_level__isnull=False) &
                         Q(minimum_profile_level__gt=user.level),
                         then=False),
                    default=True
                )
            ).filter(
                 Q(free_open_date__lte=now) |
                (Q(Q(minimum_profile_level__lte=user.level) | Q(minimum_profile_level__isnull=True)) & Q(free_open_date__gt=now))
            ).filter(open_date__lte=now).order_by('free_open_date')

        if self.action == 'list':
            if state == TournamentState.UPCOMING:
                tournaments = queryset.filter(end_date__gte=now,started_on__isnull=True)
            elif state == TournamentState.PAST:
                tournaments =  queryset.filter(end_date__lt=now)
            elif state == TournamentState.ONGOING:
                tournaments = queryset.filter(end_date__gt=now,started_on__isnull=False)
            else:
                tournaments =  queryset.all() 
        else:
            tournaments =  queryset.all() 

    
        return  tournaments  

            

    @action(methods=['GET'], detail=True, permission_classes=(permissions.IsAdminUser,))
    @transaction.atomic()
    def start(self, request, slug):
        tournament = self.get_object()
        
        
        if tournament.started_on:
            raise TournamentStartException() 

        room_size = tournament.game.room_size
        participants = tournament.tournamentparticipant_set.all()
        count = participants.count()

        if not count:
            raise TournamentFirstException()
           
        if not room_size:
            return redirect(request.META["HTTP_REFERER"])

        # for k, i in enumerate(range(0, count, room_size), 1):
        #     TournamentMatch.objects.create( 
        #         tournament=tournament,
        #         match_name=f'[Round 1] Match {k}',
        #         round_number=1,
        #     )

        tournament.started_on = timezone.now()
        tournament.save()

        return redirect(request.META["HTTP_REFERER"])
    

    @action(methods=['GET'], detail=True, permission_classes=(permissions.IsAdminUser,))
    @transaction.atomic()
    def close(self, request, slug):
        is_closed = False
        tournament = self.get_object()
        

        prizes = tournament.tournamentprize_set.filter(winner__isnull=True)
        count = prizes.count()

        if count :
            raise TournamentCloseException()

        for tournament_prize in prizes :
            winner = tournament_prize.winner
            prize_type = tournament_prize.prize_type
            if prize_type == 'cash':
                prize = tournament_prize.cash_amount
            else:
                prize = tournament_prize.actual_data_package
            if not get_prize(winner.mobile, prize, prize_type, winner.subscription,tournament.id):
                is_closed = True
                
            
        
        tournament.end_date = timezone.now()
        tournament.closed_on = timezone.now()
        tournament.save()
        tournament.send_notification_close()
        if is_closed == True:
           return Response(
                {"detail": "Tournament closed but error in granting prizes, please check with technical team!"},
                status=status.HTTP_406_NOT_ACCEPTABLE
            )
        return redirect(request.META["HTTP_REFERER"])


    @action(methods=['POST'], detail=True, permission_classes=(permissions.IsAuthenticated,))
    def join(self, request, slug):
        now = timezone.now()
        tournament = self.get_object()
        user = request.user
        linked_account = user.usergamelinkedaccount_set.filter(
            game=tournament.game
        ).first()
        if not linked_account:
            raise GameAccountUnavailable()

        if not tournament.allow_free_users:
            if user.subscription == SubscriptionType.FREE: 
                raise FreeUserCannotJoinTournament()
            elif user.is_billed == False:
                raise UnbilledUserCannotJoinTournament()

        if tournament.minimum_profile_level and \
                tournament.minimum_profile_level > user.level and tournament.free_open_date > now:
            raise MinimumProfileLevelException()

        is_waiting_list = False
        if tournament.current_participants() >= tournament.max_participants:
            is_waiting_list = True
    
        try:
            participant = TournamentParticipant.objects.get_or_create(
                tournament=tournament,
                participant=user,
                defaults={
                    'is_waiting_list': is_waiting_list
                }
            )
        except IntegrityError:
            raise ParticipantExists()


        # if tournament.give_sticker:
        #     if user.stickers.all() :
        #         sticker = Sticker.objects.filter(
        #             ~Q(id__in=user.stickers.all())
        #         ).order_by('?').first()
        #         if sticker :
        #             user.stickers.add(sticker)
        #             user.save()

        if is_waiting_list:
            return Response(
                {"code": "waiting_list",
                 "message": "You have been added to the waiting list."},
                status=status.HTTP_200_OK
            )

        return Response(status=status.HTTP_200_OK)

    # TODO: must be fixed and updated on the frontend
    @action(detail=False, methods=['get'], permission_classes=(permissions.AllowAny,))
    def get_participants(self, request):
        slug = self.request.query_params.get('slug', None)

        if not slug:
            return Response(status=status.HTTP_404_NOT_FOUND)

        try:
            tournament = Tournament.objects.get(
                slug=slug,
                regions__in=[request.region]
            )

        except Tournament.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        participants = tournament.participants()


        page_number = self.request.query_params.get('page', 1)
        page_size = self.request.query_params.get('size', 20)

        paginator = Paginator(participants, page_size)
        try:
            participants = paginator.page(int(page_number))
        except:
            participants = paginator.page(1)

        serializer = TournamentParticipantSerializer(participants, many=True)
        return Response({
            "data": serializer.data,
            "pagination": {
                "has_next": participants.has_next()
            }
        })

   
    @action(detail=False, methods=['get'], permission_classes=(permissions.AllowAny,))
    def get_tournaments(self, request):
        page_number = self.request.query_params.get('page', 1)
        page_size = self.request.query_params.get('size', 6)
        state = self.request.query_params.get('state', TournamentState.UPCOMING)
        game = self.request.query_params.get('game', 0)
        user = self.request.user
        now = timezone.now()
        tournament_list =  Tournament.objects.select_related('game').prefetch_related(
                'tournamentparticipant_set',
                Prefetch(
                    'tournamentprize_set',
                    queryset=TournamentPrize.objects.order_by('position')
                ))
        tournament_list = gettour(user,tournament_list,self.request.region)
        if game != '0' :
            tournament_list = tournament_list.filter(game__id=int(game))
        
        upcoming = tournament_list.filter(end_date__gte=now,started_on__isnull=True).order_by('start_date')
        ongoing = tournament_list.filter(end_date__gt=now,started_on__isnull=False).order_by('-live_null', 'start_date')
        previous = tournament_list.filter(end_date__lt=now)
        exceptprevioustournaments = list(ongoing) + list(upcoming)
        if state == TournamentState.UPCOMING:
            tournaments = upcoming
        elif state == TournamentState.PAST:
            tournaments =  previous
        elif state == TournamentState.ONGOING:
            tournaments = ongoing
        else:
            tournaments = list(exceptprevioustournaments)  # tournament_list.all().order_by('id')  # added order to remove warning

        
        paginator = Paginator(tournaments, page_size)
        all_paginator = Paginator(exceptprevioustournaments, page_size)
        try:
            tournaments = paginator.page(int(page_number))
            exceptprevioustournaments = all_paginator.page(int(page_number))
        except:
            tournaments = paginator.page(1)
            exceptprevioustournaments = all_paginator.page(1)
            
        serializer = TournamentSerializer(paginator.page(int(page_number)), many=True, context={'requesto': request})
        upcomingserializer = TournamentSerializer(upcoming, many=True, context={'requesto': request})
        allserializer = TournamentSerializer(exceptprevioustournaments, many=True, context={'requesto': request})
        return  Response({
            "data": serializer.data,
            "tournaments": upcomingserializer.data,
            "all_serializer": allserializer.data,
            "pagination": {
                "pages":paginator.num_pages,
                "all_pages":all_paginator.num_pages
            },
            
        })  

    
    @action(detail=False, methods=['get'], permission_classes=(permissions.AllowAny,))
    def get_tournaments2(self, request):
        user = self.request.user
       
        search = self.request.query_params.get('search',None)
       
        queryset = Tournament.objects.all().order_by('name')
        tournament_list = queryset
        tournament_list = gettour(user,tournament_list,self.request.region)
        tournament_list=tournament_list.filter(name__icontains=search)
        
        serializer = TournamentSerializer(tournament_list,many=True, context={'requesto': request})
        return  Response({
            "data": serializer.data,
            
        
        })  
    
    @action(methods=['POST'], detail=False, permission_classes=(permissions.IsAdminUser,))
    @transaction.atomic()
    def inform_participants(self, request):
        tourid = request.data.get('tourid')
        matchid = int(request.data.get('formid'))
        if not tourid:
            return Response(status=status.HTTP_404_NOT_FOUND)

        try:
            tournament = Tournament.objects.get(
                id=tourid,
                regions__in=[request.region]
            )

        except Tournament.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        matches = TournamentMatch.objects.filter(tournament=tournament).order_by('id').all()
        match = matches[matchid]
        participids = request.data.get('participants').split(',')
        print(participids)
        if not participids :
            raise UserInformException()
        # only select uninformed participants
        tourparts = TournamentParticipant.objects.filter(tournament=tournament, participant__in=participids).exclude(matches_informed=match)  # is_informed=False
        partic = tourparts.values_list('participant', flat=True)
        participants = User.objects.filter(id__in=partic)  # participids
        
        
        count = participants.count()
        print(participants, count)
        if count>0:
            #sched = "Match Schedule for "+tournament.name
            
            # for match in matches:
            #sched+="<br/>Round "+str(match.round_number)+" - Match "+match.match_name
            #sched+="<br/>Start: "+str(match.start_date)

            #sched=str(match.start_date)

            sched = (match.start_date+timedelta(hours=1)).strftime("%Y/%m/%d %H:%M")+" Lagos"
            
            stri_repl = {}
            stri_repl['MATCH_SCHEDULE'] = sched
            stri_repl['TOURNAMENT_NAME'] = match.tournament.name
            stri_repl['STARTDATE'] = sched
            
            
            for user in participants:
                @notify_when(events=[NotificationTemplate.MATCH_SCHEDULE], is_route=False,
                        is_one_time=False, str_repl=stri_repl)
                def notify(user, user_notifications):
                    """ extra logic if needed """
                    for notificationi in user_notifications:
                        print("inside notificationi")
                        notificationi.text=notificationi.notification.text.replace('TOURNAMENT_NAME',match.tournament.name).replace('STARTDATE',sched)
                        print(notificationi.text)
                        notificationi.save()
                        resp, code = send_sms(user, notificationi.text)
                        print(resp, code)
                notify(user=user)

            #for user in participants:
            #    notify(user=user)

            print("tourparts", tourparts)
            print(tourparts.values_list('matches_informed', flat=True))
            # tourparts.matches_informed.add(*match)  # add match to informed
            StudentClass = TournamentParticipant.matches_informed.through
            items = [
                StudentClass(tournamentmatch_id=match.pk, tournamentparticipant_id=student.pk)
                for student in tourparts
            ]

            StudentClass.objects.bulk_create(items)
            if count==1:
                return Response("1 participant has been informed", status=status.HTTP_200_OK)
            else:
                return Response(str(count)+" participants have been informed", status=status.HTTP_200_OK)
        else:
            return Response("All participants have already been informed", status=status.HTTP_200_OK)
        
        
        

def gettour(user,tournament_list,region):
    
  
    now = timezone.now()
   
       
    if not user.is_authenticated:
            tournament_list = tournament_list.filter(
                free_open_date__lte=now,
            ).annotate(live_null=Count('live_link'),started_null=Count('started_on')) 
    else :
            tournament_list = tournament_list.annotate(
                is_min_level=Case(
                    When(Q(minimum_profile_level__isnull=False) &
                         Q(minimum_profile_level__gt=user.level),
                         then=False),
                    default=True
                )
            ).filter(
                Q(free_open_date__lte=now) |
                (Q(Q(minimum_profile_level__lte=user.level) | Q(minimum_profile_level__isnull=True)) & Q(free_open_date__gt=now))
            ).filter(open_date__lte=now).annotate(live_null=Count('live_link'),started_null=Count('started_on'))
  
    return tournament_list.filter(regions__in=[region])



def get_event_datetime(request):
    event_datetime = timezone.datetime(2023, 5, 10, 12, 0, tzinfo=timezone.utc)
    return JsonResponse({"event_datetime": event_datetime.isoformat()})
    
 
   





class TournamentPrizeViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = TournamentPrize.objects.select_related(
        'tournament').exclude(image='')
    serializer_class = TournamentPrizeSerializer
    permission_classes = (permissions.AllowAny,)
    filterset_fields = ('prize_type',)

    def get_queryset(self):
        now = timezone.now()
        user = self.request.user
        prize_list = self.queryset.filter(
            tournament__regions__in=[self.request.region],
            tournament__end_date__gt=now
        ).exclude(image='')
        if not user.is_authenticated:
            prize_list = prize_list.filter(
                tournament__free_open_date__lte=now,
            )
        else:
            prize_list = prize_list.filter(
                Q(tournament__free_open_date__lte=now) |
                (Q(Q(tournament__minimum_profile_level__lte=user.level) | Q(tournament__minimum_profile_level__isnull=True)) & Q(tournament__free_open_date__gt=now))
            ).filter(tournament__open_date__lte=now)
        return prize_list


class TournamentWinnerViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = TournamentPrize.objects.all()
    serializer_class = TournamentWinnerSerializer
    permission_classes = (permissions.AllowAny,)

    # def list(self, request, *args, **kwargs):
    #     try:
    #         game = request.query_params['game']
    #     except KeyError:
    #         raise ValidationError('Game parameter is missing')

    #     queryset = TournamentPrize.objects.filter(
    #         winner__isnull=False,
    #         tournament__game__slug__iexact=game,
    #         tournament__regions__in=[request.region]
    #     ).values('winner').annotate(
    #         winner_name=F('winner__nickname'),
    #         win_count=Count('winner')
    #     ).values('winner_name').order_by('-win_count').all()[:10]

    #     return Response(list(queryset), status=status.HTTP_200_OK)


    def list(self, request, *args, **kwargs):
       
        game = request.query_params.get('game',None)
        tournament = request.query_params.get('tournament', None)

        
        if game and game!= '':
            queryset = TournamentPrize.objects.filter(
                winner__isnull=False,
                tournament__id=tournament,
                tournament__game__slug__iexact=game,
                tournament__regions__in=[request.region]
            ).values('winner').annotate(
                winner_name=F('winner__nickname'),
                win_count=Count('winner')
            ).values('winner_name').order_by('position').all()	
        else :
            queryset = TournamentPrize.objects.filter(
                winner__isnull=False,
                tournament__id=tournament,
                tournament__regions__in=[request.region]
            ).values('winner').annotate(
                winner_name=F('winner__nickname'),
                win_count=Count('winner')
            ).values('winner_name').order_by('position').all()	
        return Response(list(queryset), status=status.HTTP_200_OK)
