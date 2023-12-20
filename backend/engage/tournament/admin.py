from pyexpat.errors import messages
from django import forms
from django.contrib import admin
from django.utils.safestring import mark_safe
from engage.account.models import User
from engage.account.models import UserGameLinkedAccount
from jet.admin import CompactInline
from . import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.db.models import Subquery, OuterRef, TextField
from django.db.models.functions import Cast
from django.db.models import F, Q
from django.contrib import messages as messagesss
from django.forms.widgets import HiddenInput
from django.core.exceptions import ValidationError
from ..tournament.models import TournamentParticipant, get_prize
from parler.admin import TranslatableAdmin
from parler.admin import TranslatableTabularInline, TranslatableInlineModelAdmin, TranslatableStackedInline, TranslatableModelMixin, TranslatableModelForm, TranslatableBaseInlineFormSet

from parler.utils.context import switch_language
from django.forms.models import inlineformset_factory
from django.conf import settings
from django.forms.widgets import TextInput
from django.forms.models import BaseInlineFormSet


class TournamentPrizeInlineForm(TranslatableModelForm): #forms.ModelForm

    def clean(self):
        super(TournamentPrizeInlineForm, self).clean()
    #     if 'winner' in self.changed_data:  # we only try to grant prize if winner is changed, this is to prevent redundance
    #         winner = self.cleaned_data.get('winner')
    #         prize_type = self.cleaned_data.get('prize_type')
    #         if winner:
    #             if prize_type == 'cash':
    #                 prize = self.cleaned_data.get('cash_amount')
    #             else:
    #                 prize = self.cleaned_data.get('actual_data_package')
    #             if not get_prize(winner.mobile, prize, prize_type, winner.subscription):
    #                 raise ValidationError('Failed to give prize to selected winner. Please try saving again.')


class TournamentPrizeInline(CompactInline): #TranslatableStackedInline
    model = models.TournamentPrize
    min_num = 0
    form = TournamentPrizeInlineForm
    tournament = None
    extra = 0 

    def get_fields(self, request, obj=None):
        fields = super().get_fields(request, obj)
        if not obj:
            fields.remove('winner')
        return fields

    def get_formset(self, request, obj=None, **kwargs):
        if obj:
            self.tournament = obj
        return super().get_formset(request, obj, **kwargs)

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        formfield = super().formfield_for_foreignkey(db_field, request, **kwargs)
        if db_field.name == 'winner':
            # get last round
            ha = models.TournamentMatch.objects.filter(tournament=self.tournament).order_by('-round_number').first()
            if ha:
                lastround = ha.round_number
                winners = models.TournamentMatch.objects.filter(tournament=self.tournament).filter(round_number=lastround).values_list('winners',flat=True)
              
                formfield.queryset = formfield.queryset.filter(
                    tournamentparticipant__tournament=self.tournament
                ).filter(
                    tournamentmatch__round_number=lastround
                ).filter(is_staff=False).filter(pk__in=winners)
            else:
                formfield.queryset = formfield.queryset.filter(
                    tournamentparticipant__tournament=self.tournament
                ).filter(is_staff=False)
           
            subquery = UserGameLinkedAccount.objects.filter(user=OuterRef('id'), tournament=self.tournament)
            combined_query = formfield.queryset.annotate(
                    # tourn = Cast(Subquery(subquery.values('tournament')[:1]), output_field=TextField()),
                    gnickname = Cast(Subquery(subquery.values('account')[:1]), output_field=TextField())
                ).filter(is_staff=False)
            formfield.queryset = combined_query.distinct()
        return formfield

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        formfield = super().formfield_for_dbfield(
            db_field, request, **kwargs)
        if db_field.name == 'winner':
            formfield.widget.can_add_related = False
            formfield.widget.can_change_related = False
            formfield.widget.can_delete_related = False
        return formfield

class CustomTournamentParticipantForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def save(self, commit=True):
        mobile_number = self.cleaned_data.get('mobile_number')
        participant_id = User.objects.filter(mobile=mobile_number).values_list('participant', flat=True).first()
        if participant_id:
            participant = User.objects.get(id=participant_id)
            self.instance.participant = participant
        return super().save(commit=commit)
    
    class Meta:
        model = TournamentParticipant
        fields = '__all__'

class TournamentParticipantInline(CompactInline): #TranslatableStackedInline
    model = models.TournamentParticipant
    # readonly_fields = ('points', 'rank')
    exclude = ('notify_before_game', 'prize','points', 'rank', 'matches_informed','participant')
    min_num = 0
    extra = 0
    tournament = None
    formset = CustomTournamentParticipantForm    
#     def get_fields(self, request, obj=None):
#         fields = list(super().get_fields(request, obj=obj))
#         if obj is None:
#             fields.remove('participant')
#         return fields
    def get_formset(self, request, obj=None, **kwargs):
        if obj:
            self.tournament = obj
            
        return super().get_formset(request, obj, **kwargs)
    
    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        formfield = super().formfield_for_foreignkey(db_field, request, **kwargs)
        if db_field.name == 'participant':
            #linked_account_users = UserGameLinkedAccount.objects.filter(tournament=self.tournament).values_list('user', flat=True)
            #formfield.queryset = formfield.queryset.filter(id__in=linked_account_users, is_staff=False)
            #participant = models.User.objects.get(id=formfield.queryset.filter(id__in=linked_account_users, is_staff=False))
            
            
            #queryset = models.User.objects.filter(id__in=linked_account_users, is_staff=False)
            #kwargs['queryset'] = queryset
            
            
            #kwargs['widget'] = forms.TextInput(attrs={'readonly': 'readonly'})
            
            #kwargs['widget'] = TextInput()
            # Hide the default Select widget
            #kwargs['widget'].is_hidden = True
            subquery = UserGameLinkedAccount.objects.filter(user=OuterRef('id'), tournament=self.tournament)
            if self.tournament :
                formfield.queryset = formfield.queryset.filter(tournamentparticipant__tournament=self.tournament.id) \
                    .filter(is_staff=False)
                combined_query = formfield.queryset.annotate(
                        gnickname = Cast(Subquery(subquery.values('account')[:1]), output_field=TextField())
                    )
                formfield.queryset = combined_query.distinct()
                # print(formfield.queryset.values_list())
                #print("values=",formfield.queryset.values_list('pk', flat=True))
                # formfield.queryset = formfield.queryset# .filter(Q(usergamelinkedaccount__tournament_id=self.tournament.id) & Q(tournamentparticipant__status="accepted")) # .select_related('usergamelinkedaccount')
                # print(queryset)
        return formfield
        #return super().formfield_for_foreignkey(db_field, request, **kwargs)

    
    # def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
    #     formfield = super().formfield_for_foreignkey(db_field, request, **kwargs)
    #     if db_field.name == 'participant':
    #         kwargs['widget'] = TextInput()
    #     return super().formfield_for_foreignkey(db_field, request, **kwargs)
    #         # linked_account_users = UserGameLinkedAccount.objects.filter(tournament=self.tournament).values_list('user', flat=True)
    #         # formfield.queryset = formfield.queryset.filter(id__in=linked_account_users, is_staff=False)


    #         #subquery = UserGameLinkedAccount.objects.filter(user=OuterRef('id'), tournament=self.tournament)
    #         #combined_query = formfield.queryset.annotate(
    #                  # tourn = Cast(Subquery(subquery.values('tournament')[:1]), output_field=TextField()),
    #         #         gnickname = Cast(Subquery(subquery.values('account')[:1]), output_field=TextField())
    #         #     ).filter(is_staff=False)
    #         #formfield.queryset = combined_query
    #     #return formfield


    def formfield_for_dbfield(self, db_field, request, **kwargs):
        formfield = super().formfield_for_dbfield(
            db_field, request, **kwargs)
        if self.tournament and self.tournament.starts_in_full == "In Progress" and formfield is not None:
            formfield.disabled = True
        
        if db_field.name == 'participant':
            formfield.widget.can_add_related = False
            formfield.widget.can_change_related = False
            formfield.widget.can_delete_related = False
        return formfield
    
    def has_add_permission(self, request, obj=None):
        if obj and obj.starts_in_full == "In Progress":
            return False
        else:
            return False
    
    def has_delete_permission(self, request, obj=None):
        if obj and obj.starts_in_full == "In Progress":
            return False
        else:
            return True

    def get_formset(self, request, obj=None, **kwargs):
        if obj:
            self.tournament = obj
        return super().get_formset(request, obj, **kwargs)
    
    def clean(self):
        cleaned_data = super().clean()
        # Get the selected User instance from the form data
        mobile_number = cleaned_data.get('mobile_number')
        participant_id = models.User.objects.filter(mobile=mobile_number).values_list('participant', flat=True).first()
        if participant_id:
            participant = models.User.objects.get(id=participant_id)
            # Set the MSISDN value for the participant field
            msisdn_value = participant.mobile
            print("msisdn_value ",msisdn_value)
            self.cleaned_data['participant'] = f"{participant} ({msisdn_value})"
        return self.cleaned_data


    # def clean(self):
    #     cleaned_data = super().clean()
    #     # Get the selected User instance from the form data
    #     participant_id = cleaned_data.get('participant')
    #     if participant_id:
    #         participant = models.User.objects.get(id=participant_id)
        
    #         # Set the MSISDN value for the participant field
    #         msisdn_value = participant.mobile
    #         print("msisdn_value ",msisdn_value)
    #         self.cleaned_data['participant'] = f"{participant} ({msisdn_value})"
    #     return self.cleaned_data

    #old function before adding mobile number to the tournament participant tab in cms 
    # def clean(self):
    #     super().clean()
    #     for form in self.forms:
    #         participant_id = form.cleaned_data.get('participant')
    #         if participant_id:
    #             # Retrieve the MSISDN value for the selected participant
    #             msisdn = models.User.objects.filter(id=participant_id).values_list('msisdn', flat=True).first()
    #             form.cleaned_data['participant'] = f'{participant_id} ({msisdn})'
    
    

    #new function after adding mobile number to the tournament participant tab in cms
    def clean(self):
        super().clean()
        for form in self.forms:
            mobile_number = form.cleaned_data.get('mobile_number')
            if mobile_number:
                # Retrieve the participant id  value from  the  mobile number
                participant_id = models.User.objects.filter(mobile=mobile_number).values_list('participant', flat=True).first()
                form.cleaned_data['participant'] = f'{participant_id} ({mobile_number})'
    

    # def has_change_permission(self, request, obj=None):
    #     if not obj:
    #         return False
    #     elif obj.state != "upcoming":
    #         return False
    #     else:
    #         return True
    class Meta:
        model = models.TournamentParticipant
        fields = '__all__'
        widgets = {
            'participant': TextInput(attrs={'readonly': 'readonly'}),
        }


        
class TournamentMatchInlineForm(TranslatableModelForm): #forms.ModelForm
    def __init__(self, *args, **kwargs):
        super(TournamentMatchInlineForm, self).__init__(*args, **kwargs)
        
        if 'winners' in self.fields and 'instance' in kwargs:
            if kwargs['instance'].round_number >1:
                match_winners = models.TournamentMatch.objects.filter(tournament=kwargs['instance'].tournament).filter(round_number=int(kwargs['instance'].round_number)-1).values_list('winners',flat=True)
                
             
                self.fields['participants'].queryset = self.fields['participants'].queryset.filter(pk__in=match_winners)
                self.fields['winners'].queryset = self.fields['winners'].queryset.filter(pk__in=match_winners)
             
            part_round = self.fields['participants'].queryset.filter(Q(participanto__round_number=kwargs['instance'].round_number) & Q(participanto__tournament=kwargs['instance'].tournament)).values_list('pk', flat=True)
            part_match = self.fields['participants'].queryset.filter(participanto=kwargs['instance'].id)

            self.fields['participants'].queryset = self.fields['participants'].queryset.exclude(pk__in=part_round)
            self.fields['participants'].queryset = self.fields['participants'].queryset | part_match
            # self.fields['participants'].queryset = self.fields['participants'].queryset.exclude((Q(participanto__round_number=kwargs['instance'].round_number) & Q(participanto__tournament=kwargs['instance'].tournament)) & ~Q(participanto=kwargs['instance'].id)).distinct()
            self.fields['winners'].queryset = self.fields['winners'].queryset.filter(participanto=kwargs['instance'].id).distinct()
           
        elif 'winners' in self.fields:
            self.fields['participants'].queryset = self.fields['participants'].queryset.none() # self.fields['participants'].queryset.distinct()
            self.fields['winners'].queryset = self.fields['winners'].queryset.none() # self.fields['winners'].queryset.distinct()
            self.fields["participants"].widget = HiddenInput()
            self.fields["winners"].widget = HiddenInput()
            self.fields["image"].widget.attrs.update({'hidden': True})

    def clean(self):
        """
        This is the function that can be used to 
        validate your model data from admin
        """
        super(TournamentMatchInlineForm, self).clean()
        winners = self.cleaned_data.get('winners')
        image = self.cleaned_data.get('image')

        # The logic you were trying to filter..
        if winners and winners.all() and not image:
            raise ValidationError({
                'image': _('An image is required when winners are specified')
            })
        if 'start_date' in self.changed_data:
            # we set informed flag to zero if any field is updated
            # tourparts = models.TournamentParticipant.objects.filter(tournament=self.instance.tournament, matches_informed=self.instance)
            StudentClass = models.TournamentParticipant.matches_informed.through
            StudentClass.objects.filter(tournamentmatch=self.instance).delete()
            # tourparts.matches_informed.remove(self.instance)
                        
            
    # class Meta:
    #     model = models.TournamentMatch
    #     fields = "__all__"
    #     widgets = {
    #         "participants": ParticipantsWidget,  # (attrs={'style': 'width: 100% !important', 'class':'multiselect dropdown-toggle mt-multiselect',})
    #         "winners": ParticipantsWidget,  # (attrs={'style': 'width: 100% !important', 'class':'multiselect dropdown-toggle mt-multiselect',})
    #     }

class RequiredFormSet(TranslatableBaseInlineFormSet): #forms.models.BaseInlineFormSet
    def __init__(self, *args, **kwargs):
        super(RequiredFormSet, self).__init__(*args, **kwargs)
    def clean(self):

        super(RequiredFormSet, self).clean()
        try:
            querysets = [[form.cleaned_data['participants'].all(), form.cleaned_data['round_number']] for form in self.forms]
        except:
            return
        combined = [[item, sublist[1]] for sublist in querysets for item in sublist[0]]
        #print(combined)

        seen = set()
        dups = [x for x in combined if tuple(x) in seen or seen.add(tuple(x))]  
        #print("Repeated: ", dups)
        if len(dups)>0:
            raise ValidationError([{
                'participants': _('Participant(s): '+ ", ".join([dup[0].username for dup in dups]) +' is/are repeated!')
            }])


class TournamentMatchInline(CompactInline): #TranslatableStackedInline
    model = models.TournamentMatch
    form = TournamentMatchInlineForm
    formset = RequiredFormSet
    # readonly_fields = ('id',)
    exclude = ('match_data', 'id',)
    tournament = None
    extra = 0
    min_num = 0
    

    def get_fields(self, request, obj=None):
        fields = list(super().get_fields(request, obj=obj))
        if obj is None:
            fields.remove('winners')
            fields.remove('participants')
            fields.remove('image')
        return fields
    
    def get_formset(self, request, obj=None, *args, **kwargs):
        if obj:
             self.tournament = obj
        return super().get_formset(request, obj, *args, **kwargs)
   

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        formfield = super().formfield_for_foreignkey(db_field, request, **kwargs)
        if db_field.name == "participants" or db_field.name == "winners":
            # print('instance', kwargs['instance'])
            if self.tournament:
                subquery = UserGameLinkedAccount.objects.filter(user=OuterRef('id'), tournament=self.tournament)
                
                # matches = models.TournamentMatch.objects.filter(tournament=self.tournament.id).values_list('pk', flat=True)
                # formfield.queryset = formfield.queryset.filter(participanto__in=matches)
                #print("values before=",formfield.queryset.values_list('pk', flat=True))
                formfield.queryset = formfield.queryset.filter(__tournament=self.tournament.id) \
                .filter(__status="accepted").filter(is_staff=False).filter(tournamentparticipant__is_waiting_list=False)
                combined_query = formfield.queryset.annotate(
                    # tourn = Cast(Subquery(subquery.values('tournament')[:1]), output_field=TextField()),
                    gnickname = Cast(Subquery(subquery.values('account')[:1]), output_field=TextField())
                )
                formfield.queryset = combined_query.distinct()
                # print(formfield.queryset.values_list())
                #print("values=",formfield.queryset.values_list('pk', flat=True))
                # formfield.queryset = formfield.queryset# .filter(Q(usergamelinkedaccount__tournament_id=self.tournament.id) & Q(tournamentparticipant__status="accepted")) # .select_related('usergamelinkedaccount')
                # print(queryset)
        return formfield
    
    def formfield_for_dbfield(self, db_field, request, **kwargs):
        formfield = super().formfield_for_dbfield(
            db_field, request, **kwargs)
        if self.tournament and db_field.name == "round_number":
            rounds = self.tournament.rounds_number
            formfield.choices = formfield.choices[:rounds+1]
        return formfield


@admin.register(models.Tournament)
class TournamentAdmin(TranslatableAdmin): #admin.ModelAdmin  #TranslatableAdmin
    # list_display = ('name', 'game', 'start_date', 'end_date', 'start','close')
    # exclude = ('slug', 'job_id', 'created_by','format')
    # inlines = [TournamentMatchInline, TournamentPrizeInline,
    #            TournamentParticipantInline,]

    list_display = ('name', 'game', 'start_date', 'end_date', 'start', 'close')
    exclude = ('slug', 'job_id', 'created_by', 'format')
    inlines = [TournamentMatchInline, TournamentPrizeInline,] #TournamentParticipantInline,]
    
    def get_formset(self, request, obj=None, **kwargs):
        formset = super().get_formset(request, obj, **kwargs)
        formset.form = TournamentParticipantInlineFormSet
        return formset
    

    def change_view(self, request, object_id, extra_context=None):
        extra_context = extra_context or {}
         #print(object_id) # test
         # print(models.Tournament.objects.filter(id=object_id).first().starts_in_full)
        if object_id and models.Tournament.objects.filter(id=object_id).first().starts_in_full == 'In Progress':
            extra_context['state'] = 'true'
        else:
            extra_context['state'] = 'false'
        return super(TournamentAdmin, self).change_view(request, object_id, extra_context=extra_context)    

    def start(self, obj):
        now = timezone.now()
        if obj.started_on and obj.end_date > now and not obj.closed_on:
            return mark_safe('<span>ongoing</span>')
        elif obj.end_date > now and not  obj.started_on:
            return mark_safe(
                f'<a class="grp-state-focus addlink a_start" data-link="/api/tournaments/{obj.slug}/start/" style="cursor:pointer">Start</a>'
            )
    start.short_description = ''
    start.allow_tags = True

    def close(self, obj):
        now = timezone.now()
        if obj.started_on and obj.end_date > now and not obj.closed_on:
            return mark_safe(
                f'<a class="grp-state-focus addlink a_close"  data-link="/api/tournaments/{obj.slug}/close/" style="cursor:pointer">End</a>'
            )
        elif  obj.started_on and  obj.closed_on:
            return mark_safe('<span>closed</span>')  

    close.short_description = ''
    close.allow_tags = True
    
    def formfield_for_dbfield(self, db_field, request, **kwargs):
        formfield = super().formfield_for_dbfield(
            db_field, request, **kwargs)



        # if self.tournament is not None and self.tournament.state != "upcoming" and formfield is not None:
        #     formfield.disabled = True
        
        if db_field.name == 'game':
            formfield.widget.can_add_related = False
            formfield.widget.can_change_related = False
            formfield.widget.can_delete_related = False
        return formfield

    class Media:
        css = { 'all': ('admin/tournament/bootstrap-4.5.2.min.css', 'css/bootstrap-multiselect.css', 'css/tournament.css')} # 
        js = ('admin/tournament/select2.min.js', 'admin/tournament/bootstrap-multiselect.js', 'admin/tournament/base.js','admin/tournament/moment.min.js', ) # 'admin/tournament/select2.min.js', # 'js/bootstrap-multiselect.js', , 'admin/tournament/select2.multi-checkboxes.js'
    


        
