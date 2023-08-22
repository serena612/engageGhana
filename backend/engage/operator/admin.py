from django.contrib import admin
from django.forms import ModelForm
from jet.admin import CompactInline
from parler.admin import TranslatableAdmin, TranslatableModelForm, TranslatableStackedInline

from .models import (
    Operator,
    OperatorAd,
    OperatorFaq,
    OperatorWebsite,
    OperatorHomeSection,
    Region,
    PurchaseCoin,
    RedeemPackage,
    SubConfiguration
)
from ..core.fields import SVGAndImageFormField
# -*- coding: utf-8 -*-
from django.contrib import messages

class OperatorHomeSectionModelForm(TranslatableModelForm): #ModelForm
    class Meta:
        model = OperatorHomeSection
        exclude = []
        field_classes = {
            'icon': SVGAndImageFormField,
        }

class OperatorFaqModelForm(TranslatableModelForm): #ModelForm
    class Meta:
        model = OperatorFaq
        exclude = []
        fields = '__all__'
#        field_classes = {
#            'icon': SVGAndImageFormField,
#        }

class RedeemPackageModelForm(TranslatableModelForm): #ModelForm
    class Meta:
        model = RedeemPackage
        exclude = []
        field_classes = {
            'icon': SVGAndImageFormField,
        }

class OperatorFaqInline(CompactInline):
    model = OperatorFaq
    form = OperatorFaqModelForm


class OperatorWebsiteInline(TranslatableStackedInline): # admin.StackedInline
    model = OperatorWebsite
    min_num = 1
    max_num = 1


class OperatorHomeSectionInline(CompactInline):
    model = OperatorHomeSection
    form = OperatorHomeSectionModelForm
    show_change_link = True
    can_delete = True
    min_num = 1


class PurchaseCoinInline(CompactInline):
    model = PurchaseCoin
    exclude = ('uid',)
    min_num = 1


class RedeemPackageInline(CompactInline):
    model = RedeemPackage
    form = RedeemPackageModelForm
    exclude = ('uid',)
    min_num = 1

class SubConfigurationInline(CompactInline):
    model = SubConfiguration
    exclude = ('uid',)
    min_num = 1

    def has_add_permission(self, request, obj=None):
        if obj and obj.starts_in_full == "In Progress":
            return False
        else:
            return False

@admin.register(Operator)
class OperatorAdmin(TranslatableAdmin):  #admin.ModelAdmin
    list_display = ('name', 'region', 'created')
    exclude = ('schema',)
    inlines = [
        OperatorWebsiteInline,
        OperatorHomeSectionInline,
        OperatorFaqInline,
        RedeemPackageInline,
        PurchaseCoinInline,
        SubConfigurationInline
    ]

    def change_view(self, request, object_id, form_url='', extra_context=None):
        extra_context = extra_context or {}
        extra_context['show_save_and_add_another'] = False
        extra_context['show_delete'] = False
        try:
            return super().change_view(request, object_id, form_url, extra_context=extra_context)
        except Exception as e:
            # Log the error or display it using Django's messages framework
            messages.error(request, f"Error while saving: {str(e)}")
            # You can also log the error to a log file or console for debugging purposes.
            # logger.error(f"Error while saving Operator (ID: {object_id}): {str(e)}")
            return self.response_error(request, e)
        
        # return super().change_view(request, object_id, form_url,
        #                            extra_context=extra_context)
        


@admin.register(Region)
class RegionAdmin(admin.ModelAdmin):
    list_display = ('name', 'code', 'default_language', 'default_currency', 'created', 'modified')


@admin.register(OperatorAd)
class OperatorAdAdmin(TranslatableAdmin): #admin.ModelAdmin
    list_display = ('name', 'ad_type', 'start_date', 'end_date', 'created', 'modified')
