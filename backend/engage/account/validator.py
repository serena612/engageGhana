from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _
from django.contrib.staticfiles import finders



class CustomPasswordValidator():

    def __init__(self, min_length=1):
        self.min_length = min_length
        self.consec = ['012', '123', '233', '345', '456', '567', '678', '789', '890', '210', '321', '432', '543', '654', '765', '876', '987', '098']
        self.f = open(finders.find('admin/passvalidation/all_pass.txt'), encoding='latin-1')
        self.newpass = self.f.read().splitlines()
        self.f.close()
        self.special_characters = "[~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]?."

    def validate(self, password, user=None):

        if not any(char.isdigit() for char in password):
            raise ValidationError(_('Password must contain at least %(min_length)d digit.') % {'min_length': self.min_length})
        if not any(char.islower() for char in password):
            raise ValidationError(_('Password must contain at least %(min_length)d lower-case character.') % {'min_length': self.min_length})
        if not any(char in self.special_characters for char in password):
            raise ValidationError(_('Password must contain at least %(min_length)d special character.') % {'min_length': self.min_length})
        if not any(char.isupper() for char in password):
            raise ValidationError(_('Password must contain at least %(min_length)d upper-case character.') % {'min_length': self.min_length})
        for co in self.consec:
            if co in password:
                raise ValidationError(_('Password cannot contain consecutive numbers.'))
                break
        if password in self.newpass:
            raise ValidationError(_('Password has been previously exposed in data breaches. Please choose another.'))

    def get_help_text(self):
        return _("Your password must contain at lest one upper-case character, one lower-case character, one digit and one special character.")
