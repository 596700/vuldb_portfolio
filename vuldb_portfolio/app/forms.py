from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm, UserCreationForm, PasswordChangeForm,
    PasswordResetForm, SetPasswordForm
)
from django.contrib.auth import get_user_model
from .models import (
    AppName, Version, AppNameVersion,
    AppNameVersion, Vulnerability
)



# いくつかのFormで共通で使用するUserインスタント
User = get_user_model()

class LoginForm(AuthenticationForm):
    """
    Login form
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'
            field.widget.attrs['placeholder'] = field.label

class UserCreateForm(UserCreationForm):
    """
    Form user registers
    """

    class Meta:
        model = User
        fields = ('email', 'username',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

    def clean_email(self):
        email = self.cleaned_data['email']
        User.objects.filter(email=email, is_active=False).delete()
        return email

class UserUpdateForm(forms.ModelForm):
    """
    Form user updates
    """
    
    class Meta:
        model = User
        fields = ('username', 'last_name', 'first_name',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

class MyPasswordChangeForm(PasswordChangeForm):
    """
    Change password
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

class MyPasswordResetForm(PasswordResetForm):
    """
    パスワード忘れた用フォーム
    """
    def __init__(self, *args, **kwrags):
        super().__init__(*args, **kwrags)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

class MySetPasswordForm(SetPasswordForm):
    """
    パスワード忘れたリセット用フォーム
    """
    def __init__(self, *args, **kwrags):
        super().__init__(*args, **kwrags)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

class EmailChangeForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ('email',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

    def clean_email(self):
        email = self.cleaned_data['email']
        User.objects.filter(email=email, is_active=False).delete()
        return email

"""
ここからAppのForm
"""

class AppNameForm(forms.ModelForm):
    """
    アプリ名とベンダURL登録フォーム
    """
    class Meta:
        model = AppName
        fields = ('name', 'url',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

class VersionForm(forms.ModelForm):
    """
    バージョン登録フォーム
    """
    class Meta:
        model = Version
        fields = ('version',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

class AppNameVersionForm(forms.ModelForm):
    """
    アプリとバージョンの紐づけフォーム
    """
    class Meta:
        model = AppNameVersion
        fields = ('name', 'version',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'
    
    # 重複を検出する
    def clean(self):
        cleaned_data = super(AppNameVersionForm, self).clean()

        name = cleaned_data.get("name")
        version = cleaned_data.get("version")

        if AppNameVersion.check_duplicate(name=name, version=version):
            raise forms.ValidationError("アプリ名/バージョンはすでに登録済みです")
        
        return cleaned_data

class VulnerabilityForm(forms.ModelForm):
    """
    CVE作成フォーム
    """
    class Meta:
        model = Vulnerability
        fields = '__all__'
        exclude = ('creator', 'updater')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

# class CveForm(forms.ModelForm):
#     """
#     CVE登録のフォーム
#     """
#     class Meta:
#         model = Cve
#         # created_at, updated_atは自動的に入力されるためフォーム不要
#         fields = ('cve_id', 'url_1', 'url_2', 'url_3',
#                 'description', 'creator', 'updater',
#                 'app')
#         exclude = ('cvss_3',)

#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         for field in self.fields.values():
#             field.widget.attrs['class'] = 'form-control'

# # フォームセット
# Cvss_V3_Formset = forms.inlineformset_factory(
#     Cve, Cve.cvss_3.through, fields='__all__',
#     extra=1, max_num=1, can_delete=False
# )