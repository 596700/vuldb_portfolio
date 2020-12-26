from django.conf import settings
from django.shortcuts import render, redirect, resolve_url
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import (
    LoginView, LogoutView, PasswordChangeView, PasswordChangeDoneView,
    PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
)
from django.contrib.sites.shortcuts import get_current_site
from django.core.signing import BadSignature, SignatureExpired, loads, dumps
from django.http import Http404, HttpResponseBadRequest
from django.template.loader import render_to_string
from django.views import generic
from django.urls import reverse_lazy
from django.core.mail import send_mail

from .forms import (
    LoginForm, UserCreationForm, UserUpdateForm, MyPasswordChangeForm,
    MyPasswordResetForm, MySetPasswordForm, EmailChangeForm
)




# Create your views here.

# プロジェクトで使用中のUserモデル(default or custom)を取得
User = get_user_model()

class Top(generic.TemplateView):
    template_name ='app/top.html'

class Login(LoginView):
    """Login page"""
    form_class = LoginForm
    template_name = 'app/login.html'

class Logout(LogoutView):
    """Logout page"""
    template_name = 'app/top.html'

class UserCreate(generic.CreateView):
    """
    ユーザー仮登録
    """
    template_name = 'app/user_create.html'
    form_class = UserCreationForm

    # POSTメソッドでで呼ばれたときform_validが実行される(CreateViewの多重継承先に定義されている)
    def form_valid(self, form):
        """
        仮登録と本登録メール発行
        """
        # 仮登録と本登録はis_active属性を使う、本登録次users.is_active = True
        # 退会処理はis_active = Falseにする

        # 仮登録状態はuser.is_active = False
        user = form.save(commit=False)
        user.is_active = False
        user.save()

        # Send activation url
        current_site = get_current_site(self.request)
        domain = current_site.domain
        context = {
            'protocol': self.request.scheme,
            'domain': domain,
            'token': dumps(user.pk),
            'user': user,
        }
        
        subject = render_to_string('app/mail_template/create/subject.txt', context)
        message = render_to_string('app/mail_template/create/message.txt', context)

        user.email_user(subject, message)
        return redirect('app:user_create_done')

class UserCreateDone(generic.TemplateView):
    """
    仮登録
    """
    template_name = 'app/user_create_done.html'

class UserCreateComplete(generic.TemplateView):
    """"
    Register user access to url
    """
    template_name = 'app/user_create_complete.html'
    # In 24h (minutes * int * int)
    timeout_seconds = getattr(settings, 'ACTIVATION_TIMEOUT_SECONDS', 60*60*24)

    def get(self, request, **kwargs):
        """token == True then register"""
        token = kwargs.get('token')
        try:
            user_pk = loads(token, max_age=self.timeout_seconds)
        # Expires
        except SignatureExpired:
            return HttpResponseBadRequest()
        # bad token
        except BadSignature:
            return HttpResponseBadRequest()
        # no problem
        else:
            try:
                user = User.objects.get(pk=user_pk)
            except User.DoesNotExist:
                return HttpResponseBadRequest()
            else:
                if not user.is_active:
                    # register
                    user.is_active = True
                    user.save()
                    return super().get(request, **kwargs)
        return HttpResponseBadRequest()

class OnlyYouMixin(UserPassesTestMixin):
    """
    ログイン中のユーザー or superuserのみが編集できる
    """
    # 他のユーザーが干渉する等例外の場合エラー
    raise_exception = True

    def test_func(self):
        user = self.request.user
        return user.pk == self.kwargs['pk'] or user.is_superuser

class UserDetail(OnlyYouMixin, generic.DetailView):
    model = User
    template_name = 'app/user_detail.html'

class UserUpdate(OnlyYouMixin, generic.UpdateView):
    model = User
    form_class = UserUpdateForm
    template_name = 'app/user_form.html'

    def get_success_url(self):
        return resolve_url('app:user_detail', pk=self.kwargs['pk'])

# 退会機能
class UserDelete(OnlyYouMixin, generic.DeleteView):
    template_name = 'app/user_delete.html'
    success_url = reverse_lazy('app:user_delete_done')
    model = User
    slug_field = 'username'
    # slug_url_kwarg = 'username'

class UserDeleteDone(generic.TemplateView):
    """
    仮登録
    """
    template_name = 'app/user_delete_done.html'

class PasswordChange(PasswordChangeView):
    form_class = MyPasswordChangeForm
    success_url = reverse_lazy('app:password_change_done')
    template_name = 'app/password_change.html'

class PasswordChangeDone(PasswordChangeDoneView):
    template_name = 'app/password_change_done.html'

class PasswordReset(PasswordResetView):
    """
    パスワード変更用URL送付ページ
    """
    subject_template_name = 'app/mail_template/password_reset/subject.txt'
    email_template_name = 'app/mail_template/password_reset/message.txt'
    template_name = 'app/password_reset_form.html'
    form_class = MyPasswordResetForm
    success_url = reverse_lazy('app:password_reset_done')

class PasswordResetDone(PasswordResetDoneView):
    template_name = 'app/password_reset_done.html'

class PasswordResetConfirm(PasswordResetConfirmView):
    form_class = MySetPasswordForm
    success_url = reverse_lazy('app:password_reset_complete')
    template_name = 'app/password_reset_confirm.html'

class PasswordResetComplete(PasswordResetCompleteView):
    template_name = 'app/password_reset_complete.html'

class EmailChange(LoginRequiredMixin, generic.FormView):
    """
    Change email
    """
    template_name = 'app/email_change_form.html'
    form_class = EmailChangeForm

    def form_valid(self, form):
        user = self.request.user
        new_email = form.cleaned_data['email']

        # Send url
        current_site = get_current_site(self.request)
        domain = current_site.domain
        context = {
            'protocol': 'https' if self.request.is_secure() else 'http',
            'domain': domain,
            'token': dumps(new_email),
            'user': user,
        }

        subject = render_to_string('app/mail_template/email_change/subject.txt', context)
        message = render_to_string('app/mail_template/email_change/message.txt', context)
        # send_mailの場合send_mail(題名、本文、送信元、宛先)を指定
        # user.email_user(subject, message, None, [new_email])
        # user.email_userの場合題名、本文、送信元、※宛先は不要
        # user.email_user(subject, message, [new_email])
        # 今回はメール変更だからsend_mailのが適切っぽい？
        send_mail(subject, message, None, [new_email])


        return redirect('app:email_change_done')

class EmailChangeDone(LoginRequiredMixin, generic.TemplateView):
    """
    Send email change mail
    """
    template_name = 'app/email_change_done.html'

class EmailChangeComplete(LoginRequiredMixin, generic.TemplateView):
    template_name = 'app/email_change_complete.html'
    timeout_seconds = getattr(settings, 'ACTIVATION_TIMEOUT_SECONDS', 60*60*24)

    def get(self, request, **kwargs):
        token = kwargs.get('token')
        try:
            new_email = loads(token, max_age=self.timeout_seconds)

        # Expires
        except SignatureExpired:
            return HttpResponseBadRequest()

        # Bad token
        except BadSignature:
            return HttpResponseBadRequest()

        # No problem
        else:
            User.objects.filter(email=new_email, is_active=False).delete()
            request.user.email = new_email
            request.user.save()
            return super().get(request, **kwargs)