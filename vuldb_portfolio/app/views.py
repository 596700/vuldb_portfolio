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
from django.db.models import Q

from .forms import (
    LoginForm, UserCreateForm, UserUpdateForm, MyPasswordChangeForm,
    MyPasswordResetForm, MySetPasswordForm, EmailChangeForm,
    AppNameForm, VersionForm, AppNameVersionForm, VulnerabilityForm
)
from .models import (
    AppName, Version, AppNameVersion, Vulnerability
)




# Create your views here.

# プロジェクトで使用中のUserモデル(default or custom)を取得
User = get_user_model()

class Top(generic.View):
    
    def get(self, request, *args, **kwargs):
        # 最近登録したレコード(idの大きい順)
        app_name = AppName.objects.order_by('-id')
        version = Version.objects.order_by('-id')
        app_version = AppNameVersion.objects.order_by('-id')
        vulnerability = Vulnerability.objects.order_by('-id')
        context = {
            # 5個まで
            'app_name': app_name[:5],
            'version': version[:5],
            'app_version': app_version[:10],
            'vulnerability': vulnerability[:20],
        }
        return render(request, 'app/top.html', context)

class Login(LoginView):
    """Login page"""
    form_class = LoginForm
    template_name = 'app/login.html'

class Logout(LogoutView):
    """Logout page"""
    template_name = 'app/login.html'

class UserCreate(generic.CreateView):
    """
    ユーザー仮登録
    """
    template_name = 'app/user_create.html'
    form_class = UserCreateForm

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

"""
ここからAppのViews
"""

class AppNameCreate(LoginRequiredMixin, generic.CreateView):
    model = AppName
    form_class = AppNameForm
    template_name = 'app/app_create.html'
    success_url = reverse_lazy('app:app_list')

class AppNameList(generic.ListView):
    # modelよりcontext_object_nameを前にもってくること
    # context_object_nameはデフォルトでは'モデル名_list'
    context_object_name = 'app_list'
    model = AppName
    # pagenate_byで定義したページ情報はpage_objという名前でテンプレートに渡される
    paginate_by = 20
    template_name = 'app/app_list.html'
    # 検索フォーム
    def get_queryset(self):
        query_word = self.request.GET.get('query')

        if query_word:
            object_list = AppName.objects.filter(
                Q(name__icontains=query_word) |
                Q(url__icontains=query_word)
            ).distinct()
        else:
            object_list = AppName.objects.all() 
        return object_list

class AppNameDetail(generic.DetailView):
    model = AppName
    template_name = 'app/app_detail.html'

class AppNameUpdate(LoginRequiredMixin, generic.UpdateView):
    model = AppName
    form_class = AppNameForm
    template_name = 'app/app_update.html'
    success_url = reverse_lazy('app:app_list')

class AppNameDelete(LoginRequiredMixin, generic.DeleteView):
    model = AppName
    template_name = 'app/app_delete.html'
    success_url = reverse_lazy('app:app_list')

"""
ここからVersionのView
"""
class VersionCreate(LoginRequiredMixin, generic.CreateView):
    model = Version
    form_class = VersionForm
    template_name = 'app/version_create.html'
    success_url = reverse_lazy('app:version_list')

class VersionList(generic.ListView):
    context_object_name = 'version_list'
    model = AppName
    # pagenate_byで定義したページ情報はpage_objという名前でテンプレートに渡される
    paginate_by = 20
    template_name = 'app/version_list.html'
    # 検索フォーム
    def get_queryset(self):
        query_word = self.request.GET.get('query')

        if query_word:
            object_list = Version.objects.filter(
                Q(version__icontains=query_word)
            ).distinct()
        else:
            object_list = Version.objects.all() 
        return object_list

class VersionDetail(generic.DetailView):
    model = Version
    template_name = 'app/version_detail.html'

class VersionUpdate(LoginRequiredMixin, generic.UpdateView):
    model = Version
    form_class = VersionForm
    template_name = 'app/version_update.html'
    success_url = reverse_lazy('app:version_list')

class VersionDelete(LoginRequiredMixin, generic.DeleteView):
    model = Version
    template_name = 'app/version_delete.html'
    success_url = reverse_lazy('app:version_list')

"""
ここからAppVersionのView
"""

class AppVersionCreate(LoginRequiredMixin, generic.CreateView):
    model = AppNameVersion
    form_class = AppNameVersionForm
    template_name = 'app/app_version_create.html'
    success_url = reverse_lazy('app:app_version_list')

class AppVersionList(generic.ListView):
    context_object_name = 'app_version_list'
    model = AppNameVersion
    paginate_by = 20
    template_name = 'app/app_version_list.html'
    # 検索フォーム
    def get_queryset(self):
        query_word = self.request.GET.get('query')
        # name, versionフィールドともに外部キーを参照しているため、冗長した書き方になっている
        if query_word:
            object_list = AppNameVersion.objects.filter(
                Q(name__name__icontains=query_word) |
                Q(version__version__icontains=query_word)
            ).distinct()
        else:
            object_list = AppNameVersion.objects.all() 
        return object_list

class AppVersionDetail(generic.DetailView):
    model = AppNameVersion
    template_name = 'app/app_version_detail.html'

class AppVersionUpdate(LoginRequiredMixin, generic.UpdateView):
    model = AppNameVersion
    form_class = AppNameVersionForm
    template_name = 'app/app_version_update.html'
    success_url = reverse_lazy('app:app_version_list')

class AppVersionDelete(LoginRequiredMixin, generic.DeleteView):
    model = AppNameVersion
    template_name = 'app/app_version_delete.html'
    success_url = reverse_lazy('app:app_version_list')

class VulnerabilityCreate(LoginRequiredMixin, generic.CreateView):
    model = Vulnerability
    form_class = VulnerabilityForm
    template_name = 'app/vulnerability_create.html'
    success_url = reverse_lazy('app:vul_list')
    """
    creatorフィールドにユーザを記入
    updaterについては一時的に記入
    """
    
    def form_valid(self, form):
        form.instance.creator = self.request.user
        form.instance.updater = self.request.user
        return super().form_valid(form)

class VulnerabilityList(generic.ListView):
    context_object_name = 'vul_list'
    model = Vulnerability
    paginate_by = 20
    template_name = 'app/vulnerability_list.html'
    # 検索フォーム
    def get_queryset(self):
        query_word = self.request.GET.get('query')
        """
        distinct()で重複を消す

        affected_app = ManytoMany(AppNameVersion)
        appnameversion.name = app.nameのためクエリセットが冗長した書き方
        """
        if query_word:
            object_list = Vulnerability.objects.filter(
                Q(cve_id__icontains=query_word) |
                Q(affected_app__name__name__icontains=query_word) |
                Q(detailed_information__icontains=query_word)
            ).distinct()
        else:
            object_list = Vulnerability.objects.all() 
        return object_list

class VulnerabilityDetail(generic.DetailView):
    model = Vulnerability
    template_name = 'app/vulnerability_detail.html'

class VulnerabilityUpdate(LoginRequiredMixin, generic.UpdateView):
    model = Vulnerability
    form_class = VulnerabilityForm
    template_name = 'app/vulnerability_update.html'
    success_url = reverse_lazy('app:vul_list')

    def form_valid(self, form):
        form.instance.updater = self.request.user
        return super().form_valid(form)

class VulnerabilityDelete(LoginRequiredMixin, generic.DeleteView):
    model = Vulnerability
    template_name = 'app/vulnerability_delete.html'
    success_url = reverse_lazy('app:vul_list')


# class CveCreate(generic.CreateView):
#     model = Cve
#     form_class = CveForm
#     template_name = 'app/cve_create.html'
#     # cve_listに書き換え
#     success_url = reverse_lazy('app:app_version_list')

# def cve_post(request):
#     form = CveForm(request.POST or None)
#     context = {'form': form}
#     if request.method == 'POST' and form.is_valid():
#         post = form.save(commit=False)
#         formset = Cvss_V3_Formset(request.POST, instance=post)
#         if formset.is_valid():
#             post.save()
#             formset.save()
#             return redirect('app:app_list')
#         # エラーメッセージつきのformsetをtemplateに渡す
#         else:
#             context['formset'] = formset
#     # GETのとき
#     else:
#         # 未入力状態の空のformsetをテンプレートに渡す
#         context['formset'] = Cvss_V3_Formset()
    
#     return render(request, 'app/cve_create.html', context)