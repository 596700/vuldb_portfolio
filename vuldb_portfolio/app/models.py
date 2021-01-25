from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.validators import MaxValueValidator, MinValueValidator



# Create your models here.

class AppName(models.Model):
    name = models.CharField(max_length=150, unique=True, verbose_name="アプリ名")
    url = models.URLField(verbose_name="ベンダURL")

    class Meta:
        # nameフィールドのアルファベット順に並び替え
        ordering = ("name",)

    def __str__(self):
        return self.name

class Version(models.Model):
    version = models.CharField(max_length=150, unique=True, verbose_name="バージョン")
    name = models.ManyToManyField(
        AppName,
        through="AppNameVersion",)

    class Meta:
        # versionフィールドの数字(小大)文字順に並び替え
        ordering = ("version",)

    def __str__(self):
        return self.version

class AppNameVersion(models.Model):
    name = models.ForeignKey(AppName, on_delete=models.PROTECT, verbose_name="アプリ名")
    version = models.ForeignKey(Version, on_delete=models.PROTECT, verbose_name="バージョン")

    class Meta:
        ordering = ("name", "version")
        # ユニーク制約
        constraints = [
            models.UniqueConstraint(
                fields=["name", "version"],
                name="app_version_unique"
            )
        ]
    @classmethod
    def check_duplicate(cls, name: str, version: str):
        """
        登録済みはTrue, 登録なしはFalse
        """
        return cls.objects.filter(name=name, version=version).exists()

    def __str__(self):
        return str(self.name) + "/" + str(self.version)

class Vulnerability(models.Model):

    class Meta:
        ordering = ("cve_id",)
    # CVSS V3
    cve_id = models.CharField(max_length=14, verbose_name="CVE ID", default="CVE-0000-00000", unique=True)
    url = models.URLField(verbose_name="URL", default="https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN", unique=True)
    """
    「攻撃に関する基準」
    """
    # 攻撃元区分
    AV = [
        ('ネットワーク', 'Network'),
        ('隣接', 'Adjacent'),
        ('ローカル', 'Local'),
        ('物理', 'Physical'),
    ]
    access_vector = models.CharField(max_length=8, choices=AV, verbose_name="攻撃元区分")

    # 攻撃の複雑さ
    AC = [
        ('低', 'Low'),
        ('高', 'High'),
    ]
    access_complexity = models.CharField(max_length=4, choices=AC, verbose_name="攻撃条件の複雑さ")

    # 必要な特権レベル
    PR = [
        ('不要', 'None'),
        ('低', 'Low'),
        ('高', 'High'),
    ]
    privileges_required = models.CharField(max_length=4, choices=PR, verbose_name="必要な特権レベル")

    # 必要なユーザ関与レベル
    UI = [
        ('不要', 'None'),
        ('要', 'Required'),
    ]
    user_interaction = models.CharField(max_length=8, choices=UI, verbose_name="ユーザ関与レベル")

    # 攻撃された際の他方面への影響範囲の広がり
    S = [
        ('変更なし', 'Unchanged'),
        ('変更あり', 'Changed'),
    ]
    scope = models.CharField(max_length=9, choices=S, verbose_name="スコープ")

    """
    ここまで「攻撃に関する基準」
    """

    """
    「影響度」に関する基準
    """

    # 攻撃された際のシステム内の機密情報が漏洩する可能性(機密性に対する影響度)
    C = [
        ('なし', 'None'),
        ('低', 'Low'),
        ('高', 'High'),
    ]
    confidentiality_impact = models.CharField(max_length=4, choices=C, verbose_name="情報漏えいの可能性")

    # 攻撃された場合の情報改ざんの可能性(完全性に対する影響度)
    I = [
        ('なし', 'None'),
        ('低', 'Low',),
        ('高', 'High'),
    ]
    integrity_impact = models.CharField(max_length=4, choices=I, verbose_name="情報改ざんの可能性")

    # 攻撃された場合の業務が遅延・停止する可能性(可用性に対する影響度)
    A = [
        ('なし', 'None'),
        ('低', 'Low'),
        ('高', 'High'),
    ]
    availability_impact = models.CharField(max_length=4, choices=A, verbose_name="業務停止の可能性")
    """
    ここまで「影響度」に関する基準
    """
    
    base_score = models.DecimalField(max_digits=3, decimal_places=1,
                                     validators=[MinValueValidator(0.0), MaxValueValidator(10.0)],
                                     verbose_name="基本値")
    """
    NVDにおける脆弱性分類
    Weaknesses for Simplified Mapping of Published Vulnerabilities
    https://nvd.nist.gov/General/News/NVD-CWE-Slice-Update-2019
    https://cwe.mitre.org/data/definitions/1003.html
    """
    CWE = [
        ('不適切な入力確認', 'CWE-20'),
        ('インジェクション', 'CWE-74'),
        ('不適切なエンコード、または出力のエスケープ', 'CWE-116'),
        ('バッファエラー', 'CWE-119'),
        ('情報漏えい', 'CWE-200'),
        ('不適切な権限管理', 'CWE-269'),
        ('不適切な認証', 'CWE-287'),
        ('重要なデータの暗号化の欠如', 'CWE-311'),
        ('不適切な暗号強度', 'CWE-326'),
        ('不完全、または危険な暗号アルゴリズムの使用', 'CWE-327'),
        ('不十分なランダム値の使用', 'CWE-330'),
        ('データの信頼性についての不十分な検証', 'CWE-345'),
        ('競合状態', 'CWE-362'),
        ('リソースの枯渇', 'CWE-400'),
        ('リソースの不適切なシャットダウンおよびリリース', 'CWE-404'),
        ('解釈の競合', 'CWE-436'),
        ('別領域リソースに対する外部からの制御可能な参照', 'CWE-610'),
        ('不適切な同期', 'CWE-662'),
        ('不適切な初期化', 'CWE-665'),
        ('誤った領域へのリソースの漏えい', 'CWE-668'),
        ('領域間での誤ったリソース移動', 'CWE-669'),
        ('常に不適切な制御フローの実装', 'CWE-670'),
        ('有効期限後または解放後のリソースの操作', 'CWE-672'),
        ('不適切な再帰制御', 'CWE-674'),
        ('計算の誤り', 'CWE-682'),
        ('不適切な比較', 'CWE-697'),
        ('不正な型変換またはキャスト', 'CWE-704'),
        ('誤って解決された名前や参照の使用', 'CWE-706'),
        ('重要なリソースに対する不適切なパーミッションの割り当て', 'CWE-732'),
        ('例外的な状態における不適切なチェック', 'CWE-754'),
        ('例外的な状態における不適切な処理', 'CWE-755'),
        ('過度な繰り返し', 'CWE-834'),
        ('認証の欠如', 'CWE-862'),
        ('不正な認証', 'CWE-863'),
        ('動的に操作されるコードリソースの不適切な制御', 'CWE-913'),
        ('重要な情報のセキュアでない格納', 'CWE-922'),
        ('その他', 'CWE-Other'),
    ]
    weakness_enumertation = models.CharField(max_length=50, choices=CWE, verbose_name="脆弱性のタイプ")
    overview = models.TextField(verbose_name="概要")
    solution = models.TextField(verbose_name="対策方法")
    vendor_information = models.TextField(verbose_name="ベンダ情報")
    creator = models.ForeignKey(get_user_model(), on_delete=models.PROTECT,
                                verbose_name="作成者", related_name='created_by')
    updater = models.ForeignKey(get_user_model(), on_delete=models.PROTECT,
                                verbose_name="更新者", related_name='updated_by')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="作成日時")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="更新日時")
    affected_app = models.ManyToManyField(AppNameVersion, verbose_name="影響を受けるシステム")

    def __str__(self):
        return self.cve_id

# CVSS Version2
# class Vulnerability_V2(models.Model):
#     # CVSS V2
#     """
#     「攻撃内容」に関する基準
#     """
#     # セキュリティホールをどこから攻撃可能か
#     AV = [
#         ('ローカル', 'Local'),
#         ('隣接', 'Adjacent_Network'),
#         ('ネットワーク', 'Network'),
#     ]
#     access_vector = models.CharField(max_length=18, choices=AV, verbose_name="攻撃元")

#     # 攻撃成立条件の難易度
#     AC = [
#         ('難しい', 'High'),
#         ('やや難', 'Medium'),
#         ('簡単', 'Low'),
#     ]
#     access_complexity = models.CharField(max_length=6, choices=AC, verbose_name="攻撃成立条件の難易度")

#     # 攻撃前の認証要否
#     Au = [
#         ('複数回', 'Multiple'),
#         ('一回', 'Single'),
#         ('不要', 'None'),
#     ]
#     authentication = models.CharField(max_length=8, choices=Au, verbose_name="攻撃前の認証要否")
#     """
#     ここまで「攻撃内容」に関する基準
#     """

#     """
#     「影響度」に関する基準
#     """
#     # 機密性への影響
#     C = [
#         ('なし', 'None'),
#         ('部分的', 'Partical'),
#         ('全面的', 'Complete'),
#     ]
#     confidentiality_impact = models.CharField(max_length=8, choices=C, verbose_name="情報漏えいの可能性")

#     # 完全性への影響
#     I = [
#         ('なし', 'None'),
#         ('部分的', 'Partical'),
#         ('全面的', 'Complete'),
#     ]
#     integrity_impact = models.CharField(max_length=8, choices=I, verbose_name="情報改ざんの可能性")

#     # 可用性への影響
#     A = [
#         ('なし', 'None'),
#         ('部分的', 'Partical'),
#         ('全面的', 'Complete'),
#     ]
#     availability_impact = models.CharField(max_length=8, choices=A, verbose_name="業務停止の可能性")

#     """
#     基本値(Base Score)
#     """
#     base_score = models.DecimalField(max_digits=3, decimal_places=1, verbose_name="基本値")