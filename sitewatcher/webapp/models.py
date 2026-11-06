"""Explicit server-side association between a local account and monitoring data."""
from django.conf import settings
from django.db import models
import secrets


class Workspace(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    owner_id = models.PositiveBigIntegerField(unique=True)
    notification_email = models.EmailField(blank=True, default='')
    timezone = models.CharField(max_length=64, default='Europe/Moscow')
    language = models.CharField(max_length=2, choices=[('en', 'English'), ('ru', 'Русский')],
                                default='en')
    public_enabled = models.BooleanField(default=False)
    public_token_hash = models.CharField(max_length=64, blank=True, default='', db_index=True)
    public_domains = models.JSONField(default=list)
    public_slug = models.CharField(max_length=64, unique=True, null=True, blank=True)
    domain_order = models.JSONField(default=list)

    def save(self, *args, **kwargs):
        if not self.public_slug:
            self.public_slug = ('status' if not type(self).objects.filter(public_slug='status').exists()
                                else 'status-' + secrets.token_hex(8))
        super().save(*args, **kwargs)

    @property
    def public_path(self):
        return '/' + self.public_slug

    class Meta:
        constraints = [models.CheckConstraint(
            condition=models.Q(owner_id__gt=0), name='workspace_positive_owner',
        )]


class StatusPage(models.Model):
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name='status_pages')
    title = models.CharField(max_length=120, blank=True, default='')
    access_mode = models.CharField(max_length=7, default='public',
                                   choices=[('public', 'Public'), ('private', 'Private link')])
    public_enabled = models.BooleanField(default=True)
    public_domains = models.JSONField(default=list)
    public_groups = models.JSONField(default=list)
    public_slug = models.CharField(max_length=64, unique=True)
    public_token_hash = models.CharField(max_length=64, blank=True, default='', db_index=True)
    private_token_nonce = models.CharField(max_length=64, blank=True, default='')
    legacy_primary = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def owner_id(self):
        return self.workspace.owner_id

    @property
    def timezone(self):
        return self.workspace.timezone

    @property
    def language(self):
        return self.workspace.language

    @property
    def public_path(self):
        return '/' + self.public_slug

    @property
    def private_path(self):
        from .status_page_links import private_path
        return private_path(self)

    class Meta:
        ordering = ['pk']
        constraints = [
            models.UniqueConstraint(fields=['workspace'], condition=models.Q(legacy_primary=True),
                                    name='status_page_legacy_primary'),
            models.CheckConstraint(condition=models.Q(access_mode__in=['public', 'private']),
                                   name='status_page_valid_access'),
        ]
