"""Explicit server-side association between a local account and monitoring data."""
from django.conf import settings
from django.db import models
import secrets


class Workspace(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    owner_id = models.PositiveBigIntegerField(unique=True)
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
