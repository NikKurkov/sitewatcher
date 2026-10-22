"""Explicit server-side association between a local account and monitoring data."""
from django.conf import settings
from django.db import models


class Workspace(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    owner_id = models.PositiveBigIntegerField(unique=True)
    timezone = models.CharField(max_length=64, default='Europe/Moscow')
    public_enabled = models.BooleanField(default=False)
    public_token_hash = models.CharField(max_length=64, blank=True, default='', db_index=True)
    public_domains = models.JSONField(default=list)

    class Meta:
        constraints = [models.CheckConstraint(
            condition=models.Q(owner_id__gt=0), name='workspace_positive_owner',
        )]
