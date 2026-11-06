from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('webapp', '0008_statuspage_public_groups')]

    operations = [migrations.AddField(
        model_name='workspace', name='notification_email',
        field=models.EmailField(blank=True, default='', max_length=254),
    )]
