from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('webapp', '0002_workspace_public')]
    operations = [migrations.AddField(
        model_name='workspace', name='language',
        field=models.CharField(choices=[('en', 'English'), ('ru', 'Русский')],
                               default='en', max_length=2),
    )]
