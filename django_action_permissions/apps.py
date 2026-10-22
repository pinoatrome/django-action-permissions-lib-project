from django.apps import AppConfig


class ActionPermissionsConfig(AppConfig):
    name = "django_action_permissions"
    label = "django_action_permissions"
    verbose_name = "Action permissions"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from . import checks, signals  # noqa: F401  (registers the checks and the receivers)
