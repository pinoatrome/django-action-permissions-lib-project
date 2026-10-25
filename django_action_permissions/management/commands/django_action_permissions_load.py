from django.core.management import BaseCommand, CommandError

from django_action_permissions.yaml_io import YAMLNotInstalled, load_yaml


class Command(BaseCommand):
    help = (
        "Set up the permission definitions and their predicates from a YAML document "
        "(see django_action_permissions.yaml_io)."
    )
    requires_migrations_checks = True

    def add_arguments(self, parser):
        parser.add_argument("file", help="the YAML document")
        parser.add_argument(
            "--keep",
            action="store_true",
            help="keep the groups' other permissions, and the entries and rules the document doesn't list",
        )

    def handle(self, *args, file, keep, **options):
        try:
            with open(file, encoding="utf-8") as stream:
                counts = load_yaml(stream, keep=keep)
        except (OSError, ValueError, YAMLNotInstalled) as e:
            raise CommandError(str(e)) from e
        self.stdout.write(
            self.style.SUCCESS(
                f"{counts['permissions']} permissions, {counts['rules']} rules, {counts['groups']} groups set up"
                f"{' (keep)' if keep else ''}"
            )
        )
