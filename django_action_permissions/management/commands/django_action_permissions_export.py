from django.core.management import BaseCommand, CommandError

from django_action_permissions.yaml_io import YAMLNotInstalled, dump_yaml


class Command(BaseCommand):
    help = "Export the stored action permissions and their predicates as a YAML document."

    def add_arguments(self, parser):
        parser.add_argument("-o", "--output", help="the file to write (default: standard output)")

    def handle(self, *args, output, **options):
        try:
            document = dump_yaml()
        except YAMLNotInstalled as e:
            raise CommandError(str(e)) from e
        if output:
            with open(output, "w", encoding="utf-8") as stream:
                stream.write(document)
        else:
            self.stdout.write(document, ending="")
