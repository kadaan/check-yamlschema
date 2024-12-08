from __future__ import annotations

import argparse
import io
import logging
import re
import typing as t
from dataclasses import dataclass

from check_jsonschema.checker import SchemaChecker
from check_jsonschema.instance_loader import InstanceLoader
from check_jsonschema.parsers import ParseError
from check_jsonschema.reporter import TextReporter, Reporter
from check_jsonschema.result import CheckResult
from check_jsonschema.schema_loader import SchemaLoader
from jsonschema.exceptions import ValidationError
import click


@dataclass
class YamlDocument:
    id: int
    start: int
    size: int


def try_get_schema_url(line: str) -> (bool, str):
    if line.strip().startswith("# yaml-language-server"):
        match = re.match(r"# yaml-language-server: \$schema=(.*)$", line)
        if match:
            return True, match.group(1)
    return False, ""

def load_yaml_documents(file_paths: [str], result: CheckResult) -> dict[str, dict[str, [YamlDocument]]]:
    yaml_document_schemas = dict()
    def add_yaml_document(doc_schema_url, doc_id, doc_start, doc_length):
        yaml_document_schema = yaml_document_schemas.get(doc_schema_url)
        if yaml_document_schema is None:
            yaml_document_schema = dict()
            yaml_document_schemas[schema_url] = yaml_document_schema

        yaml_document = yaml_document_schema.get(file_path)
        if yaml_document is None:
            yaml_document = []
            yaml_document_schema[file_path] = yaml_document

        yaml_document.append(YamlDocument(doc_id, doc_start, doc_length))

    for file_path in file_paths:
        with open(file_path) as file:
            try:
                start = 0
                length = 0
                document_id = 0
                schema_url = ""
                in_document = False
                for line in file:
                    if re.match(r"^---\s*$", line):
                        if in_document:
                            add_yaml_document(schema_url, document_id, start, length)
                            document_id += 1
                            start += length + len(line)
                            length = 0
                            in_document = False
                        else:
                            start += length + len(line)
                    elif not in_document:
                        if line.startswith("#"):
                            matched, found_schema_url = try_get_schema_url(line)
                            if matched:
                                schema_url = found_schema_url
                        else:
                            in_document = True
                        length += len(line)
                    else:
                        length += len(line)

                if length > 0:
                    add_yaml_document(schema_url, document_id, start, length)

            except ValueError as e:
                result.record_parse_error(file_path, e)
            except Exception as e:
                result.record_parse_error(file_path, ValueError(e))
    return yaml_document_schemas


class Substream(io.TextIOBase):
    """Represents a view of a subset of a file like object"""
    def __init__(self, file: io.TextIOBase, start, size):
        self.file = file
        self.start = start
        self.size = size
        self.p = 0

    def seek(self, offset, origin=0):
        if origin == 0:
            self.p = offset
        elif origin == 1:
            self.p += offset
        # TODO: origin == 2
        else:
            raise ValueError("Unexpected origin: {}".format(origin))

    def read(self, size: int = -1):
        prev = self.file.tell()
        self.file.seek(self.start + self.p)
        if size == -1:
            data = self.file.read(self.size - self.p)
        else:
            data = self.file.read(size if self.p + size <= self.size else self.size - self.p)
        self.p += len(data)
        self.file.seek(prev)
        return data


class DocumentInstanceLoader(InstanceLoader):
    def __init__(self, files: [Tuple[str, [YamlDocument]]]):
        super().__init__([])
        self._files = files

    def iter_files(self) -> t.Iterator[tuple[str, ParseError | t.Any]]:
        for file_path, documents in self._files:
            file = open(file_path, "r")
            try:
                for document in documents:
                    name = file_path
                    if len(documents) > 1:
                        name = f"{file_path}[{str(document.id)}]"
                    try:
                        substream = Substream(file, document.start, document.size)
                        data: t.Any = self._parsers.parse_data_with_path(
                            substream, name, "yaml"
                        )
                    except ParseError as err:
                        data = err
                    else:
                        data = self._data_transform(data)
                    yield name, data
            finally:
                file.close()


class MissingSchemaValidationError(ValidationError):
    def __init__(self, start: int):
        super().__init__("Schema is required but not found")
        self._start = start

    @property
    def json_path(self):
        return str(self._start)


class AggregatingReporter(Reporter):
    def __init__(self, result: CheckResult):
        super().__init__(verbosity=0)
        self.result = result

    def report_success(self, result: CheckResult) -> None:
        for path in result.successes:
            self.result.record_validation_success(path)

    def report_errors(self, result: CheckResult) -> None:
        for path, errors in result.validation_errors.items():
            for error in errors:
                self.result.record_validation_error(path, error)
        for path, errors in result.parse_errors.items():
            for error in errors:
                self.result.record_parse_error(path, error)


def _detail(block, verbosity: int, **kwargs):
    if verbosity > 2:
        click.echo(click.style("", fg=(128, 128, 128), reset=False), nl=False)
        try:
            if callable(block):
                block(**kwargs)
            else:
                click.echo(block)
        finally:
            click.echo(click.style("", fg=(128, 128, 128), reset=True), nl=False)

def _log_command(file_paths: [str], require_schema: bool, verbose: int):
    click.echo("Starting YAML schema validation...")
    click.echo(f"  Files:")
    for file_path in sorted(file_paths):
        click.echo(f"    {file_path}")
    click.echo(f"  Require schema: {require_schema}")
    click.echo(f"  Verbosity: {verbose}")
    click.echo("")

def _log_yaml_documents(yaml_document_schemas: dict[str, dict[str, [YamlDocument]]]):
    click.echo("Loaded YAML documents:")
    for schema_url, files in yaml_document_schemas.items():
        click.echo(f"  Schema: {schema_url}")
        for file_path, documents in files.items():
            click.echo(f"    {file_path}")
            for document in documents:
                click.echo(f"      {document.id}: {document.start} to {document.start + document.size}")
    click.echo("")

def _log_missing_schemas(files: dict[str, [YamlDocument]]):
    click.echo("")
    click.echo("  No schema found in YAML documents:")
    for file_path, documents in sorted(files.items()):
        click.echo(f"    {file_path}")
    click.echo("")

def main():
    logging.basicConfig(format="%(message)s")
    parser = argparse.ArgumentParser(
        description="Validate YAML document(s) against JSON schema."
    )
    parser.add_argument("files", nargs="+", help="Path to YAML files to validate")
    parser.add_argument("-r", "--require-schema", action="store_true", help="Require schema to be specified in YAML file")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase output verbosity")
    args = parser.parse_args()
    args.verbose = args.verbose + 1

    _detail(_log_command, args.verbose, file_paths=args.files, require_schema=args.require_schema, verbose=args.verbose)

    result = CheckResult()
    aggregating_reporter = AggregatingReporter(result)
    yaml_document_schemas = load_yaml_documents(args.files, result)
    _detail(_log_yaml_documents, args.verbose, yaml_document_schemas=yaml_document_schemas)
    for schema_url, files in yaml_document_schemas.items():
        if schema_url == "":
            if args.require_schema:
                for file_path, documents in sorted(files.items()):
                    for document in documents:
                        result.record_validation_error(file_path, MissingSchemaValidationError(document.start))
            else:
                _detail(_log_missing_schemas, args.verbose, files=files)
        else:
            schema_loader = SchemaLoader(schema_url, disable_cache=False)
            instance_loader = DocumentInstanceLoader(sorted(files.items()))
            checker = SchemaChecker(schema_loader, instance_loader, aggregating_reporter)
            checker.run()

    reporter = TextReporter(verbosity=args.verbose)
    reporter.report_result(result)
    if result.success:
        _detail("YAML schema validation successful", args.verbose)
        exit(0)

    _detail("YAML schema validation failed", args.verbose)
    exit(1)


if __name__ == "__main__":
    main()
