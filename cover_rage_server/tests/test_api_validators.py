import json
import os
from unittest import TestCase

import trafaret as t

from cover_rage_server.api_validators import (
    cover_rage_client_validator,
    github_pull_request_event_validator,
    github_push_event_validator,
    github_status_validator,
    cover_rage_client_to_redis,
    github_push_to_redis,
    github_pull_request_to_redis
)


class ApiConverterTestCase(TestCase):

    def test_github_push_event_validator(self):
        fixtures_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'github_push_event_payload.json'
        )
        with open(fixtures_file) as f:
            converted = github_push_event_validator.check(json.loads(f.read()))
        expected = {
            'head_commit': {
                'sha': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c',
                'created_at': '2015-05-05T19:40:15-04:00',
            },
        }
        self.assertDictEqual(converted, expected)

    def test_github_pull_request_event_validator(self):
        fixtures_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'github_pull_request_event_payload.json'
        )
        with open(fixtures_file) as f:
            converted = github_pull_request_event_validator.check(json.loads(f.read()))
        expected = {
            'action': 'opened',
            'pull_request': {
                'id': 34778301,
                'number': 1,
                'created_at': '2015-05-05T23:40:27Z',
                'updated_at': '2015-05-05T23:40:27Z',
                'url': 'https://api.github.com/repos/baxterthehacker/public-repo/pulls/1',
                'head_commit': {
                    'sha': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c',
                },
            },
        }
        self.assertDictEqual(converted, expected)

    def test_github_status_validator(self):
        fixtures_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'github_get_status_payload.json'
        )
        with open(fixtures_file) as f:
            converted = github_status_validator.check(json.loads(f.read()))
        expected = {
            'status': 'success',
            'sha': '6dcb09b5b57875f334f61a1b2d695e2e4193db5e',
        }
        self.assertDictEqual(converted, expected)

    def test_cover_rage_client_validator_success(self):
        correct_request_data = {
            'overall_coverage': 0.9,
            'uncovered_lines': {'/foo/bar.py': [1, 2, 3], '/foo/baz.py': []},
            'git_commit': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c'
        }
        converted = cover_rage_client_validator.check(correct_request_data)
        self.assertDictEqual(converted, correct_request_data)

    def test_cover_rage_client_validator_fail(self):
        wrong_request_data = {
            'overall_coverage': 'string',
            'uncovered_lines': {'/foo/bar.py': [1, 'str', 3.1], 0: []},
            'unknown': 'some-value'
        }
        with self.assertRaises(t.DataError):
            cover_rage_client_validator.check(wrong_request_data)
        errors = t.extract_error(cover_rage_client_validator, wrong_request_data)
        expected_errors = {
            'git_commit': 'is required',
            'overall_coverage': "value can't be converted to float",
            'uncovered_lines': {
                0: {'key': 'value is not a string'},
                '/foo/bar.py': {
                    'value': {
                        1: "value can't be converted to int",
                        2: 'value is not int'
                    }
                }
            },
            'unknown': 'unknown is not allowed key'
        }
        self.assertDictEqual(errors, expected_errors)

    def test_github_push_to_redis(self):
        github = {
            'head_commit': {
                'created_at': '2015-05-05T23:40:27Z',
                'sha': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c',
            },
        }
        expected = {
            'created_at': '2015-05-05T23:40:27Z',
            'sha': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c',
        }
        self.assertDictEqual(github_push_to_redis(github), expected)

    def test_github_pull_request_to_redis(self):
        github = {
            'action': 'opened',
            'pull_request': {
                'id': 34778301,
                'number': 1,
                'created_at': '2015-05-05T23:40:27Z',
                'updated_at': '2015-05-05T23:40:27Z',
                'url': 'https://api.github.com/repos/baxterthehacker/public-repo/pulls/1',
                'head_commit': {
                    'sha': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c',
                },
            },
        }
        expected = {
            'action': 'opened',
            'id': 34778301,
            'number': 1,
            'created_at': '2015-05-05T23:40:27Z',
            'updated_at': '2015-05-05T23:40:27Z',
            'url': 'https://api.github.com/repos/baxterthehacker/public-repo/pulls/1',
            'sha': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c',
        }
        self.assertDictEqual(github_pull_request_to_redis(github), expected)

    def test_cover_rage_client_to_redis(self):
        client_data = {
            'overall_coverage': 'string',
            'git_commit': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c',
            'uncovered_lines': {'/foo/bar.py': [1, 2, 3]},
        }
        expected = {
            'overall_coverage': 'string',
            'git_commit': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c',
            'uncovered_lines': '{"/foo/bar.py": [1, 2, 3]}',
        }
        self.assertDictEqual(cover_rage_client_to_redis(client_data), expected)
