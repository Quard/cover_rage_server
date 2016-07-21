from copy import copy
import json
import os
from unittest import TestCase, mock

from aiohttp.web_exceptions import HTTPNotFound, HTTPUnauthorized

from cover_rage_server.tests.mixins import AsyncMockMixin, AioHttpViewTestMixin


HTTP_OK = 200
HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400


# noinspection PyUnresolvedReferences
class CoverRageViewsTestMixin(object):

    fixtures_file = 'github_push_event_payload.json'
    correct_headers = {}
    correct_match_info = {'token': 'valid_token'}
    correct_get_repo = (
        'r/gh/john_doe/project',
        {
            'rage_private_token': 'valid_private_token',
            'repo_access_token': 'repo_access_token',
            'min_good_coverage': 94,
            'coverage': 99,
        }
    )

    def _get_correct_request_data(self):
        fixtures_file_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'fixtures', self.fixtures_file
        )
        with open(fixtures_file_path) as f:
            return json.loads(f.read())

    def _mock_request(self, headers=None, match_info=None, request_json=None, request_data=None):
        if headers is None:
            self.request.headers = self.correct_headers
        else:
            self.request.headers = headers
        if match_info is None:
            self.request.match_info = self.correct_match_info
        else:
            self.request.match_info = match_info
        if request_data is None:
            self.request.data = b''
        else:
            self.request.data = request_data
        self.request.json = self.coro_mock()
        if request_json is None:
            self.request.json.coro.return_value = self._get_correct_request_data()
        else:
            self.request.json.coro.return_value = request_json

    def _assert_response(self, response, body=None, status_code=None, content_type='application/json'):
        if body is None:
            body = {}
        if status_code is None:
            status_code = self.success_status
        self.assertIsInstance(response.body, bytes)
        body_json = json.loads(response.body.decode())
        self.assertDictEqual(body_json, body)
        self.assertEqual(response.status, status_code)
        self.assertEqual(response.content_type, content_type)

    def test_public_token_failure(self):
        self._mock_request(match_info={})

        view = self.view(self.request)
        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.post())

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    def test_get_repo_failure(self, mocked_get_repo):
        mocked_get_repo.coro.return_value = ('key', None)
        self._mock_request()

        view = self.view(self.request)
        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.post())
        self.assertEqual(mocked_get_repo.call_count, 1)


# noinspection PyUnresolvedReferences
class PostViewsTestMixin(object):

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    def test_no_private_token_header_failure(self, mocked_get_repo):
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(headers={})

        view = self.view(self.request)
        with self.assertRaises(HTTPUnauthorized):
            self.loop.run_until_complete(view.post())

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.hmac.compare_digest')
    def test_invalid_private_token_header_failure(self, mocked_compare_digest, mocked_get_repo):
        mocked_compare_digest.return_value = False
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(headers={'X-CoverRage-Signature': 'sha1=wrong'}, request_data=b'data')

        view = self.view(self.request)
        with self.assertRaises(HTTPUnauthorized):
            self.loop.run_until_complete(view.post())

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    def test_invalid_private_token_not_sha1_header_failure(self, mocked_get_repo):
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(headers={'X-CoverRage-Signature': 'sha2=token'})

        view = self.view(self.request)
        with self.assertRaises(HTTPUnauthorized):
            self.loop.run_until_complete(view.post())


class PushEventTestCase(
    PostViewsTestMixin, AsyncMockMixin, AioHttpViewTestMixin, CoverRageViewsTestMixin, TestCase
):

    success_status = HTTP_OK
    error_status = HTTP_BAD_REQUEST
    fixtures_file = 'github_push_event_payload.json'
    correct_headers = {'X-GitHub-Event': 'push'}

    def setUp(self):
        super(PushEventTestCase, self).setUp()
        from cover_rage_server.api_views import GithubWebHookEventApiView
        self.view = GithubWebHookEventApiView

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_success(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_handle_inner_method,
        mocked_get_repo
    ):
        mocked_handle_inner_method.coro.return_value = True
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(response)
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)
        self.assertEqual(mocked_handle_inner_method.call_count, 1)
        self.assertEqual(mocked_send_github_status.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_handle_inner_method_failure(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_handle_inner_method,
        mocked_get_repo
    ):
        mocked_handle_inner_method.coro.return_value = False
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(response, body={'git_commit': 'Could not update commit'}, status_code=self.error_status)
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)
        self.assertEqual(mocked_handle_inner_method.call_count, 1)
        self.assertEqual(mocked_send_github_status.call_count, 0)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_handle_send_github_status_failure(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_handle_inner_method,
        mocked_get_repo
    ):
        mocked_handle_inner_method.coro.return_value = True
        mocked_send_github_status.coro.return_value = False
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(
            response, body={'git_commit': 'Could not set status for commit'}, status_code=self.error_status
        )
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)
        self.assertEqual(mocked_handle_inner_method.call_count, 1)
        self.assertEqual(mocked_send_github_status.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_is_valid_failure(self, mocked_check_signature, mocked_get_repo):
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(request_json={'foo': 'bar'})

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(
            response,
            body={'head_commit': 'is required'},
            status_code=self.error_status
        )
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)


class PullRequestEventTestCase(
    PostViewsTestMixin, AsyncMockMixin, AioHttpViewTestMixin, CoverRageViewsTestMixin, TestCase
):

    success_status = HTTP_OK
    error_status = HTTP_BAD_REQUEST
    fixtures_file = 'github_pull_request_event_payload.json'
    correct_headers = {'X-GitHub-Event': 'pull_request'}

    def setUp(self):
        super(PullRequestEventTestCase, self).setUp()
        from cover_rage_server.api_views import GithubWebHookEventApiView
        self.view = GithubWebHookEventApiView

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_success_create_update_action(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_update_commit,
        mocked_get_repo
    ):
        mocked_update_commit.coro.return_value = True
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)

        for action in ('edited', 'opened', 'reopened',):
            request_json = self._get_correct_request_data()
            request_json['action'] = action
            self._mock_request(request_json=request_json)

            view = self.view(self.request)
            response = self.loop.run_until_complete(view.post())
            self._assert_response(response)

        self.assertEqual(mocked_get_repo.call_count, 3)
        self.assertEqual(mocked_check_signature.call_count, 3)
        self.assertEqual(mocked_update_commit.call_count, 3)
        self.assertEqual(mocked_send_github_status.call_count, 3)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_success_ignored_action(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_update_commit,
        mocked_get_repo
    ):
        mocked_update_commit.coro.return_value = True
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)

        for action in ('assigned', 'unassigned', 'labeled', 'unlabeled', 'synchronize'):
            request_json = self._get_correct_request_data()
            request_json['action'] = action
            self._mock_request(request_json=request_json)

            view = self.view(self.request)
            response = self.loop.run_until_complete(view.post())
            self._assert_response(response, status_code=HTTP_ACCEPTED)

        self.assertEqual(mocked_get_repo.call_count, 5)
        self.assertEqual(mocked_check_signature.call_count, 5)
        self.assertEqual(mocked_update_commit.call_count, 0)

    # @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    # @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    # @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    # def test_success_delete_action(self, mocked_send_github_status, mocked_update_commit, mocked_get_repo):
    #     mocked_update_commit.coro.return_value = True
    #     mocked_send_github_status.coro.return_value = True
    #     mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
    #
    #     for action in ('closed',):
    #         request_json = self._get_correct_request_data()
    #         request_json['action'] = action
    #         self._mock_request(request_json=request_json)
    #
    #         view = self.view(self.request)
    #         response = self.loop.run_until_complete(view.post())
    #         self._assert_response(response, status_code=HTTP_NO_CONTENT)
    #
    #     self.assertEqual(mocked_get_repo.call_count, 1)
    #     self.assertEqual(mocked_update_commit.call_count, 0)
    #     self.assertEqual(mocked_send_github_status.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_failure_create_update_action_redis(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_update_commit,
        mocked_get_repo
    ):
        mocked_update_commit.coro.return_value = False
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)

        for action in ('edited', 'opened', 'reopened',):
            request_json = self._get_correct_request_data()
            request_json['action'] = action
            self._mock_request(request_json=request_json)

            view = self.view(self.request)
            response = self.loop.run_until_complete(view.post())
            self._assert_response(
                response,
                body={'git_commit': 'Could not update commit'},
                status_code=HTTP_BAD_REQUEST
            )

        self.assertEqual(mocked_get_repo.call_count, 3)
        self.assertEqual(mocked_check_signature.call_count, 3)
        self.assertEqual(mocked_update_commit.call_count, 3)
        self.assertEqual(mocked_send_github_status.call_count, 0)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_failure_create_update_action_github(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_update_commit,
        mocked_get_repo
    ):
        mocked_update_commit.coro.return_value = True
        mocked_send_github_status.coro.return_value = False
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)

        for action in ('edited', 'opened', 'reopened',):
            request_json = self._get_correct_request_data()
            request_json['action'] = action
            self._mock_request(request_json=request_json)

            view = self.view(self.request)
            response = self.loop.run_until_complete(view.post())
            self._assert_response(
                response,
                body={'git_commit': 'Could not set status for commit'},
                status_code=HTTP_BAD_REQUEST
            )

        self.assertEqual(mocked_get_repo.call_count, 3)
        self.assertEqual(mocked_check_signature.call_count, 3)
        self.assertEqual(mocked_update_commit.call_count, 3)
        self.assertEqual(mocked_send_github_status.call_count, 3)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_failure_ignored_action(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_update_commit,
        mocked_get_repo
    ):
        mocked_update_commit.coro.return_value = False
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)

        for action in ('assigned', 'unassigned', 'labeled', 'unlabeled', 'synchronize'):
            request_json = self._get_correct_request_data()
            request_json['action'] = action
            self._mock_request(request_json=request_json)

            view = self.view(self.request)
            response = self.loop.run_until_complete(view.post())
            self._assert_response(response, status_code=HTTP_ACCEPTED)

        self.assertEqual(mocked_get_repo.call_count, 5)
        self.assertEqual(mocked_check_signature.call_count, 5)
        self.assertEqual(mocked_update_commit.call_count, 0)

    # @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    # @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    # @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    # def test_failure_delete_action(self, mocked_send_github_status, mocked_update_commit, mocked_get_repo):
    #     mocked_update_commit.coro.return_value = False
    #     mocked_send_github_status.coro.return_value = True
    #     mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
    #
    #     for action in ('closed',):
    #         request_json = self._get_correct_request_data()
    #         request_json['action'] = action
    #         self._mock_request(request_json=request_json)
    #
    #         view = self.view(self.request)
    #         response = self.loop.run_until_complete(view.post())
    #         self._assert_response(
    #             response,
    #             body={'git_commit': 'Could not find / delete commit'},
    #             status_code=HTTP_BAD_REQUEST
    #         )
    #
    #     self.assertEqual(mocked_get_repo.call_count, 1)
    #     self.assertEqual(mocked_update_commit.call_count, 0)
    #     self.assertEqual(mocked_send_github_status.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_is_valid_failure(self, mocked_check_signature, mocked_get_repo):
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(request_json={'foo': 'bar'})

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(
            response,
            body={'action': 'is required', 'pull_request': 'is required'},
            status_code=self.error_status
        )
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)


class PingEventTestCase(
    PostViewsTestMixin, AsyncMockMixin, AioHttpViewTestMixin, CoverRageViewsTestMixin, TestCase
):

    success_status = HTTP_OK
    error_status = HTTP_BAD_REQUEST
    fixtures_file = 'github_ping_event_payload.json'
    correct_headers = {'X-GitHub-Event': 'ping'}

    def setUp(self):
        super(PingEventTestCase, self).setUp()
        from cover_rage_server.api_views import GithubWebHookEventApiView
        self.view = GithubWebHookEventApiView

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.GithubWebHookEventApiView.check_signature')
    def test_success(
        self,
        mocked_check_signature,
        mocked_send_github_status,
        mocked_handle_inner_method,
        mocked_get_repo
    ):
        mocked_handle_inner_method.coro.return_value = True
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(response, body={'msg': 'pong'})
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)
        self.assertEqual(mocked_handle_inner_method.call_count, 0)
        self.assertEqual(mocked_send_github_status.call_count, 0)


class ResultsApiViewTestCase(
    PostViewsTestMixin, AsyncMockMixin, AioHttpViewTestMixin, CoverRageViewsTestMixin, TestCase
):

    success_status = HTTP_OK
    error_status = HTTP_BAD_REQUEST
    correct_match_info = {'token': 'valid_token'}

    def setUp(self):
        super(ResultsApiViewTestCase, self).setUp()
        from cover_rage_server.api_views import ResultsApiView
        self.view = ResultsApiView

    def _get_correct_request_data(self):
        return {
            'overall_coverage': 0.9,
            'uncovered_lines': {'/foo/bar.py': [1, 2, 3], '/foo/baz.py': []},
            'git_commit': '0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c'
        }

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_coverage_for_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_coverage_for_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.ResultsApiView.check_signature')
    def test_success(
        self,
        mocked_check_signature,
        mocked_update_coverage_for_repo,
        mocked_send_github_status,
        mocked_handle_inner_method,
        mocked_get_repo
    ):
        mocked_handle_inner_method.coro.return_value = True
        mocked_update_coverage_for_repo.coro.return_value = True
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(response)
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)
        self.assertEqual(mocked_handle_inner_method.call_count, 1)
        self.assertEqual(mocked_update_coverage_for_repo.call_count, 1)
        self.assertEqual(mocked_send_github_status.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_coverage_for_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_coverage_for_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.ResultsApiView.check_signature')
    def test_handle_inner_method_failure_redis_commit(
        self,
        mocked_check_signature,
        mocked_update_coverage_for_repo,
        mocked_send_github_status,
        mocked_handle_inner_method,
        mocked_get_repo
    ):
        mocked_handle_inner_method.coro.return_value = False
        mocked_update_coverage_for_repo.coro.return_value = True
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(
            response,
            body={'git_commit': 'Could not update commit'},
            status_code=self.error_status
        )
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)
        self.assertEqual(mocked_handle_inner_method.call_count, 1)
        self.assertEqual(mocked_update_coverage_for_repo.call_count, 0)
        self.assertEqual(mocked_send_github_status.call_count, 0)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_coverage_for_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_coverage_for_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.ResultsApiView.check_signature')
    def test_handle_inner_method_failure_redis_repo(
        self,
        mocked_check_signature,
        mocked_update_coverage_for_repo,
        mocked_send_github_status,
        mocked_handle_inner_method,
        mocked_get_repo
    ):
        mocked_handle_inner_method.coro.return_value = True
        mocked_update_coverage_for_repo.coro.return_value = False
        mocked_send_github_status.coro.return_value = True
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(
            response,
            body={'git_commit': 'Could not update repo'},
            status_code=self.error_status
        )
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)
        self.assertEqual(mocked_handle_inner_method.call_count, 1)
        self.assertEqual(mocked_update_coverage_for_repo.call_count, 1)
        self.assertEqual(mocked_send_github_status.call_count, 0)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_coverage_for_commit', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.send_github_status', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.update_coverage_for_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.ResultsApiView.check_signature')
    def test_handle_inner_method_failure_github(
        self,
        mocked_check_signature,
        mocked_update_coverage_for_repo,
        mocked_send_github_status,
        mocked_handle_inner_method,
        mocked_get_repo
    ):
        mocked_handle_inner_method.coro.return_value = True
        mocked_update_coverage_for_repo.coro.return_value = True
        mocked_send_github_status.coro.return_value = False
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(
            response,
            body={'git_commit': 'Could not set status for commit'},
            status_code=self.error_status
        )
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)
        self.assertEqual(mocked_handle_inner_method.call_count, 1)
        self.assertEqual(mocked_update_coverage_for_repo.call_count, 1)
        self.assertEqual(mocked_send_github_status.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.ResultsApiView.check_signature')
    def test_is_valid_failure(self, mocked_check_signature, mocked_get_repo):
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(request_json={'foo': 'bar'})

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.post())
        self._assert_response(
            response,
            body={
                'foo': 'foo is not allowed key',
                'git_commit': 'is required',
                'overall_coverage': 'is required',
                'uncovered_lines': 'is required'
            },
            status_code=self.error_status
        )
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_check_signature.call_count, 1)


class BadgeApiViewTestCase(AsyncMockMixin, AioHttpViewTestMixin, CoverRageViewsTestMixin, TestCase):

    def setUp(self):
        super(BadgeApiViewTestCase, self).setUp()
        from cover_rage_server.api_views import BadgeApiView
        self.view = BadgeApiView

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    def test_success_call(self, mocked_get_repo):
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request()

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.get())

        badge_mock__path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'badge_99_good.svg')
        with open(badge_mock__path, 'r') as f:
            expected_badge = f.read().replace('\n', '').encode('utf-8')
        self.assertIsInstance(response.body, bytes)
        self.assertEqual(response.body, expected_badge)
        self.assertEqual(response.status, HTTP_OK)
        self.assertEqual(response.content_type, 'image/svg+xml')

    def test_public_token_failure(self):
        self._mock_request(match_info={})

        view = self.view(self.request)

        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.get())

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    def test_get_repo_failure(self, mocked_get_repo):
        mocked_get_repo.coro.return_value = ('key', None)
        self._mock_request()

        view = self.view(self.request)

        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.get())
        self.assertEqual(mocked_get_repo.call_count, 1)


class StatusApiViewTestCase(AsyncMockMixin, AioHttpViewTestMixin, CoverRageViewsTestMixin, TestCase):

    success_status = HTTP_OK

    def setUp(self):
        super(StatusApiViewTestCase, self).setUp()
        from cover_rage_server.api_views import StatusApiView
        self.view = StatusApiView

    def test_public_token_failure(self):
        self._mock_request(match_info={'sha': 'sha'})

        view = self.view(self.request)

        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.get())

    def test_sha_failure(self):
        self._mock_request(match_info={'token': 'valid_token'})

        view = self.view(self.request)

        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.get())

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    def test_get_repo_failure(self, mocked_get_repo):
        mocked_get_repo.coro.return_value = ('key', None)
        self._mock_request(match_info={'token': 'valid_token', 'sha': 'sha'})

        view = self.view(self.request)

        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.get())
        self.assertEqual(mocked_get_repo.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.get_commit', new_callable=AsyncMockMixin.coro_mock)
    def test_get_commit_failure(self, mocked_get_commit, mocked_get_repo):
        mocked_get_commit.coro.return_value = None
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(match_info={'token': 'valid_token', 'sha': 'sha'})

        view = self.view(self.request)

        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.get())
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_get_commit.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.get_commit', new_callable=AsyncMockMixin.coro_mock)
    def test_get_commit_failure(self, mocked_get_commit, mocked_get_repo):
        mocked_get_commit.coro.return_value = None
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(match_info={'token': 'valid_token', 'sha': 'sha'})

        view = self.view(self.request)

        with self.assertRaises(HTTPNotFound):
            self.loop.run_until_complete(view.get())
        self.assertEqual(mocked_get_repo.call_count, 1)
        self.assertEqual(mocked_get_commit.call_count, 1)

    @mock.patch('cover_rage_server.api_views.get_repo', new_callable=AsyncMockMixin.coro_mock)
    @mock.patch('cover_rage_server.api_views.get_commit', new_callable=AsyncMockMixin.coro_mock)
    def test_success_call(self, mocked_get_commit, mocked_get_repo):
        get_commit_mock = {
            'overall_coverage': 'valid_private_token',
            'uncovered_lines': {
                '/foo/bar.py': [1, 2, 3],
                '/foo/baz.py': []
            },
            'created_at': '2015-05-05T23:40:27Z',
        }

        mocked_get_commit.coro.return_value = get_commit_mock
        mocked_get_repo.coro.return_value = copy(self.correct_get_repo)
        self._mock_request(match_info={'token': 'valid_token', 'sha': 'sha'})

        view = self.view(self.request)
        response = self.loop.run_until_complete(view.get())

        self._assert_response(response, body=get_commit_mock)
