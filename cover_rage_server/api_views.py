from copy import deepcopy
from hashlib import sha1
import hmac
import json
import urllib.parse as urlparse

import trafaret
from aiohttp import web, ClientSession, MultiDict
from aiohttp.web_exceptions import HTTPUnauthorized, HTTPNotFound

from . import settings
from .badge import render_badge
from .api_validators import (
    cover_rage_client_validator,
    GITHUB_PULL_REQUEST_TRIGGER_CREATE_UPDATE_ACTIONS,
    GITHUB_PULL_REQUEST_TRIGGER_REMOVE_ACTIONS,
    github_push_event_validator,
    github_pull_request_event_validator,
    github_status_validator,
    GITHUB_AVAILABLE_STATUSES,
    GITHUB_ERROR_STATUS,
    GITHUB_FAILURE_STATUS,
    GITHUB_PENDING_STATUS,
    GITHUB_SUCCESS_STATUS,
    cover_rage_client_to_redis,
    github_push_to_redis,
    github_pull_request_to_redis,
)
from .storage import (
    get_repo, update_coverage_for_repo, split_repo_id, get_commit, update_commit, update_coverage_for_commit
)

HTTP_OK = 200
HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400


COVER_RAGE_CONTEXT = 'continuous-integration/cover_rage'


FAILURE_CHECK_DESCRIPTION = 'Not all lines are covered with tests'
PENDING_CHECK_DESCRIPTION = 'Pending coverage check'
SUCCESS_CHECK_DESCRIPTION = 'All new lines are covered with tests'
ERROR_CHECK_CLOSED_PULL_REQUEST_DESCRIPTION = 'Pull request was closed'


def cover_rage_status_url(public_token: str, sha: str) -> str:
    """
    Helper to get status url for `sha` commit
    :param public_token: Cover-Rage app public token
    :param sha: git commit hash
    :return: absolute url for `sha` commit check
    """
    url = urlparse.urlunparse(
        (
            settings.SRV_SCHEME,
            settings.SRV_HOST,
            settings.SRV_STATUS_URL.format(public_token=public_token, sha=sha),
            '',
            '',
            ''
        )
    )
    return url


# TODO: cover with tests
async def send_github_status(
    loop: object,
    repo_owner: str,
    repo_name: str,
    sha: str,
    state: str,
    target_url: str,
    description: str,
    context: str,
    github_access_token: str
) -> bool:
    """
    Helper to set Github status
    :param loop: event loop
    :param repo_owner: repo owner
    :param repo_name: repo name
    :param sha: commit hash
    :param state: status, could be one of: error / failure / pending / success
    :param target_url: url for Cover-Rage check of commit
    :param description: short description of status
    :param context: context identifier
    :param github_access_token: Github access token
    :raises: AssertationError
    :return: True if setting status was successful
    """
    assert isinstance(repo_owner, str)
    assert isinstance(repo_name, str)
    assert isinstance(sha, str)
    assert isinstance(state, str)
    assert isinstance(target_url, str)
    assert isinstance(description, str)
    assert isinstance(context, str)
    assert isinstance(github_access_token, str)
    assert repo_owner
    assert repo_name
    assert sha
    assert state in GITHUB_AVAILABLE_STATUSES
    assert target_url
    assert description
    assert context
    assert github_access_token

    github_url = 'https://api.github.com/repos/{repo_owner}/{repo_name}/statuses/{sha}'.format(
        repo_owner=repo_owner, repo_name=repo_name, sha=sha
    )

    async with ClientSession(loop=loop) as session:
        headers = {
            'Authorization': 'token {token}'.format(token=github_access_token),
            'Content-Type': 'application/json'
        }
        data = {
            'state': state,
            'target_url': target_url,
            'description': description,
            'context': context,
        }
        async with session.post(github_url, headers=headers, data=json.dumps(data)) as response:
            return response.status == 201


# TODO: cover with tests
async def get_github_status(loop: object, repo_owner: str, repo_name: str, sha: str, github_access_token: str) -> str:
    """
    Helper to get Github status
    :param loop: event loop
    :param repo_owner: repo owner
    :param repo_name: repo name
    :param sha: commit hash
    :param github_access_token: Github access token
    :raises: AssertationError
    :return: Github status, could be one of: error / failure / pending / success
    """
    assert isinstance(repo_owner, str)
    assert isinstance(repo_name, str)
    assert isinstance(sha, str)
    assert isinstance(github_access_token, str)
    assert repo_owner
    assert repo_name
    assert sha
    assert github_access_token

    github_url = 'https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{sha}/status'.format(
        repo_owner=repo_owner, repo_name=repo_name, sha=sha
    )

    async with ClientSession(loop=loop) as session:
        headers = {
            'Authorization': 'token {token}'.format(token=github_access_token),
            'Content-Type': 'application/json'
        }
        async with session.get(github_url, headers=headers) as response:
            if response.status == 200:
                response_json = await response.json()
                try:
                    validated_response = github_status_validator.check(response_json)
                    if validated_response['sha'] == sha:
                        return validated_response['status']
                except trafaret.DataError:
                    pass


class BadgeApiView(web.View):
    """
    View that handles coverage badge
    """

    encoding = 'utf-8'
    content_type = 'image/svg+xml'
    public_token = None
    sha = None
    repo_id = None
    project = None
    commit = None

    async def get(self):
        self.public_token = self.request.match_info.get('token')
        if not self.public_token:
            raise HTTPNotFound

        self.repo_id, self.project = await get_repo(self.request.app.redis_pool, token=self.public_token)
        if self.project is None:
            raise HTTPNotFound

        coverage = self.project.get('coverage', 0)
        min_good_coverage = self.project.get('min_good_coverage', settings.MIN_GOOD_COVERAGE_PERCENTAGE)
        badge = render_badge(coverage, coverage >= min_good_coverage)

        return web.Response(
            body=badge,
            headers=MultiDict({'Content-Disposition': 'Inline'}),
            status=HTTP_OK,
            content_type=self.content_type
        )


class _CoverRageCommonApiView(web.View):
    """
    Common class for all Cover-Rage API views:
      - request data validation (`self.validator` should be set)
      - searching repo in Redis
      - check Github signature (set `signature_token` parameter or override this method)
      - custom handling (should be overridden)
      - response / errors handling
    """

    validator = None
    raw_data = None
    public_token = None
    repo_id = None
    project = None
    validated_data = {}
    errors = {}
    encoding = 'utf-8'
    content_type = 'application/json'
    response_success_status = HTTP_OK
    response_error_status = HTTP_BAD_REQUEST
    signature_token = 'X-Hub-Signature'

    def check_signature(self):
        """

        :raises: HTTPUnauthorized
        """
        header_signature = self.request.headers.get(self.signature_token)
        if header_signature is None:
            raise HTTPUnauthorized

        try:
            sha_name, signature = header_signature.split('=')
        except ValueError:
            raise HTTPUnauthorized
        if sha_name != 'sha1':
            raise HTTPUnauthorized

        mac = hmac.new(self.project.get('rage_private_token').encode('utf-8'), msg=self.request.data, digestmod=sha1)
        if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
            raise HTTPUnauthorized

    def is_valid(self, validator):
        assert validator
        try:
            self.validated_data = validator.check(self.raw_data)
            return True
        except trafaret.DataError:
            self.errors = trafaret.extract_error(validator, self.raw_data)
            return False

    async def handle(self):  # pragma: no cover
        raise NotImplemented

    async def post(self):
        """
        Common POST handler:
        --------------------
        1) Get project from public token.
        2) Check authorization (if `self.check_authorization` is True).
        3) Validate input data with `self.validator`.
        4) Do something with this data - override `handle` method.
        5) Return response.

        :raises: HTTPUnauthorized, HTTPForbidden, HTTPNotFound
        """

        # Get public token from url
        self.public_token = self.request.match_info.get('token')
        if not self.public_token:
            raise HTTPNotFound

        # Get repo id and data from Redis or raise 404
        self.repo_id, self.project = await get_repo(self.request.app.redis_pool, token=self.public_token)
        if self.project is None:
            raise HTTPNotFound

        # Check Github signature
        self.check_signature()

        # Return response
        self.raw_data = await self.request.json()
        response, response_status = await self.handle()
        return web.Response(
            body=bytes(json.dumps(response), self.encoding),
            status=response_status or self.response_success_status,
            content_type=self.content_type
        )


# TODO: Implement Bitbucket web hooks handling
class BitbucketWebHookEventApiView(_CoverRageCommonApiView):

    pass


class GithubWebHookEventApiView(_CoverRageCommonApiView):

    async def handle(self):
        event = self.request.headers.get('X-GitHub-Event')
        if event == 'push':
            response, response_status = await self.handle_push()
        elif event == 'pull_request':
            response, response_status = await self.handle_pull_request()
        else:
            response, response_status = {'msg': 'pong'}, HTTP_OK

        return response, response_status

    async def handle_pull_request(self):
        if self.is_valid(github_pull_request_event_validator):
            commit_data = github_pull_request_to_redis(self.validated_data)
            git_commit = commit_data.pop('sha')

            assert 'action' in commit_data
            if commit_data['action'] in GITHUB_PULL_REQUEST_TRIGGER_CREATE_UPDATE_ACTIONS:
                description = PENDING_CHECK_DESCRIPTION  # TODO: cover with tests
                status = GITHUB_PENDING_STATUS  # TODO: cover with tests
            elif commit_data['action'] in GITHUB_PULL_REQUEST_TRIGGER_REMOVE_ACTIONS:
                description = ERROR_CHECK_CLOSED_PULL_REQUEST_DESCRIPTION  # TODO: cover with tests
                status = GITHUB_ERROR_STATUS  # TODO: cover with tests
            else:
                # Ignore other Github pull request actions
                description = None
                status = None

            if all((description, status)):
                if not await update_commit(self.request.app.redis_pool, self.repo_id, git_commit, commit_data):
                    return {'git_commit': 'Could not update commit'}, HTTP_BAD_REQUEST

                _, repo_owner, repo_name = split_repo_id(self.repo_id)
                if await send_github_status(
                    self.request.app.loop,
                    repo_owner,
                    repo_name,
                    git_commit,
                    status,
                    cover_rage_status_url(self.public_token, git_commit),
                    description,
                    COVER_RAGE_CONTEXT,
                    self.project['repo_access_token']
                ):
                    return {}, HTTP_OK
                else:
                    return {'git_commit': 'Could not set status for commit'}, HTTP_BAD_REQUEST
            else:
                return {}, HTTP_ACCEPTED
        else:
            return deepcopy(self.errors), self.response_error_status

    async def handle_push(self):
        if self.is_valid(github_push_event_validator):
            commit_data = github_push_to_redis(self.validated_data)
            git_commit = commit_data.pop('sha')

            if not await update_commit(self.request.app.redis_pool, self.repo_id, git_commit, commit_data):
                return {'git_commit': 'Could not update commit'}, HTTP_BAD_REQUEST

            _, repo_owner, repo_name = split_repo_id(self.repo_id)
            if await send_github_status(
                self.request.app.loop,
                repo_owner,
                repo_name,
                git_commit,
                GITHUB_PENDING_STATUS,
                cover_rage_status_url(self.public_token, git_commit),
                PENDING_CHECK_DESCRIPTION,
                COVER_RAGE_CONTEXT,
                self.project['repo_access_token']
            ):
                return {}, HTTP_OK
            else:
                return {'git_commit': 'Could not set status for commit'}, HTTP_BAD_REQUEST
        else:
            return deepcopy(self.errors), self.response_error_status


class ResultsApiView(_CoverRageCommonApiView):
    """
    Update repo information with coverage data from Cover-Rage client.
    """

    validator = cover_rage_client_validator
    signature_token = 'X-CoverRage-Signature'

    async def handle(self):
        if self.is_valid(cover_rage_client_validator):
            coverage_data = cover_rage_client_to_redis(self.validated_data)
            git_commit = coverage_data.pop('git_commit')

            if not await update_coverage_for_commit(
                self.request.app.redis_pool,
                self.repo_id,
                git_commit,
                coverage_data
            ):
                return {'git_commit': 'Could not update commit'}, HTTP_BAD_REQUEST

            current_coverage = int(round(self.validated_data['overall_coverage'] * 100))

            if await update_coverage_for_repo(self.request.app.redis_pool, self.repo_id, current_coverage):
                _, repo_owner, repo_name = split_repo_id(self.repo_id)
                if self.validated_data['uncovered_lines']:
                    description = FAILURE_CHECK_DESCRIPTION  # TODO: cover with tests
                    status = GITHUB_FAILURE_STATUS  # TODO: cover with tests
                else:
                    description = SUCCESS_CHECK_DESCRIPTION  # TODO: cover with tests
                    status = GITHUB_SUCCESS_STATUS  # TODO: cover with tests
                if await send_github_status(
                    self.request.app.loop,
                    repo_owner,
                    repo_name,
                    git_commit,
                    status,
                    cover_rage_status_url(self.public_token, git_commit),
                    description,
                    COVER_RAGE_CONTEXT,
                    self.project['repo_access_token']
                ):
                    return {}, HTTP_OK
                else:
                    return {'git_commit': 'Could not set status for commit'}, HTTP_BAD_REQUEST
            else:
                return {'git_commit': 'Could not update repo'}, HTTP_BAD_REQUEST
        else:
            response = deepcopy(self.errors)
            response_status = self.response_error_status
        return response, response_status


class StatusApiView(web.View):
    """
    View that handles status of check for required commit
    """

    encoding = 'utf-8'
    content_type = 'application/json'
    public_token = None
    sha = None
    repo_id = None
    project = None
    commit = None

    async def get(self):
        """
        Get commit data from Redis
        :raises: HTTPNotFound
        :return:
        """
        self.public_token = self.request.match_info.get('token')
        if not self.public_token:
            raise HTTPNotFound

        self.sha = self.request.match_info.get('sha')
        if not self.sha:
            raise HTTPNotFound

        self.repo_id, self.project = await get_repo(self.request.app.redis_pool, token=self.public_token)
        if self.project is None:
            raise HTTPNotFound

        self.commit = await get_commit(self.request.app.redis_pool, self.repo_id, self.sha)
        if self.commit is None:
            raise HTTPNotFound

        return web.Response(
            body=bytes(json.dumps(self.commit), self.encoding),
            status=HTTP_OK,
            content_type=self.content_type
        )
