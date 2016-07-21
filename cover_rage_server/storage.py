"""
Hashes:
-------

repositories:
  key: repo_id
  fields:
    - rage_public_token
    - rage_private_token
    - repo_access_token
    - min_good_coverage
    - coverage
  description: stores main data about repo such as access token, Cover-Rage tokens, other settings

repositories_backward:
  key: rage_public_token
  fields:
    - repo_id
  description: required for backward repo search by Cover-Rage public token

commits_coverage:
  key: commit_id
  fields:
    - overall_coverage
    - uncovered_lines (JSON):
      - file 1: [line number 1, line number 2, line number K]
      - file 2: [line number 1, line number 2, line number L]
      ...
      - file N: [line number 1, line number 2, line number M]
    - created_at
    - updated_at (for commit from pull request)
    - action (for commit from pull request)
    - id of pull request (for commit from pull request)
    - number of pull request (for commit from pull request)
    - url of pull request (for commit from pull request)


Hash Keys:
----------

repo_id:
  parts:
    - prefix
    - kind (`gh` or `bb`)
    - owner
    - repo name
  delimiter: /
  examples:
    - r/gh/john_doe/cool_project
    - r/bb/jane_doe/test_project

commit_id:
  parts:
    - prefix
    - repo_id
    - commit hash
  delimiter: #
  examples:
    - c#r/gh/john_doe/cool_project#1234qwerty5678
    - c#r/bb/jane_doe/test_project#0987sha1234
"""

import json
import logging
# from secrets import token_urlsafe  # TODO: uncomment this in Python 3.6

import aioredis
from aioredis.errors import RedisError

from . import settings
from .secrets import token_urlsafe  # noqa # TODO: remove this in Python 3.6


__all__ = [
    'create_repo', 'get_repo', 'update_coverage_for_repo',
    'get_commit', 'update_commit', 'delete_commit', 'update_coverage_for_commit'
]


logger = logging.getLogger('cover_rage')

RAGE_SRV_REPO_PREFIX = 'r'
RAGE_SRV_COVERAGE_PREFIX = 'c'


def dict_to_redis_iterable(value: dict) -> dict:
    """
    Covert Python dictionary to Redis HMSET-command format - http://redis.io/commands/hmset
    :param value: dict
    :raises: AssertationError
    :return: list
    """
    assert isinstance(value, dict)
    result = []
    for k, v in value.items():
        result.extend([k, v])
    return result


def convert_bytes_dict_to_string_dict(value: dict) -> dict:

    def convert(data):
        if isinstance(data, bytes):
            return data.decode()
        elif isinstance(data, dict):
            return dict(map(convert, data.items()))
        elif isinstance(data, (list, tuple)):
            return type(data)(map(convert, data))
        else:
            return data

    return convert(value)


def get_repo_id(repo_kind: str, repo_owner: str, repo_name: str) -> str:
    assert isinstance(repo_kind, str)
    assert isinstance(repo_owner, str)
    assert isinstance(repo_name, str)
    assert repo_kind in ('gh', 'bb')
    assert repo_owner
    assert repo_name
    return '{prefix}/{kind}/{owner}/{name}'.format(
        prefix=RAGE_SRV_REPO_PREFIX,
        kind=repo_kind,
        owner=repo_owner,
        name=repo_name
    )


def split_repo_id(repo_id: str) -> (str, str, str):
    assert isinstance(repo_id, str)
    assert repo_id
    repo_parts = tuple(repo_id.split('/'))
    assert len(repo_parts) == 4
    prefix, repo_kind, repo_owner, repo_name = repo_parts
    assert prefix == RAGE_SRV_REPO_PREFIX
    assert repo_kind in ('gh', 'bb')
    assert repo_owner
    assert repo_name
    return repo_kind, repo_owner, repo_name


def get_commit_id(repo_id: str, commit_hash: str) -> str:
    assert isinstance(repo_id, str)
    assert isinstance(commit_hash, str)
    assert repo_id
    assert commit_hash
    return '{prefix}#{repo_id}#{commit_hash}'.format(
        prefix=RAGE_SRV_COVERAGE_PREFIX,
        repo_id=repo_id,
        commit_hash=commit_hash
    )


def split_commit_id(commit_id: str) -> (str, str):
    assert isinstance(commit_id, str)
    assert commit_id
    commit_parts = tuple(commit_id.split('#'))
    assert len(commit_parts) == 3
    prefix, repo_id, commit_id = commit_parts
    assert prefix == RAGE_SRV_COVERAGE_PREFIX
    assert repo_id
    assert commit_id
    return repo_id, commit_id


async def create_redis_pool(loop: object) -> object:
    """
    Helper to create redis pool
    :param loop: event loop
    :return: Redis pool coroutine
    """
    return await aioredis.create_pool((settings.REDIS_HOST, settings.REDIS_PORT), db=settings.REDIS_DB, loop=loop)


# TODO: cover with tests
async def create_repo(
    pool: object,
    repo_id: str,
    repo_access_token: str,
    min_good_coverage=settings.MIN_GOOD_COVERAGE_PERCENTAGE
) -> (str, str):
    """
    Add data about project to Redis
    :param pool: Redis connection
    :param repo_id: repo id, like `/github/alex/test_project`
    :param repo_access_token: repo access token (Github / Bitbucket token)
    :param min_good_coverage: minimal good coverage percentage (for background color of badge)
    :raises: AssertationError
    :return: tuple with Cover-Rage public and private tokens
    """
    rage_public_token = token_urlsafe(16)
    rage_private_token = token_urlsafe(48)

    async with pool.get() as redis:
        redis_already_has_this_repo = await redis.exists(repo_id)

    assert not redis_already_has_this_repo, 'This repo {} has been already added to cover-rage'.format(repo_id)

    repo = {
        'rage_public_token': rage_public_token,
        'rage_private_token': rage_private_token,
        'repo_access_token': repo_access_token,
        'min_good_coverage': min_good_coverage,
    }

    async with pool.get() as redis:
        await redis.hmset(repo_id, *dict_to_redis_iterable(repo))
        await redis.set(rage_public_token, repo_id)

    return rage_public_token, rage_private_token


# TODO: cover with tests
async def get_repo(pool: object, token=None, repo_id=None) -> (str, dict):
    """
    Get repo from Redis by `repo_id` or `token` (Cover-Rage public token).
    One of `repo_id` or `token` should be set - or AssertationError would be raised.
    :param pool: Redis pool
    :param token: Cover-Rage public token (could be None)
    :param repo_id: Redis repo hash key (could be None)
    :raises: AssertationError
    :return: tuple(`repo_id`, repo data)
    """
    if repo_id is not None:
        key = repo_id
    elif token is not None:
        async with pool.get() as redis:
            key = await redis.get(token)
    else:
        key = None
    assert key
    key = key.decode()
    async with pool.get() as redis:
        repo = await redis.hgetall(key)
        assert repo
        repo = convert_bytes_dict_to_string_dict(repo)
        if 'min_good_coverage' in repo:
            repo['min_good_coverage'] = int(repo['min_good_coverage'])
        if 'coverage' in repo:
            repo['coverage'] = int(repo['coverage'])
        return key, repo


# TODO: cover with tests
async def update_coverage_for_repo(pool: object, repo_id: str, coverage: int) -> bool:
    """
    Update repo data with coverage
    :param pool: Redis pool
    :param repo_id: Redis repo hash key
    :param coverage: coverage percentage
    :return: bool
    """
    try:
        async with pool.get() as redis:
            repo_exists = await redis.exists(repo_id)
            if repo_exists:
                await redis.hmset(repo_id, 'coverage', coverage)
                return True
            else:
                return False
    except RedisError as e:
        message = {
            'parameters': {
                'repo_id': repo_id,
                'coverage': coverage,
            },
            'exception': e
        }
        logging.error(str(message))
        return False


# TODO: cover with tests
async def get_commit(pool: object, repo_id: str, commit_hash: str) -> dict:
    """
    Get commit data from Redis
    :param pool: Redis pool
    :param repo_id: Redis repo hash key
    :param commit_hash: commit hash
    :return: dict
    """
    commit_id = get_commit_id(repo_id, commit_hash)
    try:
        async with pool.get() as redis:
            commit = await redis.hgetall(commit_id)
            assert commit
            commit = convert_bytes_dict_to_string_dict(commit)
            if 'uncovered_lines' in commit:
                commit['uncovered_lines'] = json.loads(commit['uncovered_lines'])
            return commit
    except RedisError as e:
        message = {
            'parameters': {
                'repo_id': repo_id,
                'commit_hash': commit_hash,
            },
            'exception': e
        }
        logging.error(str(message))


# TODO: cover with tests
async def update_commit(pool: object, repo_id: str, commit_hash: str, commit_data: dict) -> bool:
    """
    Create mapping `commit_data` for commit with `commit_hash` in repo `repo_id` and return True.
    If mapping for this commit (in this repo) does not exist - return False.
    :param pool: Redis pool
    :param repo_id: Cover-Rage public token
    :param commit_hash: commit hash
    :param commit_data: commit data
    :return: bool
    """
    commit_id = get_commit_id(repo_id, commit_hash)
    try:
        async with pool.get() as redis:
            await redis.hmset(commit_id, *dict_to_redis_iterable(commit_data))
    except RedisError as e:
        message = {
            'parameters': {
                'repo_id': repo_id,
                'commit_hash': commit_hash,
                'commit_data': commit_data,
            },
            'exception': e
        }
        logging.error(str(message))
        return False
    else:
        return True


# TODO: cover with tests
async def delete_commit(pool: object, repo_id: str, commit_hash: str) -> None:
    """
    Delete mapping for commit with `commit_hash` in repo `repo_id` and return True.
    If mapping for this commit (in this repo) does not exist - return False.
    :param pool: Redis pool
    :param repo_id: Cover-Rage public token
    :param commit_hash: commit hash
    :return: bool
    """
    commit_id = get_commit_id(repo_id, commit_hash)
    try:
        async with pool.get() as redis:
            await redis.delete(commit_id)
    except RedisError as e:
        message = {
            'parameters': {
                'repo_id': repo_id,
                'commit_hash': commit_hash,
            },
            'exception': e
        }
        logging.error(str(message))
        return False
    else:
        return True


# TODO: cover with tests
async def update_coverage_for_commit(pool: object, repo_id: str, commit_hash: str, coverage_data: dict) -> bool:
    """
    Update data for commit with `commit_hash` in repo `repo_id` with coverage data and return True.
    If mapping for this commit (in this repo) does not exist - return False.
    :param pool: Redis pool
    :param repo_id: Cover-Rage public token
    :param commit_hash: commit hash
    :param coverage_data: dict with coverage data
    :return: bool
    """
    commit_id = get_commit_id(repo_id, commit_hash)
    try:
        async with pool.get() as redis:
            await redis.hmset(commit_id, *dict_to_redis_iterable(coverage_data))
    except RedisError as e:
        message = {
            'parameters': {
                'repo_id': repo_id,
                'commit_hash': commit_hash,
                'coverage_data': coverage_data,
            },
            'exception': e
        }
        logging.error(str(message))
        return False
    else:
        return True
