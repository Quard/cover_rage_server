#!/usr/bin/env python
import json

import asyncio
import sys
import urllib.parse as urlparse

from aiohttp import ClientSession

from . import settings
from .storage import create_redis_pool, get_repo_id, create_repo


async def create_github_web_hook(
    loop: object,
    repo_owner: str,
    repo_name: str,
    github_token: str,
    public_token: str,
    private_token: str
) -> str:
    """
    Helper to create Github web hooks for for PUSH & PULL REQUEST events
    https://developer.github.com/v3/repos/hooks/#create-a-hook

    :param loop: event loop
    :param repo_owner: Github repo owner
    :param repo_name: Github repo name
    :param github_token: Github access token
    :param public_token: Cover-Rage public token
    :param private_token: Cover-Rage private token
    :return: Github web hook urls for PUSH & PULL REQUEST events
    """
    github_url = 'https://api.github.com/repos/{repo_owner}/{repo_name}/hooks'.format(
        repo_owner=repo_owner, repo_name=repo_name
    )
    rage_server_event_hook_url = urlparse.urlunparse(
        (
            settings.SRV_SCHEME,
            settings.SRV_HOST,
            settings.SRV_API_GITHUB_WEB_HOOK_URL.format(public_token=public_token),
            '',
            '',
            ''
        )
    )
    async with ClientSession(loop=loop) as session:
        headers = {
            'Authorization': 'token {token}'.format(token=github_token),
            'Content-Type': 'application/json'
        }
        data = {
            'name': 'web',
            'events': ['push', 'pull_request'],
            'config': {
                'url': rage_server_event_hook_url,
                'content_type': 'json',
                'secret': private_token
            }
        }
        async with session.post(github_url, headers=headers, data=json.dumps(data)) as response:
            response_json = await response.json()
            if response.status == 201 and 'url' in response_json:
                return response_json['url']


# TODO: Implement Bitbucket web hooks creation
async def create_bitbucket_web_hook(
    loop: object,
    repo_owner: str,
    repo_name: str,
    bitbucket_token: str,
    public_token: str,
    private_token: str
) -> str:
    """
    Helper to create Bitbucket web hooks for for PUSH & PULL REQUEST events
    :param loop: event loop
    :param repo_owner: Bitbucket repo owner
    :param repo_name: Bitbucket repo name
    :param bitbucket_token: Bitbucket access token
    :param public_token: Cover-Rage public token
    :param private_token: Cover-Rage private token
    :return: Bitbucket web hook url for PUSH & PULL REQUEST events
    """
    return None, None


async def add_project_to_redis(loop: object, repo_kind: str, repo_owner: str, repo_name: str, repo_token: str) -> None:

    redis_pool = await create_redis_pool(loop)

    # Generate COver-Rage tokens
    repo_id = get_repo_id(repo_kind, repo_owner, repo_name)
    public_token, private_token = await create_repo(redis_pool, repo_id, repo_token)
    assert public_token
    assert private_token
    print('Success: Cover-Rage tokens were generated.')
    print('\n')

    # Create web hooks for Github / Bitbucket
    if repo_kind == 'gh':
        web_hook_url = await create_github_web_hook(
            loop, repo_owner, repo_name, repo_token, public_token, private_token
        )
    elif repo_kind == 'bb':
        web_hook_url = await create_bitbucket_web_hook(
            loop, repo_owner, repo_name, repo_token, public_token, private_token
        )
    else:
        web_hook_url = None

    if web_hook_url is not None:
        print('Success: web hook for PUSH / PULL REQUEST events was created.')
        print(web_hook_url)
    else:
        print('Error: web hook for PUSH / PULL REQUEST events was not created. Please create this web hook manually.')
    print('\n')

    # Cover-Rage client script on CI
    client_script = 'rage_client {server_url} {token} </path/to/git/root> </path/to/coverage.xml>'.format(
        server_url=urlparse.urlunparse(
            (
                settings.SRV_SCHEME,
                settings.SRV_HOST,
                settings.SRV_API_SEND_RESULTS_URL.format(public_token=public_token),
                '',
                '',
                '',
            )
        ),
        token=private_token
    )
    print('CI script: pip install cover-rage-client && {client_script}'.format(client_script=client_script))

    await redis_pool.clear()
    redis_pool.close()


def __main__():  # pragma: no cover

    if len(sys.argv) != 5:
        print('Usage: {} <repo_kind: gh|bb> <repo_owner> <repo_name> <repo_token>'.format(sys.argv[0]))
        exit(1)

    main_loop = asyncio.get_event_loop()
    main_loop.run_until_complete(
        add_project_to_redis(
            main_loop,
            sys.argv[1],
            sys.argv[2],
            sys.argv[3],
            sys.argv[4],
        )
    )
