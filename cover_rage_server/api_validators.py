import json

import trafaret as t


ISO8601_DATETIME_REGEX = r'\d+\-\d+\-\d+T\d+\:\d+\:\d+[Z\-\+\:0-9]{0,6}'


"""
Validate and convert Cover-Rage client request to Python dictionary:
{
    'overall_coverage': float(<overall_coverage>),
    'git_commit': str(<git_commit>),
    'uncovered_lines': {
        str(<file 1>): [int(<line number 1>, int(<line number 2>, ..., int(<line number K>,],
        str(<file 2>): [int(<line number 1>, int(<line number 2>, ..., int(<line number L>,],
        str(<file N>): [int(<line number 1>, int(<line number 2>, ..., int(<line number M>,],
    }
}
"""
cover_rage_client_validator = t.Dict({
    t.Key('overall_coverage') >> 'overall_coverage': t.Float,
    t.Key('git_commit') >> 'git_commit': t.String,
    t.Key('uncovered_lines') >> 'uncovered_lines': t.Mapping(t.String, t.List(t.Int)),
})

# Available Github pull requests actions
# https://developer.github.com/v3/activity/events/types/#pullrequestevent
GITHUB_PULL_REQUEST_ACTIONS = (
    'assigned',
    'unassigned',
    'labeled',
    'unlabeled',
    'opened',
    'edited',
    'closed',
    'reopened',
    'synchronize',
)

# Github pull requests actions that triggers create / update Cover-Rage checks
GITHUB_PULL_REQUEST_TRIGGER_CREATE_UPDATE_ACTIONS = (
    'opened',
    'reopened',
    'edited',
)

# Github pull requests actions that triggers removing Cover-Rage check
GITHUB_PULL_REQUEST_TRIGGER_REMOVE_ACTIONS = (
    'closed'
)

# Regular expression for available Github pull requests actions
github_action_regex = r'|'.join([r'\b{action}\b'.format(action=a) for a in GITHUB_PULL_REQUEST_ACTIONS])

# Github statuses
GITHUB_ERROR_STATUS = 'error'
GITHUB_FAILURE_STATUS = 'failure'
GITHUB_PENDING_STATUS = 'pending'
GITHUB_SUCCESS_STATUS = 'success'
GITHUB_AVAILABLE_STATUSES = (GITHUB_ERROR_STATUS, GITHUB_FAILURE_STATUS, GITHUB_PENDING_STATUS, GITHUB_SUCCESS_STATUS)

# Regular expression for available Github statuses
github_status_regex = r'|'.join([r'\b{action}\b'.format(action=a) for a in GITHUB_AVAILABLE_STATUSES])

"""
Validate and convert Github `PUSH` event payload to Python dictionary:
{
    'head_commit': {
        'sha': str(<sha>),
        'created_at': str(<timestamp>),
    },
}

https://developer.github.com/v3/activity/events/types/#pushevent
"""
github_push_event_validator = t.Dict({
    t.Key('head_commit') >> 'head_commit': t.Dict({
        t.Key('id') >> 'sha': t.String(),
        t.Key('timestamp') >> 'created_at': t.String(regex=ISO8601_DATETIME_REGEX),
    }).ignore_extra('*')
}).ignore_extra('*')

"""
Validate and convert Github `PULL REQUEST` event payload to Python dictionary:
{
    'action': str(assigned|unassigned|labeled|unlabeled|opened|edited|closed|reopened|synchronize),
    'pull_request': {
        'id': int(<id>),
        'number': int(<number>),
        'created_at': str(<created_at>),
        'updated_at': str(<updated_at>),
        'url': str(<url>),
        'head_commit': {
            'sha': str(<sha>),
        },
    },
}

https://developer.github.com/v3/activity/events/types/#pullrequestevent
"""
github_pull_request_event_validator = t.Dict({
    t.Key('action') >> 'action': t.String(regex=github_action_regex),
    t.Key('pull_request') >> 'pull_request': t.Dict({
        t.Key('number') >> 'number': t.Int(),
        t.Key('id') >> 'id': t.Int(),
        t.Key('url') >> 'url': t.URL,
        t.Key('created_at') >> 'created_at': t.String(regex=ISO8601_DATETIME_REGEX),
        t.Key('updated_at') >> 'updated_at': t.String(regex=ISO8601_DATETIME_REGEX),
        t.Key('head') >> 'head_commit': t.Dict({
            t.Key('sha') >> 'sha': t.String,
        }).ignore_extra('*')
    }).ignore_extra('*')
}).ignore_extra('*')

"""
Validate and convert Github `Status` for specific `Ref` payload to Python dictionary:
{
    'status': str(failure|pending|success),
    'sha': str(<sha>),
}

https://developer.github.com/v3/repos/statuses/#get-the-combined-status-for-a-specific-ref
"""
github_status_validator = t.Dict({
    t.Key('state') >> 'status': t.String(regex=github_status_regex),
    t.Key('sha') >> 'sha': t.String,
}).ignore_extra('*')


def cover_rage_client_to_redis(client: dict) -> dict:
    # Additional helper to convert Python dict with data received Cover-Rage client to store it in Redis
    return {
        'overall_coverage': client['overall_coverage'],
        'git_commit': client['git_commit'],
        'uncovered_lines': json.dumps(client['uncovered_lines']),
    }


def github_push_to_redis(gh: dict) -> dict:
    # Additional helper to convert Github `PUSH` to flat dict to store it in Redis
    return {
        'created_at': gh['head_commit']['created_at'],
        'sha': gh['head_commit']['sha'],
    }


def github_pull_request_to_redis(gh: dict) -> dict:
    # Additional helper to convert Github `PULL REQUEST` to flat dict to store it in Redis
    return {
        'action': gh['action'],
        'id': gh['pull_request']['id'],
        'number': gh['pull_request']['number'],
        'created_at': gh['pull_request']['created_at'],
        'updated_at': gh['pull_request']['updated_at'],
        'url': gh['pull_request']['url'],
        'sha': gh['pull_request']['head_commit']['sha'],
    }
