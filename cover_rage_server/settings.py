from envparse import env


# Number of threads in executor
# https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.ThreadPoolExecutor
THREAD_POOL_SIZE = env.int('RAGE_SRV_THREAD_POOL_SIZE', default=4)


# Redis connection settings
REDIS_HOST = env.str('RAGE_SRV_REDIS_HOST', default='127.0.0.1')
REDIS_PORT = env.int('RAGE_SRV_REDIS_PORT', default=6379)
REDIS_DB = env.int('RAGE_SRV_REDIS_DB', default=1)


# Cover-Rage binding address settings. `SRV_SCHEME` could be one of: 'http', 'https'
SRV_SCHEME = env.str('RAGE_SRV_SCHEME', default='https')
SRV_HOST = env.str('RAGE_SRV_HOST')


# Cover-Rage API urls
SRV_API_SEND_RESULTS_URL = '/api/results/{public_token}/'
SRV_API_GITHUB_WEB_HOOK_URL = '/api/github/{public_token}/'

# TODO: change url from API end point to regular view
SRV_STATUS_URL = '/api/status/{public_token}/{sha}/'


# Minimal good coverage percentage (required for background color of badge)
# If project's coverage is less then value of this settings - badge background color will be red.
# If it's greater or equal - badge background color will be green.
# If it's zero (undefined) - badge background color will be orange.
MIN_GOOD_COVERAGE_PERCENTAGE = env.int('RAGE_SRV_MIN_GOOD_COVERAGE_PERCENTAGE', default=94)


# Almost all settings have default values. On the other hand - you're responsible for changing them.
# All the settings you specify will be used as is... except several values that could conflict with common sense:
assert THREAD_POOL_SIZE > 0
assert SRV_SCHEME in ('https', 'http',)
assert MIN_GOOD_COVERAGE_PERCENTAGE <= 100


# Settings without default values that you have to set:
assert SRV_HOST
