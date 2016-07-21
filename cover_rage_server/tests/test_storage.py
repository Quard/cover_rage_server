import asyncio
from unittest import TestCase, mock

from cover_rage_server.tests.mixins import AsyncMockMixin
from cover_rage_server.storage import (
    dict_to_redis_iterable,
    convert_bytes_dict_to_string_dict,
    get_repo_id,
    split_repo_id,
    get_commit_id,
    split_commit_id,
    create_redis_pool,
)


class StorageModuleHelpersTestCase(TestCase):

    def test_dict_to_redis_iterable_success(self):
        input_data = {'foo': 1, 'bar': 'baz'}
        result = dict_to_redis_iterable(input_data)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 4)
        self.assertIn('foo', result)
        self.assertIn(1, result)
        self.assertIn('bar', result)
        self.assertIn('baz', result)

    def test_dict_to_redis_iterable_fail(self):
        input_data = [1, 2, 3]
        with self.assertRaises(AssertionError):
            dict_to_redis_iterable(input_data)

    def test_get_repo_id_success(self):
        self.assertEqual(get_repo_id('gh', 'john_doe', 'project'), 'r/gh/john_doe/project')
        self.assertEqual(get_repo_id('bb', 'jane_doe', 'test'), 'r/bb/jane_doe/test')

    def test_get_repo_id_fail_wrong_kind(self):
        with self.assertRaises(AssertionError):
            get_repo_id('42', 'john_doe', 'project')

    def test_get_repo_id_fail_wrong_owner(self):
        with self.assertRaises(AssertionError):
            get_repo_id('github', '', 'project')

    def test_get_repo_id_fail_wrong_project(self):
        with self.assertRaises(AssertionError):
            get_repo_id('github', 'john_doe', '')

    def test_split_repo_id_success(self):
        self.assertSequenceEqual(split_repo_id('r/gh/john_doe/project'), ('gh', 'john_doe', 'project'))
        self.assertSequenceEqual(split_repo_id('r/bb/jane_doe/test'), ('bb', 'jane_doe', 'test'))

    def test_split_repo_id_fail_blank_repo_id(self):
        with self.assertRaises(AssertionError):
            split_repo_id('')

    def test_split_repo_id_fail_wrong_input_data(self):
        with self.assertRaises(AssertionError):
            split_repo_id('r/gh')

    def test_split_repo_id_fail_wrong_prefix(self):
        with self.assertRaises(AssertionError):
            split_repo_id('wrong/gh/john_doe/project')

    def test_split_repo_id_fail_wrong_repo_id(self):
        with self.assertRaises(AssertionError):
            split_repo_id('r/gh/john_doe')

    def test_split_repo_id_fail_wrong_repo_kind_in_repo_id(self):
        with self.assertRaises(AssertionError):
            split_repo_id('r/42/john_doe/project')

    def test_split_repo_id_fail_wrong_repo_owner_in_repo_id(self):
        with self.assertRaises(AssertionError):
            split_repo_id('r/gh//project')

    def test_split_repo_id_fail_wrong_repo_name_in_repo_id(self):
        with self.assertRaises(AssertionError):
            split_repo_id('r/gh/john_doe/')

    def test_get_commit_id_success(self):
        self.assertEqual(
            get_commit_id('r/gh/john_doe/project', '1234hash5678'),
            'c#r/gh/john_doe/project#1234hash5678'
        )
        self.assertEqual(
            get_commit_id('r/bb/jane_doe/test', '9090hash0909'),
            'c#r/bb/jane_doe/test#9090hash0909'
        )

    def test_get_commit_id_fail_wrong_repo_id(self):
        with self.assertRaises(AssertionError):
            get_commit_id('', '1234hash5678')

    def test_get_commit_id_fail_wrong_commit_hash(self):
        with self.assertRaises(AssertionError):
            get_commit_id('r/gh/john_doe/project', '')

    def test_split_commit_id(self):
        self.assertSequenceEqual(
            split_commit_id('c#r/gh/john_doe/project#1234hash5678'),
            ['r/gh/john_doe/project', '1234hash5678']
        )

    def test_split_commit_id_fail_blank_commit_id(self):
        with self.assertRaises(AssertionError):
            split_repo_id('c#r/gh/john_doe/project#')

    def test_split_commit_id_fail_wrong_input_data(self):
        with self.assertRaises(AssertionError):
            split_repo_id('wrong')

    def test_split_commit_id_fail_wrong_prefix(self):
        with self.assertRaises(AssertionError):
            split_repo_id('wrong#r/gh/john_doe/project#1234hash5678')

    def test_split_commit_id_fail_wrong_repo_id(self):
        with self.assertRaises(AssertionError):
            split_repo_id('c##1234hash5678')

    def test_split_commit_id_fail_wrong_commit_hash(self):
        with self.assertRaises(AssertionError):
            split_repo_id('c#r/gh/john_doe/project#')

    def test_convert_bytes_dict_to_string_dict(self):
        input_dict = {
            b'key1': 'str_value',
            b'key2': [b'bytes_value', 0],
            'key3': {
                b'sub_key1': 'str_value',
                b'sub_key2': b'bytes_value',
            }
        }
        expected_output = {
            'key1': 'str_value',
            'key2': ['bytes_value', 0],
            'key3': {
                'sub_key1': 'str_value',
                'sub_key2': 'bytes_value',
            }
        }
        self.assertDictEqual(convert_bytes_dict_to_string_dict(input_dict), expected_output)


class RedisConnectionHelpersTestCase(AsyncMockMixin, TestCase):

    def setUp(self):
        super(RedisConnectionHelpersTestCase, self).setUp()
        self.loop = asyncio.get_event_loop()

    @mock.patch('cover_rage_server.storage.settings.REDIS_HOST', 'example.com')
    @mock.patch('cover_rage_server.storage.settings.REDIS_PORT', 5555)
    @mock.patch('cover_rage_server.storage.settings.REDIS_DB', 2)
    def test_create_redis_pool(self):
        with mock.patch(
            'cover_rage_server.storage.aioredis.create_pool', new_callable=self.coro_mock
        ) as mocked_create_pool:
            mocked_create_pool.coro.return_value = object()
            self.loop.run_until_complete(create_redis_pool(self.loop))
            mocked_create_pool.assert_called_once_with(('example.com', 5555), db=2, loop=self.loop)
