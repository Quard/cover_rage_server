import os
from unittest import TestCase

from cover_rage_server.badge import render_badge


class RenderBadgeTestCase(TestCase):

    undefined_badge_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'badge_undefined.svg')
    bad_80_badge_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'badge_80_bad.svg')
    good_99_badge_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'badge_99_good.svg')

    def test_undefined(self):
        with open(self.undefined_badge_path, 'r') as f:
            expected_badge = f.read().replace('\n', '').encode('utf-8')
            badge = render_badge(0, True)
            self.assertEqual(badge, expected_badge)
            badge = render_badge(0, False)
            self.assertEqual(badge, expected_badge)

    def test_bad(self):
        with open(self.bad_80_badge_path, 'r') as f:
            expected_badge = f.read().replace('\n', '').encode('utf-8')
            badge = render_badge(80, False)
            self.assertEqual(badge, expected_badge)

    def test_good(self):
        with open(self.good_99_badge_path, 'r') as f:
            expected_badge = f.read().replace('\n', '').encode('utf-8')
            badge = render_badge(99, True)
            self.assertEqual(badge, expected_badge)
