"""Owner-scoped group persistence and atomic settings integration."""
import sqlite3

import pytest

from sitewatcher import storage, web_actions
from sitewatcher.config import AppConfig
from sitewatcher.reporting import build_snapshot


def groups_module():
    from sitewatcher import domain_groups
    return domain_groups


def test_defaults_and_snapshot_are_owner_scoped():
    groups = groups_module()
    storage.add_domain(11, 'example.com')
    storage.add_domain(22, 'other.com')
    assert groups.list_groups(11) == [{'id': 0, 'name': '', 'is_default': True}]
    assert groups.group_for_domain(11, 'example.com') == 0
    gid = groups.create_group(11, ' Work ')
    groups.move_domains(11, ['example.com'], gid)
    snapshot = build_snapshot(AppConfig(), 11)
    assert snapshot['groups'][1] == {'id': gid, 'name': 'Work', 'is_default': False}
    assert snapshot['domains'][0]['group_id'] == gid
    assert groups.list_groups(22) == [{'id': 0, 'name': '', 'is_default': True}]
    assert build_snapshot(AppConfig(), 22)['domains'][0]['group_id'] == 0


def test_cross_owner_groups_domains_and_batch_moves_are_rejected_atomically():
    groups = groups_module()
    storage.add_domain(11, 'mine.com')
    storage.add_domain(22, 'other.com')
    mine = groups.create_group(11, 'Mine')
    other = groups.create_group(22, 'Other')
    for action in (lambda: groups.move_domains(11, ['mine.com'], other),
                   lambda: groups.rename_group(11, other, 'Stolen'),
                   lambda: groups.delete_group(11, other),
                   lambda: groups.move_domains(11, ['mine.com', 'other.com'], mine)):
        with pytest.raises(ValueError):
            action()
    assert groups.group_for_domain(11, 'mine.com') == 0
    assert groups.list_groups(22)[1]['name'] == 'Other'


def test_membership_survives_domain_rename_and_group_rename_then_cascades():
    groups = groups_module()
    storage.add_domain(11, 'old.com')
    gid = groups.create_group(11, 'Work')
    groups.move_domains(11, ['old.com'], gid)
    storage.rename_domain(11, 'old.com', 'new.com', {},
                          expected_revision=storage.domain_override_revision({}))
    assert groups.group_for_domain(11, 'new.com') == gid
    groups.rename_group(11, gid, 'Projects')
    assert groups.list_groups(11)[1]['name'] == 'Projects'
    groups.delete_group(11, gid)
    assert groups.group_for_domain(11, 'new.com') == 0
    gid = groups.create_group(11, 'Again')
    groups.move_domains(11, ['new.com'], gid)
    storage.remove_domain(11, 'new.com')
    with sqlite3.connect(storage.DEFAULT_DB) as conn:
        assert conn.execute('SELECT COUNT(*) FROM domain_group_members').fetchone()[0] == 0


@pytest.mark.parametrize('name', ['', '   ', 'Main', ' ОСНОВНАЯ ', 'x' * 81, 'bad\nname', 'x\u200by'])
def test_invalid_group_names_are_rejected(name):
    with pytest.raises(ValueError):
        groups_module().create_group(11, name)


def test_unicode_group_names_are_unique_per_owner():
    groups = groups_module()
    gid = groups.create_group(11, ' Café ')
    with pytest.raises(ValueError):
        groups.create_group(11, 'CAFE\u0301')
    other = groups.create_group(11, 'Other')
    with pytest.raises(ValueError):
        groups.rename_group(11, other, 'café')
    groups.rename_group(11, gid, 'CAFÉ')
    groups.create_group(22, 'café')


def test_form_assignments_are_atomic_and_missing_field_preserves_membership():
    groups = groups_module()
    cfg = AppConfig()
    gid = groups.create_group(11, 'Work')
    foreign = groups.create_group(22, 'Foreign')
    web_actions.add_domains(cfg, 11, {'domain': 'a.com,b.com', 'group_id': str(gid)})
    assert groups.group_for_domain(11, 'a.com') == gid
    context = web_actions.settings_context(cfg, 11, 'a.com')
    assert context['values']['group_id'] == str(gid)
    form = {'domain': 'a.com', 'revision': context['revision'], 'interval_minutes': '12'}
    with pytest.raises(ValueError):
        web_actions.save_domain(cfg, 11, {**form, 'group_id': str(foreign)})
    assert storage.get_domain_override(11, 'a.com') == {}
    web_actions.save_domain(cfg, 11, form)
    assert groups.group_for_domain(11, 'a.com') == gid
    for value in (str(foreign), '-1', 'invalid'):
        with pytest.raises(ValueError):
            web_actions.add_domains(cfg, 11, {'domain': 'c.com,d.com', 'group_id': value})
        assert not storage.domain_exists(11, 'c.com')
    revision = storage.domain_override_revision(storage.get_domain_override(11, 'a.com'))
    with pytest.raises(ValueError):
        storage.rename_domain(11, 'a.com', 'renamed.com', {}, expected_revision=revision,
                              group_id=foreign)
    assert storage.domain_exists(11, 'a.com')
    assert not storage.domain_exists(11, 'renamed.com')
    with pytest.raises(ValueError):
        storage.set_domain_override(11, 'new.com', {}, create_missing=True, group_id=foreign)
    assert not storage.domain_exists(11, 'new.com')


def test_legacy_snapshot_reads_default_without_creating_tables():
    storage.add_domain(11, 'legacy.com')
    with sqlite3.connect(storage.DEFAULT_DB) as conn:
        conn.execute('DROP TABLE IF EXISTS domain_group_members')
        conn.execute('DROP TABLE IF EXISTS domain_groups')
    snapshot = build_snapshot(AppConfig(), 11)
    assert snapshot['groups'] == [{'id': 0, 'name': '', 'is_default': True}]
    assert snapshot['domains'][0]['group_id'] == 0
    with sqlite3.connect(storage.DEFAULT_DB) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='domain_groups'").fetchone() is None


def test_database_rejects_cross_owner_memberships():
    groups = groups_module()
    storage.add_domain(11, 'mine.com')
    storage.add_domain(22, 'other.com')
    foreign = groups.create_group(22, 'Foreign')
    mine = groups.create_group(11, 'Mine')
    for owner, domain, gid in ((11, 'mine.com', foreign), (11, 'other.com', mine)):
        with pytest.raises(sqlite3.IntegrityError), storage._write_connection() as conn:
            conn.execute('INSERT INTO domain_group_members(owner_id,domain,group_id) VALUES(?,?,?)',
                         (owner, domain, gid))


def test_default_group_cannot_be_renamed_or_deleted():
    groups = groups_module()
    with pytest.raises(ValueError):
        groups.rename_group(11, 0, 'Renamed')
    with pytest.raises(ValueError):
        groups.delete_group(11, 0)
    assert groups.list_groups(11) == [{'id': 0, 'name': '', 'is_default': True}]


def test_form_explicit_assignment_to_main_and_create_with_group():
    groups = groups_module()
    cfg = AppConfig()
    gid = groups.create_group(11, 'Work')
    web_actions.save_domain(cfg, 11, {'domain': 'example.com', 'group_id': str(gid)}, create=True)
    assert groups.group_for_domain(11, 'example.com') == gid
    context = web_actions.settings_context(cfg, 11, 'example.com')
    web_actions.save_domain(cfg, 11, {**context['values'], 'group_id': '0'})
    assert groups.group_for_domain(11, 'example.com') == 0


@pytest.mark.parametrize('rename', [False, True])
def test_stale_group_form_preserves_bulk_move_and_settings(rename):
    groups = groups_module()
    cfg = AppConfig()
    group_a = groups.create_group(11, 'A')
    group_b = groups.create_group(11, 'B')
    web_actions.save_domain(cfg, 11, {'domain': 'example.com', 'group_id': str(group_a)}, create=True)
    context = web_actions.settings_context(cfg, 11, 'example.com')
    form = {**context['values'], 'original_group_id': str(group_a), 'check.ping': 'off'}
    if rename:
        form['domain'] = 'renamed.com'
    groups.move_domains(11, ['example.com'], group_b)
    with pytest.raises(ValueError, match='Settings changed; reload this page before saving'):
        web_actions.save_domain(cfg, 11, form)
    assert storage.get_domain_override(11, 'example.com') == {}
    assert groups.group_for_domain(11, 'example.com') == group_b
    assert not storage.domain_exists(11, 'renamed.com')


@pytest.mark.parametrize('baseline', [None, '', '-1', 'invalid'])
def test_edit_group_assignment_requires_valid_original_group(baseline):
    cfg = AppConfig()
    storage.add_domain(11, 'example.com')
    context = web_actions.settings_context(cfg, 11, 'example.com')
    form = {**context['values'], 'group_id': '0', 'check.ping': 'off'}
    form.pop('original_group_id', None)
    if baseline is not None:
        form['original_group_id'] = baseline
    with pytest.raises(ValueError, match='Settings changed; reload this page before saving'):
        web_actions.save_domain(cfg, 11, form)
    assert storage.get_domain_override(11, 'example.com') is None


def test_add_batch_creates_one_group_with_all_domains():
    groups = groups_module()
    cfg = AppConfig()
    assert web_actions.add_domains(cfg, 11, {
        'domain': 'a.com,b.com', 'group_id': 'new', 'new_group_name': ' Projects ',
    }) == 2
    created = groups.list_groups(11)[1]
    assert created['name'] == 'Projects'
    assert groups.group_for_domain(11, 'a.com') == created['id']
    assert groups.group_for_domain(11, 'b.com') == created['id']


@pytest.mark.parametrize('rename', [False, True])
def test_edit_creates_group_atomically_and_requires_fresh_baseline(rename):
    groups = groups_module()
    cfg = AppConfig()
    storage.add_domain(11, 'example.com')
    context = web_actions.settings_context(cfg, 11, 'example.com')
    form = {**context['values'], 'group_id': 'new', 'new_group_name': 'Projects',
            'check.ping': 'off'}
    if rename:
        form['domain'] = 'renamed.com'
    moved = groups.create_group(11, 'Moved')
    groups.move_domains(11, ['example.com'], moved)
    with pytest.raises(ValueError, match='Settings changed'):
        web_actions.save_domain(cfg, 11, form)
    assert [item['name'] for item in groups.list_groups(11)] == ['', 'Moved']
    assert storage.get_domain_override(11, 'example.com') is None
    assert not storage.domain_exists(11, 'renamed.com')
    form['original_group_id'] = str(moved)
    target = web_actions.save_domain(cfg, 11, form)
    assert target == ('renamed.com' if rename else 'example.com')
    assert groups.list_groups(11)[2]['name'] == 'Projects'
    assert groups.group_for_domain(11, target) == groups.list_groups(11)[2]['id']
    assert storage.get_domain_override(11, target)['checks']['ping'] is False


@pytest.mark.parametrize('form', [
    {'domain': 'a.com', 'new_group_name': ''},
    {'domain': 'a.com', 'new_group_name': 'Main'},
    {'domain': 'a.com', 'new_group_name': 'Projects', 'http_timeout_s': '0'},
    {'domain': 'invalid host', 'new_group_name': 'Projects'},
    {'domain': 'a.com,a.com', 'new_group_name': 'Projects'},
])
def test_invalid_batch_does_not_create_orphan_group(form):
    groups = groups_module()
    with pytest.raises(ValueError):
        web_actions.add_domains(AppConfig(), 11, {**form, 'group_id': 'new'})
    assert groups.list_groups(11) == [{'id': 0, 'name': '', 'is_default': True}]
    assert not storage.domain_exists(11, 'a.com')


def test_new_group_conflict_rolls_back_settings_and_batch_domains():
    groups = groups_module()
    cfg = AppConfig()
    groups.create_group(11, 'Café')
    with pytest.raises(ValueError, match='Group already exists'):
        web_actions.add_domains(cfg, 11, {
            'domain': 'a.com,b.com', 'group_id': 'new', 'new_group_name': 'CAFE\u0301',
        })
    assert not storage.domain_exists(11, 'a.com')
    assert not storage.domain_exists(11, 'b.com')
    storage.add_domain(11, 'example.com')
    context = web_actions.settings_context(cfg, 11, 'example.com')
    with pytest.raises(ValueError, match='Group already exists'):
        web_actions.save_domain(cfg, 11, {
            **context['values'], 'domain': 'renamed.com', 'group_id': 'new',
            'new_group_name': 'CAFÉ', 'check.ping': 'off',
        })
    assert storage.domain_exists(11, 'example.com')
    assert not storage.domain_exists(11, 'renamed.com')
    assert storage.get_domain_override(11, 'example.com') is None


def test_direct_batch_conflict_rolls_back_new_group_and_partial_domains():
    groups = groups_module()
    storage.add_domain(11, 'existing.com')
    with pytest.raises(ValueError, match='Domain already exists'):
        storage.create_domains_with_overrides(11, {'new.com': {}, 'existing.com': {}},
                                              new_group_name='Projects')
    assert not storage.domain_exists(11, 'new.com')
    assert len(groups.list_groups(11)) == 1


def test_create_single_domain_in_new_group_and_ignore_name_for_existing_group():
    groups = groups_module()
    cfg = AppConfig()
    web_actions.save_domain(cfg, 11, {
        'domain': 'example.com', 'group_id': 'new', 'new_group_name': 'Projects',
    }, create=True)
    gid = groups.list_groups(11)[1]['id']
    assert groups.group_for_domain(11, 'example.com') == gid
    web_actions.add_domains(cfg, 11, {
        'domain': 'another.com', 'group_id': str(gid), 'new_group_name': 'Ignored',
    })
    assert len(groups.list_groups(11)) == 2
    assert groups.group_for_domain(11, 'another.com') == gid
