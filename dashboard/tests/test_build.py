import json
import os
from pathlib import Path
import shutil
import sys
import threading
import unittest
import uuid
from unittest.mock import patch

from agent2.build import (BuildJob, BuildManager, docker_command, docker_environment,
                          run_build, source_compose_command)


FAKE_DOCKER = r'''
import json, os, sys, time
from pathlib import Path
root = Path.cwd()
mode = (root / 'mode').read_text()
args = sys.argv[1:]
with (root / 'commands.jsonl').open('a') as output:
    output.write(json.dumps({'argv': args, 'cwd': str(root),
                             'compose_file_env': os.environ.get('COMPOSE_FILE'),
                             'agent_key_present': 'AGENT2_API_KEY' in os.environ}) + '\n')
# Global options must always bind both config and up/ps to this exact source.
assert args[1:3] == ['--project-directory', str(root)]
assert args[3] == '--env-file'
assert args[5:7] == ['--file', str(root / 'docker-compose.yml')]
args = ['compose', *args[7:]]
if args[:3] == ['compose', 'config', '--services']:
    if mode == 'config-failure':
        print('API_KEY=fixture-secret failed to solve', file=sys.stderr)
        sys.exit(1)
    print('web\ndb')
elif args[:4] == ['compose', 'config', '--format', 'json']:
    config_path = root / 'resolved-config.json'
    config = json.loads(config_path.read_text()) if config_path.exists() else {
        'services': {'web': {'build': {'context': str(root), 'dockerfile': 'Dockerfile'}},
                     'db': {'image': 'mysql:5.6'}}}
    print(json.dumps(config))
elif args[:4] == ['compose', 'up', '--build', '-d']:
    print('#1 [internal] load Dockerfile', flush=True)
    print('#2 [web 1/2] RUN prepare', flush=True)
    if mode == 'slow':
        time.sleep(.3)
    if mode == 'up-failure':
        print('API_KEY=fixture-secret failed to solve', file=sys.stderr, flush=True)
        sys.exit(1)
    print('Container fixture-web Started', flush=True)
elif args[:5] == ['compose', 'ps', '--all', '--format', 'json']:
    count_path = root / 'ps-count'
    count = int(count_path.read_text()) + 1 if count_path.exists() else 1
    count_path.write_text(str(count))
    if mode == 'ps-failure':
        print('password=fixture-secret error during connect', file=sys.stderr)
        sys.exit(1)
    health = 'starting' if mode == 'delayed-health' and count == 1 else 'healthy'
    if mode == 'unhealthy':
        health = 'unhealthy'
    if mode == 'exited':
        web = {'Service': 'web', 'State': 'exited', 'Health': ''}
    else:
        web = {'Service': 'web', 'State': 'running', 'Health': health}
    db = {'Service': 'db', 'State': 'running', 'Health': ''}
    print(json.dumps([web, db]))
else:
    sys.exit(2)
'''


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(__file__).resolve().parents[1]
        self.base = self.workspace / ('build-test-' + uuid.uuid4().hex)
        self.base.mkdir()
        self.root = self.base / 'source with spaces'
        self.root.mkdir()
        (self.root / 'docker-compose.yml').write_text('services:\n  web:\n    build: .\n')
        (self.root / 'mode').write_text('success')
        self.script = self.base / 'fake_docker.py'
        self.script.write_text(FAKE_DOCKER, encoding='utf-8')
        self.command = [sys.executable, str(self.script), 'compose']

    def tearDown(self):
        if self.base.resolve().is_relative_to(self.workspace.resolve()):
            shutil.rmtree(self.base)

    def job(self, mode='success', *, timeout=10, health_timeout=1):
        (self.root / 'mode').write_text(mode)
        return BuildJob(self.root, self.command, timeout=timeout, health_timeout=health_timeout)

    def commands(self):
        return [json.loads(line) for line in (self.root / 'commands.jsonl').read_text().splitlines()]

    def test_build_and_run_requires_running_services(self):
        job = self.job()
        run_build(job)
        self.assertEqual(job.state, 'succeeded')
        self.assertTrue(job.done.is_set())
        self.assertEqual(job.services, ('web', 'db'))
        prefix = ['compose', '--project-directory', str(self.root), '--env-file', os.devnull,
                  '--file', str(self.root / 'docker-compose.yml')]
        self.assertEqual([c['argv'] for c in self.commands()], [
            prefix + ['config', '--services'],
            prefix + ['config', '--format', 'json'],
            prefix + ['up', '--build', '-d'],
            prefix + ['ps', '--all', '--format', 'json'],
        ])
        self.assertTrue(all(c['cwd'] == str(self.root) for c in self.commands()))
        self.assertTrue(any('Build & Run thành công' in e for e in job.events))
        self.assertTrue(any('Build image: bước 2' in e for e in job.events))
        self.assertTrue(any(f'Build context (web): {self.root}' in e for e in job.events))

    def test_wrong_source_inputs_fail_before_any_build_or_start(self):
        outside = str(self.base / 'other-source')
        cases = {
            'context': {'build': {'context': outside}},
            'remote': {'build': {'context': 'https://example.com/other.git'}},
            'dockerfile': {'build': {'context': str(self.root), 'dockerfile': '../Dockerfile'}},
            'additional': {'build': {'context': str(self.root),
                                     'additional_contexts': {'other': outside}}},
            'ssh-additional': {'build': {'context': str(self.root),
                                         'additional_contexts': {'other': 'git@example.com:other.git'}}},
            'mount': {'build': {'context': str(self.root)},
                      'volumes': [{'type': 'bind', 'source': outside, 'target': '/var/www/html'}]},
            'image-only': {'image': 'other-web'},
        }
        for name, web in cases.items():
            with self.subTest(name=name):
                (self.root / 'commands.jsonl').unlink(missing_ok=True)
                (self.root / 'resolved-config.json').write_text(json.dumps({
                    'services': {'web': web, 'db': {'image': 'mysql:5.6'}}}))
                job = self.job()
                run_build(job)
                self.assertEqual(job.state, 'failed')
                self.assertFalse(any('up' in c['argv'] for c in self.commands()))

    def test_inherited_compose_settings_cannot_redirect_build(self):
        with patch.dict(os.environ, {'COMPOSE_FILE': str(self.base / 'wrong.yml'),
                                     'COMPOSE_ENV_FILES': str(self.base / 'wrong.env'),
                                     'COMPOSE_PROJECT_NAME': 'wrong-project'}):
            job = self.job()
            run_build(job)
            self.assertEqual(job.state, 'succeeded')
            self.assertNotIn('COMPOSE_ENV_FILES', docker_environment())
            self.assertNotIn('COMPOSE_PROJECT_NAME', docker_environment())
        self.assertTrue(all(c['compose_file_env'] is None for c in self.commands()))

    def test_same_folder_name_at_three_locations_builds_each_selected_source(self):
        manager = BuildManager()
        with patch('agent2.build.docker_command', return_value=self.command):
            for drive in ('C', 'D', 'E'):
                root = self.base / drive / 'lazyweb'
                root.mkdir(parents=True)
                (root / 'docker-compose.yml').write_text('services: {}\n')
                (root / 'mode').write_text('success')
                job = manager.start(str(root))
                self.assertTrue(job.done.wait(10))
                self.assertEqual(job.state, 'succeeded', job.error)
                commands = [json.loads(line) for line in (root / 'commands.jsonl').read_text().splitlines()]
                self.assertTrue(all(c['cwd'] == str(root) for c in commands))
                self.assertTrue(any(f'Build context (web): {root}' in e for e in job.events))

    @unittest.skipUnless(shutil.which('docker'), 'Docker CLI required (daemon not used)')
    def test_real_compose_ignores_other_source_from_environment_and_dotenv(self):
        import subprocess

        wrong = self.base / 'other' / 'lazyweb'
        wrong.mkdir(parents=True)
        (wrong / 'compose.yaml').write_text('services:\n  wrong:\n    build: .\n')
        # Both process variables and local .env try to redirect discovery.
        (self.root / '.env').write_text('COMPOSE_FILE=' + (wrong / 'compose.yaml').as_posix() + '\n')
        (self.root / 'compose.override.yaml').write_text('services:\n  web:\n    build:\n      args:\n        LOCAL_OVERRIDE: yes\n')
        with patch.dict(os.environ, {'COMPOSE_FILE': str(wrong / 'compose.yaml'),
                                     'COMPOSE_ENV_FILES': str(wrong / 'missing.env')}):
            result = subprocess.run(source_compose_command(self.root, docker_command())
                                    + ['config', '--format', 'json'],
                                    cwd=wrong, env=docker_environment(), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        self.assertEqual(set(config['services']), {'web'})
        build = config['services']['web']['build']
        self.assertEqual(Path(build['context']).resolve(), self.root)
        self.assertIn('LOCAL_OVERRIDE', build['args'])

    def test_failed_build_or_compose_config_never_reports_success(self):
        for mode in ('up-failure', 'config-failure', 'ps-failure'):
            with self.subTest(mode=mode):
                job = self.job(mode)
                run_build(job)
                self.assertEqual(job.state, 'failed')
                self.assertTrue(job.done.is_set())
                self.assertNotIn('Build & Run thành công', '\n'.join(job.events))
                self.assertNotIn('fixture-secret', '\n'.join(job.events))

    def test_exited_or_unhealthy_service_is_failure(self):
        for mode in ('exited', 'unhealthy'):
            with self.subTest(mode=mode):
                job = self.job(mode)
                run_build(job)
                self.assertEqual(job.state, 'failed')
                self.assertIn('healthcheck', job.error)

    def test_waits_for_healthcheck_before_success(self):
        job = self.job('delayed-health')
        with patch('agent2.build.time.sleep'):
            run_build(job)
        self.assertEqual(job.state, 'succeeded')
        self.assertEqual((self.root / 'ps-count').read_text(), '2')
        self.assertTrue(any('1/2' in e for e in job.events))
        self.assertTrue(any('2/2' in e for e in job.events))

    def test_progress_arrives_before_process_finishes_and_replays(self):
        job = self.job('slow')
        worker = threading.Thread(target=run_build, args=(job,))
        worker.start()
        progress = job.stream()
        first = next(progress)
        self.assertFalse(job.done.is_set())
        self.assertIn('Đang kiểm tra Docker Compose', first)
        all_events = [first, *progress]
        worker.join(timeout=10)
        self.assertEqual(all_events, list(job.stream()))

    def test_agent_keys_are_not_inherited_or_shown_in_progress(self):
        with patch.dict(os.environ, {'AGENT2_API_KEY': 'fixture-secret',
                                     'GEMINI_API_KEY': 'another-secret',
                                     'CUSTOM_PASSWORD': 'password-secret',
                                     'SERVICE_TOKEN': 'token-secret'}):
            job = self.job('up-failure')
            run_build(job)
            self.assertNotIn('AGENT2_API_KEY', docker_environment())
            self.assertNotIn('GEMINI_API_KEY', docker_environment())
            self.assertNotIn('CUSTOM_PASSWORD', docker_environment())
            self.assertNotIn('SERVICE_TOKEN', docker_environment())
        self.assertTrue(all(not c['agent_key_present'] for c in self.commands()))
        self.assertNotIn('fixture-secret', '\n'.join(job.events))
        self.assertNotIn('another-secret', '\n'.join(job.events))

    def test_same_source_double_click_uses_one_worker(self):
        manager = BuildManager()
        gate = threading.Event()

        def worker(job):
            gate.wait(5)
            job.done.set()

        with patch('agent2.build.docker_command', return_value=self.command), \
             patch('agent2.build.run_build', side_effect=worker) as launch:
            first = manager.start(str(self.root))
            second = manager.start(str(self.root))
            self.assertIs(first, second)
            self.assertIs(manager.latest(str(self.root)), first)
            other = self.base / 'other-source'
            other.mkdir()
            (other / 'compose.yaml').write_text('services: {}\n')
            with self.assertRaisesRegex(ValueError, 'source khác đang build'):
                manager.start(str(other))
            gate.set()
            self.assertTrue(first.done.wait(5))
            self.assertEqual(launch.call_count, 1)

    def test_missing_compose_file_blocks_launch(self):
        (self.root / 'docker-compose.yml').unlink()
        with self.assertRaisesRegex(ValueError, 'compose'):
            BuildManager().start(str(self.root))

    @unittest.skipUnless(os.name == 'nt', 'Docker Desktop per-user path is Windows-only')
    def test_finds_per_user_docker_when_parent_process_path_is_stale(self):
        executable = self.base / 'Programs/DockerDesktop/resources/bin/docker.exe'
        executable.parent.mkdir(parents=True)
        executable.touch()
        with patch('agent2.build.shutil.which', return_value=None), \
             patch.dict(os.environ, {'LOCALAPPDATA': str(self.base)}):
            self.assertEqual(docker_command(), [str(executable), 'compose'])
            self.assertEqual(docker_environment(str(executable))['PATH'].split(os.pathsep)[0],
                             str(executable.parent))


if __name__ == '__main__':
    unittest.main()
