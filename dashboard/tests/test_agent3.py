import json
import os
from pathlib import Path
import shutil
import sys
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from agent2.agent3 import (Job, JobManager, MODEL, classify_cli_error,
                           cli_command, process_lines, run_job, verification_plan)


FAKE_CLI = r'''
import json, sys, time
from pathlib import Path
sys.stdin.reconfigure(encoding='utf-8')
root = Path.cwd()
mode = (root / 'mode').read_text()
prompt = json.loads(sys.stdin.read())["message"]["content"]
(root / 'last_prompt').write_text(prompt, encoding='utf-8')
counter = root / 'attempts'
n = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(n))
def emit(event):
    print(json.dumps(event), flush=True)
emit({'event': 'init', 'init': {'model': 'wrong-model' if mode == 'wrong-model' else 'gemini-3.1-pro-high'}})
emit({'event': 'step_update', 'step_update': {'step_type': 'tool', 'tool_name': 'replace', 'state': 'ACTIVE'}})
if mode != 'no-change':
    (root / 'app.py').write_text('SAFE = ' + str(mode != 'bad-test' and (mode != 'retry' or n > 1)))
if mode == 'slow':
    time.sleep(0.2)
if mode == 'secret':
    print('key=test-secret', file=sys.stderr, flush=True)
if mode == 'auth-error':
    print('Authorization: Bearer leaked-secret; HTTP 401', file=sys.stderr, flush=True)
if mode != 'missing-result':
    emit({'event': 'result', 'result': {'status': 'ERROR' if mode in ('result-error', 'auth-error') else 'SUCCESS',
                                      'error': 'api_key=leaked-secret; unauthorized' if mode == 'auth-error' else None}})
sys.exit(1 if mode == 'nonzero' else 0)
'''


class Agent3Tests(unittest.TestCase):
    def setUp(self):
        self.base = Path(__file__).resolve().parent / f'agent3 test {uuid.uuid4().hex}'
        self.base.mkdir()
        self.root = self.base / 'source with spaces'
        self.root.mkdir()
        self.script = self.base / 'fake_cli.py'
        self.script.write_text(FAKE_CLI, encoding='utf-8')
        (self.root / 'app.py').write_text('SAFE = False')
        self.checks = [[sys.executable, '-c', 'from app import SAFE; assert SAFE, "regression failed"']]
        self.app_root = patch('agent2.agent3.APP_ROOT', self.base)
        self.app_root.start()

    def tearDown(self):
        self.app_root.stop()
        if self.base.parent == Path(__file__).resolve().parent and self.base.name.startswith('agent3 test '):
            shutil.rmtree(self.base)

    def job(self, mode='ok'):
        (self.root / 'mode').write_text(mode)
        return Job(self.root, 'Fix unsafe behavior. Unicode: sửa lỗi. & % ! "',
                   [sys.executable, str(self.script)], self.checks, timeout=10)

    def test_success_requires_process_and_real_checks(self):
        job = self.job()
        run_job(job)
        self.assertEqual(job.state, 'succeeded')
        self.assertIn('app.py', job.changed_files)
        self.assertTrue(job.done.is_set())
        self.assertEqual(json.loads((job.run_dir / 'result.json').read_text())['state'], 'succeeded')
        self.assertIn(job.instructions, (self.root / 'last_prompt').read_text(encoding='utf-8'))

    def test_edit_only_skips_all_checks_and_records_unverified_result(self):
        (self.root / 'app.py').write_text('SAFE = True')
        job = self.job('bad-test')
        job.verify = False
        with patch('agent2.agent3.process_lines', wraps=process_lines) as streamed:
            run_job(job)
        self.assertEqual(job.state, 'edited')
        self.assertEqual(streamed.call_count, 1)
        self.assertEqual((self.root / 'attempts').read_text(), '1')
        prompt = (self.root / 'last_prompt').read_text(encoding='utf-8')
        self.assertIn('CODE EDITS ONLY', prompt)
        self.assertIn('Skip any testing instructions in the handoff', prompt)
        self.assertNotIn('Add meaningful regression tests', prompt)
        self.assertFalse(any('Kiểm tra 1/' in event for event in job.events))
        saved = json.loads((job.run_dir / 'result.json').read_text())
        self.assertFalse(saved['verification_enabled'])
        self.assertEqual(saved['state'], 'edited')

    def test_edit_only_still_rejects_cli_failure_and_missing_source_changes(self):
        for mode in ('result-error', 'no-change'):
            with self.subTest(mode=mode):
                job = self.job(mode)
                job.verify = False
                run_job(job)
                self.assertEqual(job.state, 'failed')

    def test_default_manager_never_loads_verification_plan(self):
        (self.root / 'mode').write_text('ok')
        with patch('agent2.agent3.cli_command', return_value=[sys.executable, str(self.script)]), \
             patch('agent2.agent3.verification_plan', side_effect=AssertionError('must not load checks')):
            job = JobManager().start(str(self.root), 'Fix source only.')
            self.assertTrue(job.done.wait(10))
        self.assertEqual(job.checks, [])
        self.assertFalse(job.verify)
        self.assertEqual(job.max_attempts, 1)
        self.assertEqual(job.state, 'edited')

    def test_exit_zero_without_change_is_not_success(self):
        job = self.job('no-change')
        run_job(job)
        self.assertEqual(job.state, 'failed')
        self.assertEqual((self.root / 'attempts').read_text(), '3')

    def test_lab_fix_log_is_saved_by_worker_on_success_and_failure(self):
        report = self.base / 'du_lieu_theo_lab' / '127.0.0.1' / 'phan_tich_agent2' / 'agent3_fix_LFI_phien_01.md'
        for mode, state in (('ok', 'succeeded'), ('result-error', 'failed')):
            with self.subTest(mode=mode):
                (self.root / 'app.py').write_text('SAFE = False')
                job = self.job(mode)
                job.report_paths = (str(report),)
                job.secret_values = ('private-test-key',)
                job.instructions = 'Fix unsafe behavior. private-test-key'
                run_job(job)
                saved = report.read_text(encoding='utf-8')
                self.assertIn('Trạng thái: ' + state, saved)
                self.assertIn('Fix unsafe behavior.', saved)
                self.assertNotIn('private-test-key', saved)
                self.assertIn('Tiến độ và kiểm tra', saved)
                self.assertTrue(job.done.is_set())

    def test_failed_verification_is_fed_back_and_repaired(self):
        job = self.job('retry')
        run_job(job)
        self.assertEqual(job.state, 'succeeded')
        self.assertEqual((self.root / 'attempts').read_text(), '2')
        self.assertIn('regression failed', (self.root / 'last_prompt').read_text(encoding='utf-8'))

    def test_permanent_check_failure_never_becomes_success(self):
        job = self.job('bad-test')
        run_job(job)
        self.assertEqual(job.state, 'failed')
        self.assertEqual((self.root / 'attempts').read_text(), '3')

    def test_incomplete_or_failed_cli_never_becomes_success(self):
        for mode in ('nonzero', 'result-error', 'missing-result', 'wrong-model'):
            with self.subTest(mode=mode):
                job = self.job(mode)
                run_job(job)
                self.assertEqual(job.state, 'failed')

    def test_progress_arrives_before_completion_and_replays(self):
        job = self.job('slow')
        worker = threading.Thread(target=run_job, args=(job,))
        worker.start()
        stream = job.stream()
        first = next(stream)
        self.assertFalse(job.done.is_set())
        events = [first, *stream]
        worker.join(timeout=10)
        self.assertEqual(events, list(job.stream()))
        self.assertEqual(job.state, 'succeeded')

    def test_redacts_key_in_progress_and_does_not_persist_log(self):
        job = self.job('secret')
        with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-secret'}):
            run_job(job)
        self.assertNotIn('test-secret', '\n'.join(job.events))
        self.assertFalse((job.run_dir / 'progress.log').exists())

    def test_cli_and_verification_do_not_inherit_api_credentials(self):
        job = self.job()
        with patch.dict(os.environ, {'AGENT2_API_KEY': 'agent-two-secret',
                                      'GEMINI_API_KEY': 'gemini-secret',
                                      'GITHUB_TOKEN': 'github-secret'}), \
             patch('agent2.agent3.process_lines', wraps=process_lines) as streamed:
            run_job(job)
        self.assertEqual(job.state, 'succeeded')
        self.assertGreaterEqual(streamed.call_count, 2)
        for call in streamed.call_args_list:
            child_env = call.args[2]
            self.assertNotIn('AGENT2_API_KEY', child_env)
            self.assertNotIn('GEMINI_API_KEY', child_env)
            self.assertNotIn('GITHUB_TOKEN', child_env)

    def test_check_output_is_kept_out_of_dashboard_and_redacted_in_retry(self):
        job = self.job()
        job.checks = [[sys.executable, '-c',
                       "print('client_secret=printed-secret'); raise SystemExit(1)"]]
        run_job(job)
        self.assertEqual(job.state, 'failed')
        self.assertNotIn('printed-secret', '\n'.join(job.events))
        self.assertFalse((job.run_dir / 'progress.log').exists())
        self.assertNotIn('printed-secret', (self.root / 'last_prompt').read_text(encoding='utf-8'))
        self.assertIn('[REDACTED]', (self.root / 'last_prompt').read_text(encoding='utf-8'))

    def test_cli_error_is_classified_without_raw_credentials(self):
        job = self.job('auth-error')
        run_job(job)
        self.assertEqual(job.state, 'failed')
        self.assertTrue(any('đăng nhập lại' in event for event in job.events))
        self.assertNotIn('leaked-secret', '\n'.join(job.events))
        self.assertFalse((job.run_dir / 'progress.log').exists())

    def test_cli_error_categories_are_controlled_text(self):
        samples = ['401 unauthorized x', 'quota exceeded x', 'model not found x',
                   'EACCES x', 'DNS failure x']
        for sample in samples:
            with self.subTest(sample=sample):
                reason = classify_cli_error(sample)
                self.assertIsNotNone(reason)
                self.assertNotIn(' x', reason)

    def test_process_timeout(self):
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            list(process_lines([sys.executable, '-c', 'import time; time.sleep(20)'],
                               self.root, os.environ.copy(), None, 0.3))
        self.assertLess(time.monotonic() - started, 10)

    def test_same_source_double_click_attaches_to_worker(self):
        manager = JobManager()
        gate = threading.Event()
        def worker(job):
            gate.wait(5)
            job.done.set()
        with patch('agent2.agent3.cli_command', return_value=[sys.executable]), \
             patch('agent2.agent3.verification_plan', return_value=self.checks), \
             patch('agent2.agent3.run_job', side_effect=worker) as launch:
            first = manager.start(str(self.root), 'fix')
            second = manager.start(str(self.root), 'fix again')
            self.assertIs(first, second)
            self.assertIs(manager.latest(str(self.root)), first)
            gate.set()
            self.assertTrue(first.done.wait(5))
            self.assertEqual(launch.call_count, 1)

    def test_no_verification_plan_fails_before_editing(self):
        with self.assertRaisesRegex(RuntimeError, 'agent3-checks'):
            verification_plan(self.root)
        (self.root / '.agent3-checks.json').write_text('[]')
        with self.assertRaises(ValueError):
            verification_plan(self.root)

    def test_project_checks_and_cli_entry_discovery(self):
        (self.root / '.agent3-checks.json').write_text(json.dumps(self.checks))
        self.assertEqual(verification_plan(self.root), self.checks)
        entry = self.base / 'agy.exe'
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_text('')
        self.assertEqual(cli_command(str(entry)), [str(entry.resolve())])

    def test_dashboard_renders_verified_success_with_build_control(self):
        from streamlit.testing.v1 import AppTest
        job = self.job()
        run_job(job)
        app_path = Path(__file__).resolve().parents[1] / 'app.py'
        with patch.object(JobManager, 'latest', return_value=job):
            app = AppTest.from_file(str(app_path))
            app.session_state['source_root'] = str(self.root)
            app.run(timeout=10)
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any('kiểm tra' in item.value for item in app.success))
        labels = [b.label for b in app.button]
        self.assertFalse(any('Poll' in label or 'Check Now' in label for label in labels))
        self.assertTrue(any('Build & Run' in label for label in labels))

    def test_dashboard_failure_has_no_success_banner(self):
        from streamlit.testing.v1 import AppTest
        job = self.job('result-error')
        run_job(job)
        app_path = Path(__file__).resolve().parents[1] / 'app.py'
        with patch.object(JobManager, 'latest', return_value=job):
            app = AppTest.from_file(str(app_path))
            app.session_state['source_root'] = str(self.root)
            app.run(timeout=10)
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(len(app.success), 0)
        self.assertTrue(any('Chưa sửa thành công' in item.value for item in app.error))

    def test_send_button_runs_edit_only_worker_and_displays_unverified_result(self):
        import streamlit as st
        from streamlit.testing.v1 import AppTest
        st.cache_resource.clear()
        (self.root / 'mode').write_text('ok')
        app_path = Path(__file__).resolve().parents[1] / 'app.py'
        with patch('agent2.agent3.cli_command', return_value=[sys.executable, str(self.script)]), \
             patch('agent2.agent3.verification_plan', return_value=self.checks):
            app = AppTest.from_file(str(app_path))
            app.session_state['source_root'] = str(self.root)
            app.session_state['analysis_source_root'] = str(self.root.resolve())
            app.session_state['analysis_result'] = {'results': [{'analysis_status': 'confirmed'}]}
            app.session_state['agent3_payload'] = 'Fix unsafe behavior in app.py.'
            app.run(timeout=10)
            send = next(b for b in app.button if b.label == '🚀 Gửi cho Agent 3')
            self.assertFalse(send.disabled)
            send.click().run(timeout=15)
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any('Chưa chạy kiểm thử' in item.value for item in app.info))
        self.assertFalse(any('vượt qua' in item.value for item in app.success))
        self.assertEqual((self.root / 'attempts').read_text(), '1')
        st.cache_resource.clear()


if __name__ == '__main__':
    unittest.main()
