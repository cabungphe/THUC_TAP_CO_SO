"""Offline integration checks; the scripted model does not test a live LLM."""
import json
import unittest
from pathlib import Path

from agent2.adapter import convert_agent1_to_batch
from agent2.agent import Agent2Runner
from agent2.cli import build_agent3_payload
from agent2.schemas import FindingBatch
from agent2.tools import ReadOnlySourceTools


PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT.parent / 'lazyweb'


class ScriptedLFIModel:
    """Exercise the real runner and source tools with predetermined decisions."""
    def __init__(self):
        self.turn = 0

    def complete(self, messages):
        paths = ['page.php', 'libs/common.php', 'init.php', 'libs/AumWAF.class.php']
        self.turn += 1
        if self.turn <= len(paths):
            return json.dumps({
                'action': 'read_file',
                'args': {'path': paths[self.turn - 1], 'start_line': 1, 'end_line': 100},
            })
        observations = [json.loads(m['content'].split('\n', 1)[1])
                        for m in messages if m['content'].startswith('TOOL_OBSERVATION\n')]
        assert len(observations) == 4
        assert all('tool_error' not in item for item in observations)
        assert 'include $page;' in observations[0]['content']
        assert 'return element($index, $_GET, $default);' in observations[1]['content']
        return json.dumps({'action': 'finish', 'result': {
            'analysis_status': 'confirmed',
            'confidence': 'high',
            'code_locations': [
                {'path': 'page.php', 'start_line': 4, 'end_line': 6, 'role': 'vulnerable_handler'},
                {'path': 'libs/common.php', 'start_line': 28, 'end_line': 30, 'role': 'source'},
            ],
            'root_cause': {
                'summary': 'Scripted offline result: query page reaches a dynamic PHP include.',
                'source': "$_GET['page']",
                'sink': 'include $page',
                'data_flow': ["query page -> get('page')", '$page -> include $page'],
            },
            'remediation': {
                'recommended_strategy': 'Map permitted page identifiers to fixed local template paths.',
                'constraints': ['Preserve valid pages and missing-page redirect behavior.'],
            },
            'notes': ['Scripted integration test; not a live model analysis or HTTP exploitation test.'],
        }})


class LFIPipelineTests(unittest.TestCase):
    def test_both_input_formats(self):
        exported = json.loads((PROJECT / 'examples/agent1_lfi_test_log.json').read_text(encoding='utf-8'))
        direct = json.loads((PROJECT / 'examples/finding_batch_lfi.json').read_text(encoding='utf-8'))
        self.assertEqual(direct['findings'][0]['evidence']['request_line'], 'GET /page.php?page=LICENSE HTTP/1.1')
        self.assertEqual(exported['observations'][-1]['request_line'], 'GET /page.php?page=LICENSE HTTP/1.1')
        self.assertEqual(exported['session']['total_steps'], len(exported['observations']))
        self.assertEqual(exported['session']['total_testcases'], len(exported['test_cases']))
        for raw in [convert_agent1_to_batch(exported), direct]:
            batch = FindingBatch.from_dict(raw)
            self.assertEqual(len(batch.findings), 1)
            self.assertEqual(batch.findings[0].endpoint, '/page.php')
            self.assertEqual(batch.findings[0].vulnerability_type, 'lfi')

    def test_php_search_read_and_agent3_handoff(self):
        tools = ReadOnlySourceTools(SOURCE)
        self.assertEqual(tools.search_code('include $page', path='page.php')['count'], 1)
        raw = json.loads((PROJECT / 'examples/finding_batch_lfi.json').read_text(encoding='utf-8'))
        batch = FindingBatch.from_dict(raw)
        result = Agent2Runner(ScriptedLFIModel(), tools).analyze_batch(batch)
        self.assertEqual(result['results'][0]['analysis_status'], 'confirmed')
        self.assertEqual(result['results'][0]['metrics']['read_calls'], 4)
        instructions = build_agent3_payload(result, str(SOURCE))
        self.assertIn('Bản sửa #1: LFI', instructions)
        self.assertIn('page.php', instructions)
        self.assertIn(str(SOURCE), instructions)
        self.assertIn('Map permitted page identifiers', instructions)
