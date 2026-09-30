import unittest

import nylib.ue
from nylib.ue.errors import DetectionError, SchemaError, SnapshotError, UeError


class SnapshotErrorTests(unittest.TestCase):
    def test_str(self):
        err = SnapshotError('X:/snap', 'not a completed snapshot')
        self.assertEqual(str(err), 'invalid snapshot X:/snap: not a completed snapshot')

    def test_attrs(self):
        err = SnapshotError('X:/snap', 'not a completed snapshot')
        self.assertEqual(err.path, 'X:/snap')
        self.assertEqual(err.reason, 'not a completed snapshot')

    def test_subclass(self):
        self.assertTrue(issubclass(SnapshotError, UeError))
        self.assertIsInstance(SnapshotError('p', 'r'), UeError)


class SchemaErrorTests(unittest.TestCase):
    def test_str_is_reason_exactly(self):
        reason = 'meta.json has schema 2.0; this reader understands 1.x.'
        err = SchemaError('X:/snap', reason)
        self.assertEqual(str(err), reason)

    def test_attrs(self):
        err = SchemaError('X:/snap', 'some reason')
        self.assertEqual(err.path, 'X:/snap')
        self.assertEqual(err.reason, 'some reason')

    def test_subclass(self):
        self.assertTrue(issubclass(SchemaError, SnapshotError))
        self.assertTrue(issubclass(SchemaError, UeError))
        self.assertIsInstance(SchemaError('p', 'r'), SnapshotError)


class DetectionErrorTests(unittest.TestCase):
    def test_str(self):
        err = DetectionError('scan-pattern', 'no candidate matched')
        self.assertEqual(str(err), 'detection stopped at scan-pattern: no candidate matched')

    def test_attrs_default_explanations(self):
        err = DetectionError('scan-pattern', 'no candidate matched')
        self.assertEqual(err.step, 'scan-pattern')
        self.assertEqual(err.detail, 'no candidate matched')
        self.assertEqual(err.explanations, ())
        self.assertIsInstance(err.explanations, tuple)

    def test_explanations_stored_as_tuple(self):
        err = DetectionError('scan-pattern', 'no candidate matched', ['tried A', 'tried B'])
        self.assertEqual(err.explanations, ('tried A', 'tried B'))
        self.assertIsInstance(err.explanations, tuple)

    def test_non_iterable_explanations_raises_type_error(self):
        with self.assertRaises(TypeError):
            DetectionError('scan-pattern', 'no candidate matched', 42)

    def test_subclass(self):
        self.assertTrue(issubclass(DetectionError, UeError))
        self.assertIsInstance(DetectionError('s', 'd'), UeError)


class ReExportTests(unittest.TestCase):
    def test_snapshot_error(self):
        self.assertIs(nylib.ue.SnapshotError, SnapshotError)

    def test_schema_error(self):
        self.assertIs(nylib.ue.SchemaError, SchemaError)

    def test_detection_error(self):
        self.assertIs(nylib.ue.DetectionError, DetectionError)


if __name__ == '__main__':
    unittest.main()
