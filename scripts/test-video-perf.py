#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('perf', Path(__file__).with_name('analyze-video-perf.py'))
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)

def sample(t, n, cost=10, backend='deko', epoch=1, width=1280):
    return '\n'.join([
        f'vp1 id={t} s=1 e={epoch} b={backend} hw=1 w={width} h=720 dec={n} show={n} repl=0 drop=0',
        f'vp2 id={t} n={n} prep={n*cost} age={n*1000} wait={n*200} decode={n*300}',
        f'vp3 id={t} draws={n*2} redraw={n} begin={n*100} ui={n*200} present={n*300}',
        f'vp4 id={t} uploads=0 bytes=0 downloads=0 imports=2',
        f'vp5 id={t} maps=2 pools=1 busy=1 image=1000 mapped=2000'])+'\n'

class Perf(unittest.TestCase):
    def test_weighting_and_redraw(self):
        r=perf.summarize(sample(1000,0)+sample(2000,10)+sample(3000,40),0)
        self.assertEqual(r['fps'],20)
        self.assertEqual(r['new_frame_prepare_mean_us'],10)
        self.assertEqual(r['totals']['redraw'],40)
    def test_missing_snapshot(self):
        text=sample(1000,0)+sample(2000,10).replace('vp3','lost')+sample(3000,40)
        r=perf.summarize(text,0)
        self.assertEqual(r['complete_snapshots'],2)
        self.assertEqual(r['totals']['n'],40)
    def test_epoch_reset(self):
        r=perf.summarize(sample(1000,100)+sample(2000,0,epoch=2)+sample(3000,20,epoch=2),0)
        self.assertEqual(r['totals']['n'],20)
    def test_warmup(self):
        r=perf.summarize(''.join(sample(i*1000,i*10) for i in range(8)),5)
        self.assertEqual(r['measured_ms'],2000)
    def test_stall_counts_in_fps(self):
        r=perf.summarize(sample(1000,0)+sample(2000,10)+sample(3000,10),0)
        self.assertEqual(r['fps'],5)
    def test_comparison(self):
        new=perf.summarize(sample(1000,0)+sample(2000,10),0)
        old=perf.summarize(sample(1000,0,100,'sdl')+sample(2000,10,100,'sdl'),0)
        self.assertEqual(perf.compare(new,old)['prepare_reduction_percent'],90)
        old['modes'][0]['width']=1920
        with self.assertRaises(ValueError):perf.compare(new,old)
    def test_old_logs_not_fabricated(self):
        self.assertEqual(perf.summarize('stats frames=50 fps=60')['measured_ms'],0)
    def test_counter_reversal(self):
        r=perf.summarize(sample(1000,100)+sample(2000,10),0)
        self.assertEqual(r['measured_ms'],0)

if __name__=='__main__':unittest.main()
