"""Seed actor latency controls; synthetic, no Windows qualification."""
import copy
import importlib.util
from pathlib import Path
import unittest
SPEC=importlib.util.spec_from_file_location('q',Path(__file__).with_name('Invoke-StagedInvariantQualification.py'))
Q=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(Q)

def fixture(case='S00-observer-control'):
    classes=('writer-open','cached-write','flush','close') if case=='S00-observer-control' else ('writer-open-deny',)
    operations=[];latency=[]
    for n in range(101):
        for j,name in enumerate(classes):
            start=1000+(n*len(classes)+j)*20000
            operations.append(dict(Class=name,Trial=n,Cold=n==0,NativeCode=0 if len(classes)==4 else 5,StartQpc=start,EndQpc=start+10000))
    for name in classes:
        latency.append(dict(Class=name,Verdict='PASS',UnheldCount=100,P95Ms=10.0,MaxMs=10.0,Samples=[dict((k,v)for k,v in c.items()if k!='Class')|dict(Ms=10.0)for c in operations if c['Class']==name]))
    trial=dict(Repetitions=dict(Unheld=100),Operations=operations,Latency=latency,WriterFence=dict(Complete=True,BootId='active',QpcFrequency=1000000,ExpectedAttempts=101,ReleasedQpc=0,CompletedQpc=operations[-1]['EndQpc']+1))
    return dict(CaseId=case,BootIds=dict(Active='active')),trial

class SeedLatencyTests(unittest.TestCase):
    def test_all_seed_native_paths(self):
        for name in ('S00-observer-control','S01-denied-write-after-boot','S02-agent-down-open-refused'):
            r,t=fixture(name);self.assertTrue(Q.mvp_seed_latency_passed(r,t))
    def test_product_functional_case_still_needs_dedicated(self):
        r,t=fixture();r['CaseId']='C01-approve-absent';self.assertFalse(Q.mvp_seed_latency_passed(r,t))
    def test_each_native_receipt_binding(self):
        for key,value in (('Trial',True),('Trial',1),('Cold',False),('Held',True),('NativeCode',5),('NativeCode',False),('StartQpc',None),('StartQpc',-1),('EndQpc',999),('Class','mapped-store')):
            r,t=fixture();t['Operations'][0][key]=value
            with self.subTest(key=key,value=value):self.assertFalse(Q.mvp_seed_latency_passed(r,t))
    def test_no_partial_duplicate_or_unbound_samples(self):
        for change in ('missing','duplicate','sample','ms','p95','max','order'):
            r,t=fixture()
            if change=='missing':t['Operations'].pop()
            elif change=='duplicate':t['Operations'][4]=copy.deepcopy(t['Operations'][0])
            elif change=='sample':t['Latency'][0]['Samples'][0]['StartQpc']+=1
            elif change=='ms':t['Latency'][0]['Samples'][0]['Ms']=float('nan')
            elif change=='p95':t['Latency'][0]['P95Ms']=0
            elif change=='max':t['Latency'][0]['MaxMs']=0
            elif change=='order':t['Latency'].reverse()
            with self.subTest(change=change):self.assertFalse(Q.mvp_seed_latency_passed(r,t))
    def test_fence_holds_and_repetition_scope(self):
        for key,value in (('Complete',False),('BootId','old'),('QpcFrequency',0),('ExpectedAttempts',100),('CompletedQpc',0)):
            r,t=fixture();t['WriterFence'][key]=value
            with self.subTest(key=key):self.assertFalse(Q.mvp_seed_latency_passed(r,t))
        for key in ('HeldReceipt','CloseBarrierQpc','DedicatedLatencyOnly'):
            r,t=fixture();t[key]=True;self.assertFalse(Q.mvp_seed_latency_passed(r,t))
    def test_recomputed_native_budget(self):
        r,t=fixture('S01-denied-write-after-boot')
        for op,sample in zip(t['Operations'],t['Latency'][0]['Samples']):
            op['StartQpc']=1000+op['Trial']*300000;op['EndQpc']=op['StartQpc']+260000;sample.update(StartQpc=op['StartQpc'],EndQpc=op['EndQpc'],Ms=260.0)
        t['WriterFence']['CompletedQpc']=t['Operations'][-1]['EndQpc']+1
        t['Latency'][0].update(P95Ms=260.0,MaxMs=260.0)
        self.assertFalse(Q.mvp_seed_latency_passed(r,t))

if __name__=='__main__':unittest.main()
