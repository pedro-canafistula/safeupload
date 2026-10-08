"""Synthetic A04 receipt/provenance controls; not Windows qualification."""
import copy
import json
import tempfile
import importlib.util
from pathlib import Path
import unittest

SPEC=importlib.util.spec_from_file_location('qualification',Path(__file__).with_name('Invoke-StagedInvariantQualification.py'))
Q=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(Q)


def fixture():
    actor=dict(Pid=10,Sid='S-1-5-21-1-2-3-1001',SessionId=0,BootId='active',Elevated=False,IsAdministrator=False,OwnerSid='S-1-5-21-1-2-3-1001',CommandLine='powershell.exe -File \"C:\\\\owned\\\\writer.ps1\"')
    child=dict(actor,Pid=20,OwnerSid=actor['Sid'],CommandLine='powershell.exe -File "C:\\owned\\duplicate-writer.ps1"')
    setup=dict(SameFileObject=True)
    for i,(name,pid) in enumerate((('Duplicate',10),('Adopt',20),('ParentPosition',10),('ChildQuery',20),('ChildPosition',20),('ParentQuery',10))):
        setup[name]=dict(Pid=pid,BootId='active',NativeCode=0,QpcFrequency=10000000,StartQpc=i*10,EndQpc=i*10+1)
    setup['Duplicate'].update(TargetPid=20,SourceHandle=100,RemoteHandle=200)
    setup['Adopt'].update(RemoteHandle=200)
    setup['PhysicalObjectProof']=dict(Status='OK',CollectedBySid='S-1-5-18',CollectedByPid=99,Source='NtQuerySystemInformation/SystemExtendedHandleInformation',BootId='active',QpcFrequency=10000000,StartQpc=52,EndQpc=53,PrimaryPid=10,ChildPid=20,SourceHandle=100,RemoteHandle=200,Object='0xFFFF800000000123',ObjectTypeIndex=7,InventoryCount=1000)
    setup['PhysicalObjectArtifact']=dict(Artifact='C:\\owned\\activation-trusted-physical-object.json',Length=1000,Sha256='C'*64,Entry=copy.deepcopy(setup['PhysicalObjectProof']))
    for key in ('ParentPosition','ChildQuery'):setup[key]['Position']=317
    for key in ('ChildPosition','ParentQuery'):setup[key]['Position']=619
    assertions=[dict(Name=name,Verdict='INCONCLUSIVE' if name in ('A04PublicationAndTemporalCoverage','NeverReadyWholeHolderInterval') else 'PASS') for name in sorted(Q.A04_REQUIRED_ASSERTIONS)]
    assertions.append(dict(Name='LiveTaintFlags', Verdict='PASS'))
    return dict(Schema='StagedInvariantSuite/2',AuthoritativeCaseExport=True,CaseId='A04',Mode='runtime-verifier',CaseStatus='READY',Verdict='INCONCLUSIVE',ForbiddenByteCount=0,
                InputHashes={k:'A'*64 for k in Q.MVP_BUILD_HASHES},Restoration=dict(Known=True,GuestChecks=True,IndependentBaseline='baseline.txt',IndependentBaselineSha256='B'*64),
                BootIds=dict(Active='active'),Trials=[dict(Verdict='INCONCLUSIVE',ForbiddenByteCount=0,Disposal=dict(Status='OK'),Errors=[],Actor=actor,DuplicateActor=child,
                DuplicateSetup=setup,Assertions=assertions,Predicate=dict(Verdict='INCONCLUSIVE',Assertions=[]),Latency=[])])


class A04GateTests(unittest.TestCase):
    def test_mapping_only_receipts_are_required_in_a02_and_a03(self):
        for case in ('A02', 'A03'):
            result=fixture();result['CaseId']=case
            result['Trials'][0]['Assertions']=[dict(Name=name,Verdict='PASS') for name in Q.activation_required_assertions(case) | {'LiveTaintFlags'}]
            self.assertTrue(Q.mvp_case_gate(result)['MvpGatePassed'])
            for missing in ('MappingOnlyAfterProbeClose', 'MappingOnlyServicePending'):
                bad=copy.deepcopy(result);bad['Trials'][0]['Assertions']=[a for a in bad['Trials'][0]['Assertions'] if a['Name']!=missing]
                with self.subTest(case=case,missing=missing):
                    self.assertIn('Missing:'+missing,Q.mvp_case_gate(bad)['MvpBlockers'])

    def test_complete_same_object_provenance(self):
        result=fixture();self.assertTrue(Q.activation_duplicate_provenance(result));self.assertTrue(Q.mvp_case_gate(result)['MvpGatePassed'])

    def test_every_specific_contract_assertion_required(self):
        for name in Q.A04_REQUIRED_ASSERTIONS:
            result=fixture();t=result['Trials'][0];t['Assertions']=[a for a in t['Assertions'] if a['Name']!=name]
            with self.subTest(name=name):self.assertIn('Missing:'+name,Q.mvp_case_gate(result)['MvpBlockers'])

    def test_distinct_standard_user_child_bound_to_actual_os_owner(self):
        for key,value in (('Pid',10),('Sid','other'),('SessionId',1),('BootId','other'),('OwnerSid','other'),('Elevated',True),('IsAdministrator',True),('CommandLine','wrong')):
            result=fixture();result['Trials'][0]['DuplicateActor'][key]=value
            with self.subTest(key=key):self.assertFalse(Q.activation_duplicate_provenance(result));self.assertIn('DuplicateActorProvenance',Q.mvp_case_gate(result)['MvpBlockers'])

    def test_both_os_actor_proofs_and_typed_ids_required(self):
        for actor in ('Actor','DuplicateActor'):
            for key,value in (('Pid',True),('Pid',0),('SessionId',True),('OwnerSid','wrong'),('Elevated',True),('IsAdministrator',True)):
                result=fixture();result['Trials'][0][actor][key]=value
                with self.subTest(actor=actor,key=key):self.assertFalse(Q.activation_duplicate_provenance(result))

    def test_native_api_handle_and_shared_position_receipts_required(self):
        for key,field,value in (('Duplicate','NativeCode',5),('Duplicate','TargetPid',99),('Duplicate','SourceHandle',0),('Duplicate','SourceHandle',True),('Adopt','RemoteHandle',200.0),('Duplicate','RemoteHandle',201),('Adopt','Pid',10),('ChildQuery','Position',0),('ParentQuery','Position',317),('ChildPosition','StartQpc',0),('Adopt','QpcFrequency',1)):
            result=fixture();result['Trials'][0]['DuplicateSetup'][key][field]=value
            with self.subTest(key=key,field=field):self.assertFalse(Q.activation_duplicate_provenance(result))

    def test_primary_cannot_use_duplicate_launcher(self):
        result=fixture();result['Trials'][0]['Actor']['CommandLine']=result['Trials'][0]['DuplicateActor']['CommandLine'];self.assertFalse(Q.activation_duplicate_provenance(result))

    def test_trusted_native_physical_object_proof_required(self):
        for key,value in (('Status','INCONCLUSIVE'),('CollectedBySid','user'),('CollectedByPid',10),('Source','actor-reported'),('BootId','old'),('PrimaryPid',20),('ChildPid',10),('SourceHandle',101),('RemoteHandle',201),('Object','0x0000000000000000'),('Object','bad'),('ObjectTypeIndex',0),('InventoryCount',1),('StartQpc',0)):
            result=fixture();result['Trials'][0]['DuplicateSetup']['PhysicalObjectProof'][key]=value
            with self.subTest(key=key):self.assertFalse(Q.activation_duplicate_provenance(result))
        result=fixture();del result['Trials'][0]['DuplicateSetup']['PhysicalObjectProof'];self.assertFalse(Q.activation_duplicate_provenance(result))

    def test_trusted_physical_artifact_link_required(self):
        for key,value in (('Artifact','wrong'),('Length',0),('Sha256','bad'),('Entry',{})):
            result=fixture();result['Trials'][0]['DuplicateSetup']['PhysicalObjectArtifact'][key]=value
            with self.subTest(key=key):self.assertFalse(Q.activation_duplicate_provenance(result))

    def test_actual_copied_physical_artifact_link(self):
        result=fixture();setup=result['Trials'][0]['DuplicateSetup'];record=setup['PhysicalObjectArtifact']
        with tempfile.TemporaryDirectory() as d:
            destination=Path(d);path=destination/'activation-trusted-physical-object.json'
            path.write_text(json.dumps(setup['PhysicalObjectProof']))
            record.update(Artifact='C:\\owned\\activation-trusted-physical-object.json',Length=path.stat().st_size,Sha256=Q.sha(path))
            Q.validate_service_artifacts(result,destination,'C:\\owned\\')
            record['Entry']=dict(record['Entry'],Object='0xFFFF800000000999')
            with self.assertRaises(RuntimeError):Q.validate_service_artifacts(result,destination,'C:\\owned\\')

    def test_missing_proof_never_qualifies(self):
        result=fixture();del result['Trials'][0]['DuplicateSetup'];self.assertFalse(Q.activation_duplicate_provenance(result));self.assertFalse(Q.mvp_case_gate(result)['MvpGatePassed'])


if __name__=='__main__': unittest.main()
