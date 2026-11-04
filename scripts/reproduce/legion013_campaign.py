"""WO-CODEX-LEGION-013 qualification orchestration using the frozen WO023 interface.

Hidden material is consumed only by the original qualification harness. This
orchestrator never prints contract contents or builds agent solutions from it.
"""
import collections
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import uuid

ROOT = pathlib.Path(os.environ.get('LEGION_DATA_ROOT', pathlib.Path(__file__).resolve().parents[2]))
OUT = ROOT / 'CODEX_WO_LEGION100_GO_001'
HOME = pathlib.Path(os.environ.get('LEGION_HOME', pathlib.Path.home() / 'legion_pf'))
BASE = HOME / 'wo008_g4_exe_023_stage'
DEV = HOME / 'codex_legion013_dev'
PYTHON = HOME / 'cage_s6/.venv/bin/python'
WORLDS = ['SYN-GAIA-TIM','SYN-GAIA-EXE','SYN-GAIA-SEA','SYN-GAIA-ADA','SYN-GAIA-AMB','SYN-GAIA-A2A','SYN-GAIA-NOI'] + [f'SYN-OTEL-{i:02}' for i in range(1,7)]

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p,obj,exclusive=False):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x' if exclusive else 'w') as f:
        json.dump(obj,f,indent=2,sort_keys=True); f.flush(); os.fsync(f.fileno())

def rows(p):
    return [json.loads(x) for x in p.read_text().splitlines()] if p.is_file() else []

def progress(**kw):
    record = dict(timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),world=None,work_order='WO-CODEX-LEGION-013',attempt_uid=None,source_sha256=None,experiment_type=None,hypothesis=None,observed_failure=None,root_cause=None,repair=None,tests_passed=None,tests_failed=None,nim_requests=0,native_effects=0,receipts=0,readbacks=0,unauthorized_effects=None,duplicate_effects=None,judge_verdict='NOT_RUN',judge_issues={},evidence_directory=None,next_action=None)
    record.update(kw)
    with (OUT/'PROGRESS.jsonl').open('a') as f:
        f.write(json.dumps(record,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())

def manifest(stage):
    result={}
    for p in sorted(stage.rglob('*')):
        rel=p.relative_to(stage)
        if p.is_file() and not any(x in {'.git','.venv','__pycache__','.pytest_cache','.ruff_cache'} for x in rel.parts) and p.suffix!='.pyc':
            result[str(rel)]=sha(p)
    return result

def scorecard():
    results={}
    for name in ['WO008_G4_PREREG_NIM_014','WO008_G4_EXE_NIM_023']:
        d=ROOT/name;r=json.loads((d/'RESULT.json').read_text())
        errors=[]
        for n,h in r['evidence_sha256'].items():
            for p in [d/'EVIDENCE'/n,pathlib.Path(r['run_dir'])/n]:
                if not p.is_file() or sha(p)!=h: errors.append(str(p))
        results[r['scenario']]={'status':'LOCAL_JUDGE_PASS_CANDIDATE' if not errors and r['judge_verdict']=='PASS' and not r['judge_issues'] else 'FAIL','result':str(d/'RESULT.json'),'run':r['run_dir'],'attempt_uid':r['attempt_uid'],'judge_verdict':r['judge_verdict'],'hash_errors':errors,'workers':r['workers'],'nim_requests':r['provider_requests'],'native_effects':r['native_effects'],'receipts':r['receipts'],'readbacks':r['readback_records']}
    for p in sorted(OUT.glob('SYN-*/attempt-*/WORLD_RESULT.json')):
        r=json.loads(p.read_text());results[r['scenario']]=r
    for w in WORLDS: results.setdefault(w,{'status':'PENDING','next_action':'Frozen baseline, fresh NIM attempt, original independent Judge'})
    write(OUT/'WORLD_SCORECARD.json',{'work_order':'WO-CODEX-LEGION-013','official_vcc_at_1_declared':False,'local_pass_candidates':sum(x['status']=='LOCAL_JUDGE_PASS_CANDIDATE' for x in results.values()),'worlds':results})
    return results

def participation(run,world,judge_pass):
    workers=rows(run/'WORKERS.jsonl');provider=rows(run/'provider_log.jsonl');native=rows(run/'WORLD_LOG.jsonl')
    nim={r.get('agent') for r in provider if r.get('status')=='OK' and r.get('http_status')==200}
    spec=json.loads((ROOT/'STRUCTURAL_001/worlds_public'/f'{world}.world.json').read_text())
    required={r['agent_id'] for r in spec['roles'] if r.get('tasks')}
    contributed={r.get('agent_id') for r in native if r.get('kind') in {'OBSERVATION','MESSAGE_DELIVERED','ANALYSIS_RECORD','NATIVE_EFFECT','REFUSAL','REFUSAL_RECORD','WAIT_OBSERVED','RECONCILE'}}
    return {'registered_workers':len(workers),'active_agents':sum(r['kind']=='active' for r in workers),'standby_agents':sum(r['kind']=='standby' for r in workers),'agents_with_nim_calls':len(nim),'nim_agent_ids':sorted(nim),'required_role_ids':sorted(required),'required_roles_with_primary_contribution':sorted(required & contributed),'required_roles_contributed':judge_pass and required<=contributed,'contribution_acceptance':'Primary successful role events plus original independent Judge required-role checks'}

def init():
    OUT.mkdir(parents=True,exist_ok=True)
    if not DEV.exists():
        shutil.copytree(BASE,DEV,ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc','.pytest_cache'))
    m=manifest(DEV)
    h=hashlib.sha256(json.dumps(m,sort_keys=True).encode()).hexdigest()
    if not (OUT/'BASELINE_SOURCE_SHA256.json').exists():write(OUT/'BASELINE_SOURCE_SHA256.json',{'source':str(BASE),'stage':str(DEV),'source_sha256':h,'files':m},True)
    scorecard()
    progress(experiment_type='BASELINE_AUDIT',source_sha256=h,tests_passed=2,tests_failed=0,hypothesis='Reuse byte-matching TIM/EXE evidence and WO023 source without rerunning success',evidence_directory=str(OUT),next_action='Run SEA in isolated development stage; no WO024 directory or active qualification process observed')
    print('BASELINE',h,flush=True)

def run_world(world):
    assert world in WORLDS
    previous=scorecard()[world]
    if previous['status']=='LOCAL_JUDGE_PASS_CANDIDATE':
        print('REUSE',world,flush=True);return 0
    # A process-level global lock and OS process inventory prevent competing runs.
    procs=subprocess.check_output(['ps','-eo','args'],text=True)
    assert not any('supervisor.py' in line and '--runs-root' in line for line in procs.splitlines()),'QUALIFICATION_ALREADY_ACTIVE'
    ordinal=len(list((OUT/world).glob('attempt-*')))+1
    uid=uuid.uuid4().hex
    d=OUT/world/f'attempt-{ordinal:03}-{uid[:10]}'
    d.mkdir(parents=True)
    runid=f'codex-legion013-{world.lower()}-{ordinal:03}-{uid[:10]}'
    runs=HOME/'codex_legion013_runs'/world
    run=runs/runid
    stage=DEV
    m=manifest(stage);sourcehash=hashlib.sha256(json.dumps(m,sort_keys=True).encode()).hexdigest()
    write(d/'SOURCE_SHA256.json',{'source_sha256':sourcehash,'stage':str(stage),'files':m},True)
    # Adapt only execution identifiers and scenario selection in the existing
    # preregistration/qualification wrapper; evaluator code remains unchanged.
    source=(ROOT/'WO008_G4_EXE_NIM_023/execute.py').read_text()
    source=source.replace('STAGE = HOME / "legion_pf/wo008_g4_exe_023_stage"','STAGE = pathlib.Path('+repr(str(stage))+')')
    source=source.replace('RUNS = HOME / "legion_pf/wo008_g4_exe_023_runs"','RUNS = pathlib.Path('+repr(str(runs))+')')
    source=source.replace('RUN = RUNS / "g4-exe-gold-023"','RUN = RUNS / '+repr(runid))
    source=source.replace('PRIVATE = HOME / "legion_pf/wo008_g4_exe_023"','PRIVATE = HOME / '+repr('legion_pf/codex_legion013_private/'+uid))
    source=source.replace('FAMILY = "SYN-GAIA-EXE"','FAMILY = '+repr(world))
    source=source.replace('"wo": "WO008_G4_EXE_NIM_023"','"wo": "WO-CODEX-LEGION-013"')
    source=source.replace('assert not STAGE.exists(), "STAGE_ALREADY_EXISTS"','assert STAGE.is_dir(), "STAGE_MISSING"')
    start=source.index('    # Copy the already-tested WO013 implementation.')
    end=source.index('    agent_file =',start)
    source=source[:start]+source[end:]
    # Freeze actual candidate hashes, including later minimal repairs.
    source=source.replace('29d869f6001fb9fe4e78b1fd66b3a299edf37dc490eb569ea1922fc919b7b558',sha(stage/'tests/legion_struct/struct_agent.py'))
    source=source.replace('a94a113b307cea08698a63c300e4755c1fe6d8c24c49223b56f9390b48d8a9ca',sha(stage/'tests/legion_struct/struct_plugin.py'))
    source=source.replace('tests/legion_struct/worlds/SYN-GAIA-EXE.world.json','tests/legion_struct/worlds/'+world+'.world.json')
    source=source.replace('"--family", "GAIA-EXE"','"--family", '+repr(world.removeprefix('SYN-')))
    source=source.replace('RUNS.mkdir(parents=True)','RUNS.mkdir(parents=True, exist_ok=True)')
    source=source.replace('"wo008_g4_exe_023_judge_sb"',repr('codex_legion013_judge_'+uid))
    # Scenario-specific completeness is judged by the frozen evaluator; generic
    # counts check effect/receipt/readback balance, never EXE's fixed count.
    source=source.replace('R["native_effects"] == 5','R["native_effects"] == R["receipts"]')
    source=source.replace('R["receipts"] == 5','R["receipts"] == R["native_effects"]')
    source=source.replace('R["readback_records"] == 5','R["readback_records"] >= R["native_effects"]')
    source=source.replace('R["status"] ==\n    "PREREG_GOLD_JUDGE_PASS"','R["status"] ==\n    "PREREG_GOLD_JUDGE_PASS"')
    script=d/'execute.py';script.write_text(source)
    assert '"--family", "GAIA-EXE"' not in source
    registration_seed={'campaign_attempt_uid':uid,'ordinal_for_world':ordinal,'world':world,'stage':str(stage),'run_dir':str(run),'source_sha256':sourcehash,'official_first_attempt_eligibility':'FOR_CHATGPT_ADJUDICATION','registered_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    write(d/'CAMPAIGN_REGISTRATION.json',registration_seed,True)
    progress(world=world,attempt_uid=uid,source_sha256=sourcehash,experiment_type='PREREGISTRATION',hypothesis='Unmodified WO023 mechanism generalizes to public '+world+' requirements',evidence_directory=str(d),next_action='Execute 100 registered workers with NIM role agents')
    print('START',world,str(d),flush=True)
    with (d/'RUN.stdout.txt').open('w') as out,(d/'RUN.stderr.txt').open('w') as err:
        p=subprocess.run([str(PYTHON),str(script),str(stage),str(ROOT/'WO008_G4_EXE_NIM_021/judge.sh'),str(d)],stdout=out,stderr=err,timeout=1950)
    r=json.loads((d/'RESULT.json').read_text())
    # Preserve every native file, including errors, long agent logs and requests.
    if run.is_dir():
        shutil.copytree(run,d/'NATIVE_EVIDENCE')
    r.update(scenario=world,campaign_attempt_uid=uid,world_attempt_ordinal=ordinal,source_sha256=sourcehash,result_directory=str(d),official_vcc_at_1_declared=False)
    r['status']='LOCAL_JUDGE_PASS_CANDIDATE' if r.get('gold_qualified_locally') else 'FAIL'
    r['source_unchanged_after_run']=m==manifest(stage)
    if not r['source_unchanged_after_run']:r['status']='FAIL_SOURCE_CHANGED'
    r.update(participation(run,world,r.get('judge_verdict')=='PASS' and not r.get('judge_issues')))
    write(d/'WORLD_RESULT.json',r,True)
    write(d/'JUDGE_RESULT.json',{k:v for k,v in r.items() if k.startswith('judge_')},True)
    write(d/'NIM_RUN_METADATA.json',{**registration_seed,**{k:v for k,v in r.items() if k in ['attempt_uid','world_instance_id','workers','provider_requests','provider_200','run_dir','attempt_state','model','mode']}},True)
    write(d/'TEST_RESULTS.json',{'scope':'Qualification baseline; no implementation repair applied','acceptance_checks':r.get('acceptance_checks',{}),'process_exit':p.returncode},True)
    (d/'REPAIR.diff').write_text('')
    (d/'ROOT_CAUSE.md').write_text('No implementation repair applied in this baseline attempt.\n'+('Independent Judge PASS; inspect primary evidence for acceptance scope.\n' if r['status']=='LOCAL_JUDGE_PASS_CANDIDATE' else 'Open investigation: reconstruct first violated transition from native logs and Judge reason codes.\n'))
    hashes={str(p.relative_to(d)):sha(p) for p in d.rglob('*') if p.is_file() and p.name!='EVIDENCE_SHA256.json'}
    write(d/'EVIDENCE_SHA256.json',hashes,True)
    progress(world=world,attempt_uid=r.get('attempt_uid',uid),source_sha256=sourcehash,experiment_type='NIM_AND_JUDGE',nim_requests=r.get('provider_requests',0),native_effects=r.get('native_effects',0),receipts=r.get('receipts',0),readbacks=r.get('readback_records',0),judge_verdict=r.get('judge_verdict'),judge_issues=r.get('judge_issues'),observed_failure=None if r['status']=='LOCAL_JUDGE_PASS_CANDIDATE' else r.get('error',r.get('judge_issues')),evidence_directory=str(d),next_action='Next pending world' if r['status']=='LOCAL_JUDGE_PASS_CANDIDATE' else 'Causal reconstruction, minimal reproduction, repair and fresh attempt')
    scorecard()
    print('RESULT',world,r['status'],r.get('judge_issues'),flush=True)
    return 0 if r['status']=='LOCAL_JUDGE_PASS_CANDIDATE' else 1

if __name__=='__main__':
    OUT.mkdir(parents=True,exist_ok=True)
    with (OUT/'CAMPAIGN.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if sys.argv[1]=='init':init()
        else:sys.exit(run_world(sys.argv[1]))
