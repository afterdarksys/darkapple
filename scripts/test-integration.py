#!/usr/bin/env python3
"""Real macOS peer authentication -> SQLite -> local HTTP receiver. No live APIs.

Also exercises the ack table: 0x02, an unknown byte and no byte from a scripted
fake socket (record retained, exit 2); 0x00 from the real Darksignal for a peer
mismatch and for an unknown rule (record moved to state=refused, exit 3, never
resent; `ship` stops there and leaves the later records pending and
unattempted); `requeue-refused` recovery after fixing the producer, with
Darksignal dedupe; and a refused health frame in `run` (events stay pending,
unattempted; `requeue-refused` refuses while `run` holds the writer lock).
"""
import http.server, json, os, pathlib, socket, sqlite3, struct, subprocess, tempfile, threading, time, shutil, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
APPLE=pathlib.Path(os.environ.get('DARKAPPLE_BINARY', ROOT/'target/debug/darkapple')).resolve()
SIGNAL=pathlib.Path(os.environ.get('DARKSIGNAL_BINARY', ROOT/'../darksignal/target/debug/darksignal')).resolve()
if '--bundle' in sys.argv:
    APPLE=ROOT/'build/Darkapple.app/Contents/MacOS/darkappled'
    SIGNAL=ROOT/'build/Darkapple.app/Contents/MacOS/darksignal'
received=[]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.headers['Authorization']=='Bearer local-integration-test-key'
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        received.append((self.path,body))
        self.send_response(200);self.end_headers();self.wfile.write(b'{}')
    def log_message(self,*args): pass

def write(p,value):
    p.write_text(json.dumps(value));p.chmod(0o600)

def run(*args,code=0,binary=None):
    # Every darkapple call asks for the JSON envelope (default output is human text).
    p=subprocess.run([str(binary or APPLE),*map(str,args),'--json'],capture_output=True,text=True,timeout=20)
    if code is not None: assert p.returncode==code,(p.returncode,code,p.stderr)
    return p

class FakeSignal:
    """Scripted Darksignal stand-in: answers each frame with the next byte; None closes without one."""
    def __init__(self,path,script):
        self.path=path;self.script=list(script);self.bodies=[]
        path.parent.mkdir(mode=0o700,exist_ok=True)
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.bind(str(path));path.chmod(0o600)
        self.sock.listen(8);self.sock.settimeout(.2);self.stop=False
        self.thread=threading.Thread(target=self.serve,daemon=True);self.thread.start()
    def serve(self):
        while not self.stop:
            try: conn,_=self.sock.accept()
            except socket.timeout: continue
            with conn:
                conn.settimeout(2)
                head=b''
                while len(head)<4: head+=conn.recv(4-len(head))
                n=struct.unpack('<I',head)[0];body=b''
                while len(body)<n: body+=conn.recv(n-len(body))
                self.bodies.append(json.loads(body)['body'])
                ack=self.script.pop(0) if len(self.script)>1 else self.script[0]
                if ack is not None: conn.sendall(bytes([ack]))
    def close(self):
        self.stop=True;self.thread.join();self.sock.close();self.path.unlink()

def records(state):
    db=sqlite3.connect(state/'events.db')
    rows=db.execute('SELECT id,state,attempts,event FROM records WHERE event IS NOT NULL ORDER BY id').fetchall();db.close()
    return [(i,s,a,json.loads(e)) for i,s,a,e in rows]

def sql(state,query,*args):
    db=sqlite3.connect(state/'events.db');db.execute(query,args);db.commit();db.close()

def envelope(p,kind):
    v=json.loads(p.stdout)
    assert (v['schema_version'],v['kind'],v['tool'])==(1,'darkapple.'+kind,'darkapple'),v
    return v

def status(config):
    v=envelope(run('status','--config',config),'status')
    assert v['schema']=='darkapple.status.v1' and isinstance(v['stale'],bool),v
    return v['store']

def observation(pid,exe):
    return json.dumps({'source':'process','kind':'process.observed','observed_at_ms':1780000000000,'pid':pid,'start_us':1234567,'exe':exe,'value':'present'})+'\n'

with tempfile.TemporaryDirectory(prefix='darkapple-e2e-',dir='/private/tmp') as tmp:
    root=pathlib.Path(tmp);root.chmod(0o700)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    key=root/'api.key';key.write_text('local-integration-test-key');key.chmod(0o600)
    sock=root/'ipc'/'signal.sock';uid=os.geteuid();state=root/'apple'
    ds={'mode':'host','host':'mac-test','socket':str(sock),'state_dir':str(root/'signal'),'api_url':f'http://127.0.0.1:{server.server_port}','api_key_file':str(key),'allow_loopback_http':True,'producers':{'darkapple':{'exe':str(APPLE.resolve()),'uid':uid}}}
    da={'host':'mac-test','state_dir':str(state),'darksignal_socket':str(sock),'interval_seconds':1,'capacity':100,'retention_days':1,'launch_dirs':[]}
    fake_sock=root/'fake'/'s.sock'
    write(root/'signal.json',ds);write(root/'apple.json',da);write(root/'fake.json',{**da,'darksignal_socket':str(fake_sock)})
    fixture=root/'observations.jsonl';fixture.write_text(observation(4242,'/opt/.cache/example'))
    run('replay','--config',root/'apple.json','--input',fixture)
    # Unavailable socket retains original event across process restart (transport failure, exit 2).
    run('ship','--config',root/'apple.json',code=2)
    original=records(state)[0][3]
    st=status(root/'apple.json');assert st['pending']==1 and st['counters']['transport_errors']==1,st

    # 0x02, an unknown byte and no byte are all transient: retained, exit 2, never refused.
    fake=FakeSignal(fake_sock,[0x02,0x07,None])
    for expected in ('retried','transport_errors','transport_errors'):
        sql(state,'UPDATE records SET next_try=0')
        p=run('ship','--config',root/'fake.json',code=2)
        assert 'retained for retry' in p.stderr,p.stderr
    fake.close()
    assert len(fake.bodies)==3 and all(b['event_id']==original['event_id'] for b in fake.bodies)
    [(rid,rstate,attempts,event)]=records(state)
    assert (rstate,attempts,event)==('pending',4,original),(rstate,attempts)
    st=status(root/'apple.json')
    assert (st['pending'],st['refused'],st['counters']['retried'],st['counters']['transport_errors'])==(1,0,1,3),st
    assert 'refused' not in st['counters'],st

    log=open(root/'darksignal.log','w+')
    process=subprocess.Popen([str(SIGNAL),'run','--config',str(root/'signal.json')],stdout=log,stderr=log)
    try:
        deadline=time.monotonic()+15
        while not sock.exists():
            assert process.poll() is None,'darksignal exited before binding'
            assert time.monotonic()<deadline,'socket timeout'
            time.sleep(.1)
        time.sleep(1.1)
        extra=root/'extra.jsonl';extra.write_text(observation(4245,'/opt/.cache/second')+observation(4246,'/opt/.cache/third'))
        run('replay','--config',root/'apple.json','--input',extra)
        sql(state,'UPDATE records SET next_try=0')
        before=records(state);assert [s for _,s,_,_ in before]==['pending']*3,before
        # Wrong binary with the same name cannot submit for the configured producer:
        # real Darksignal answers 0x00 (peer mismatch), a permanent refusal. ship
        # stops there: only the first record is refused, the rest stay pending,
        # unattempted (same attempts, still due).
        copied=root/'darkapple';shutil.copy2(APPLE,copied)
        p=run('ship','--config',root/'apple.json',code=3,binary=copied)
        assert 'REFUSED' in p.stderr and original['event_id'] in p.stderr,p.stderr
        assert '2 later due record(s) left pending and unattempted' in p.stderr and 'requeue-refused' in p.stderr,p.stderr
        assert '/opt/.cache/example' not in p.stderr,'refusal log must not include the event body'
        after=records(state)
        assert [s for _,s,_,_ in after]==['refused','pending','pending'],after
        assert after[0][3]==original and after[0][2]==before[0][2]+1,after[0]
        assert [(i,a,e) for i,_,a,e in after[1:]]==[(i,a,e) for i,_,a,e in before[1:]],(before,after)
        st=status(root/'apple.json');assert (st['pending'],st['refused'],st['counters']['refused'])==(2,1,1),st
        deadline=time.monotonic()+15
        while time.monotonic()<deadline and not any(i['rule']=='ipc.peer_mismatch' for path,b in received if path=='/v1/darksignal/darkapple' for i in b['signals']): time.sleep(.1)
        assert any(i['rule']=='ipc.peer_mismatch' for path,b in received if path=='/v1/darksignal/darkapple' for i in b['signals']),received
        assert not [i for path,b in received if path=='/v1/darksignal/darkapple' for i in b['signals'] if i['rule']!='ipc.peer_mismatch'],received
        # requeue-refused needs an explicit selector and reports ids it did not requeue.
        p=run('requeue-refused','--config',root/'apple.json',code=2)
        err=json.loads(p.stderr)
        assert p.stdout=='' and (err['kind'],err['category'],err['exit_code'])==('error','usage',2) and 'requires --event-id' in err['message'],p.stderr
        p=run('requeue-refused','--config',root/'apple.json','--event-id',after[1][3]['event_id'],code=2)
        v=envelope(p,'requeue_refused');assert (v['requeued'],v['not_requeued'])==(0,[after[1][3]['event_id']]),p.stdout
        assert [s for _,s,_,_ in records(state)]==['refused','pending','pending']
        # Operator recovery after switching back to the correct binary: requeue the
        # retained evidence, then one ship delivers everything.
        p=run('requeue-refused','--config',root/'apple.json','--all')
        v=envelope(p,'requeue_refused');assert (v['requeued'],v['not_requeued'])==(1,[]),p.stdout
        r=records(state);assert (r[0][1],r[0][2],r[0][3])==('pending',0,original),r[0]
        st=status(root/'apple.json');assert (st['pending'],st['refused'],st['counters']['requeued'])==(3,0,1),st
        time.sleep(2.1)
        run('ship','--config',root/'apple.json',code=0)
        assert [s for _,s,_,_ in records(state)]==['done']*3
        wanted={e['event_id'] for _,_,_,e in after}
        deadline=time.monotonic()+15
        signals=[]
        while time.monotonic()<deadline:
            signals=[item for path,body in received if path=='/v1/darksignal/darkapple' for item in body['signals'] if item['rule']=='macos.process.hidden_executable']
            if {i['source_ref']['id'] for i in signals}==wanted: break
            time.sleep(.1)
        assert len(signals)==3 and {i['source_ref']['id'] for i in signals}==wanted,received
        signal=[i for i in signals if i['source_ref']['id']==original['event_id']][0]
        assert signal['tool']=='darkapple' and signal['host']=='mac-test'
        assert signal['schema']=='darksignal.signal.v2' and signal['class']=='threat'
        assert signal['source_ref']=={'kind':'darkapple.event','id':original['event_id']}
        assert {'type':'exe','value':'/opt/.cache/example'} in signal['join']
        assert 'argv' not in json.dumps(signal)
        # Re-send same durable event after an ACK/commit crash simulation: receiver dedupes.
        sql(state,"UPDATE records SET state='pending',next_try=0 WHERE event IS NOT NULL")
        run('ship','--config',root/'apple.json')
        db=sqlite3.connect(root/'signal/signals.db')
        rows=db.execute("SELECT payload FROM signals WHERE tool='darkapple'").fetchall();db.close()
        assert sum(json.loads(r[0])['rule']=='macos.process.hidden_executable' for r in rows)==3
        assert status(root/'apple.json')['pending']==0

        # Classifier refusal (unknown rule) from the real Darksignal is permanent;
        # ship stops there and the next record is delivered by the next ship, while
        # the refused one is never resent.
        more=root/'more.jsonl';more.write_text(observation(4343,'/opt/.cache/tampered')+observation(4444,'/opt/.cache/valid'))
        run('replay','--config',root/'apple.json','--input',more)
        tampered,valid=[r for r in records(state) if r[1]=='pending']
        bad=dict(tampered[3],rule_id='macos.process.not_a_rule')
        sql(state,'UPDATE records SET event=? WHERE id=?',json.dumps(bad),tampered[0])
        p=run('ship','--config',root/'apple.json',code=3)
        assert 'macos.process.not_a_rule' in p.stderr and bad['event_id'] in p.stderr,p.stderr
        states={i:(s,a) for i,s,a,_ in records(state)}
        assert (states[tampered[0]],states[valid[0]])==(('refused',1),('pending',0)),states
        sql(state,'UPDATE records SET next_try=0')
        run('ship','--config',root/'apple.json',code=0)
        states={i:s for i,s,_,_ in records(state)}
        assert (states[tampered[0]],states[valid[0]])==('refused','done'),states
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            ids=[item['source_ref']['id'] for path,body in received if path=='/v1/darksignal/darkapple' for item in body['signals'] if 'source_ref' in item]
            if valid[3]['event_id'] in ids: break
            time.sleep(.1)
        assert valid[3]['event_id'] in ids and bad['event_id'] not in ids,ids
        st=status(root/'apple.json');assert (st['pending'],st['refused'])==(0,1),st
        print('PASS: real peer identity, wrong-binary refusal stops ship (1 refused, rest pending), requeue-refused recovery, unknown-rule refusal, 0x02/unknown/no-byte retention, source reference, dedupe, HTTP shipment')
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill();process.wait()
        log.seek(0)
        if process.returncode not in (-15,0): print(log.read())
        log.close();server.shutdown();server.server_close()

    # run: a refused health frame stops the batch, so events are not refused one by one.
    run_state=root/'run';run_cfg=root/'run.json'
    write(run_cfg,{**da,'state_dir':str(run_state),'darksignal_socket':str(fake_sock),'capacity':100000})
    run('replay','--config',run_cfg,'--input',fixture)
    fake=FakeSignal(fake_sock,[0x00])
    daemon=subprocess.Popen([str(APPLE),'run','--config',str(run_cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+20
        while time.monotonic()<deadline and not fake.bodies: time.sleep(.1)
        time.sleep(1)
        # The daemon holds the exclusive writer lock: requeue-refused must refuse.
        p=run('requeue-refused','--config',run_cfg,'--all',code=2)
        assert 'another darkapple writer' in p.stderr,p.stderr
    finally:
        daemon.terminate()
        _,err=daemon.communicate(timeout=20)
        fake.close()
    assert daemon.returncode==0,(daemon.returncode,err)
    assert fake.bodies and all(b['schema']=='darkapple.health.v1' for b in fake.bodies),fake.bodies
    assert 'REFUSED a health frame' in err,err
    st=envelope(run('status','--config',run_cfg),'status')['store']
    assert st['counters']['health_refused']>=1 and 'refused' not in st['counters'] and st['refused']==0,st
    assert all(s=='pending' and a==0 for _,s,a,_ in records(run_state))
    print('PASS: run mode keeps events pending when the health frame is refused; requeue-refused refuses while run holds the writer lock')
