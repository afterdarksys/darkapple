#!/usr/bin/env python3
"""Real macOS peer authentication -> SQLite -> local HTTP receiver. No live APIs."""
import http.server, json, os, pathlib, sqlite3, subprocess, tempfile, threading, time, shutil, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
APPLE=pathlib.Path(os.environ.get('DARKAPPLE_BINARY', ROOT/'target/debug/darkapple')).resolve()
SIGNAL=pathlib.Path(os.environ.get('DARKSIGNAL_BINARY', ROOT/'integration/darksignal/target/debug/darksignal')).resolve()
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

def run(*args,success=True):
    p=subprocess.run([str(APPLE),*map(str,args)],capture_output=True,text=True,timeout=20)
    if success: assert p.returncode==0,(p.returncode,p.stderr)
    return p

with tempfile.TemporaryDirectory(prefix='darkapple-e2e-',dir='/private/tmp') as tmp:
    root=pathlib.Path(tmp);root.chmod(0o700)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    key=root/'api.key';key.write_text('local-integration-test-key');key.chmod(0o600)
    sock=root/'ipc'/'signal.sock';uid=os.geteuid()
    ds={'mode':'host','host':'mac-test','socket':str(sock),'state_dir':str(root/'signal'),'api_url':f'http://127.0.0.1:{server.server_port}','api_key_file':str(key),'allow_loopback_http':True,'producers':{'darkapple':{'exe':str(APPLE.resolve()),'uid':uid}}}
    da={'host':'mac-test','state_dir':str(root/'apple'),'darksignal_socket':str(sock),'interval_seconds':1,'capacity':100,'retention_days':1,'launch_dirs':[]}
    write(root/'signal.json',ds);write(root/'apple.json',da)
    fixture=root/'observations.jsonl';fixture.write_text(json.dumps({'source':'process','kind':'process.observed','observed_at_ms':1780000000000,'pid':4242,'start_us':1234567,'exe':'/opt/.cache/example','value':'present'})+'\n')
    run('replay','--config',root/'apple.json','--input',fixture)
    # Unavailable socket retains original event across process restart.
    failed=run('ship','--config',root/'apple.json',success=False);assert failed.returncode==2
    db=sqlite3.connect(root/'apple/events.db');original=json.loads(db.execute('SELECT event FROM records WHERE event IS NOT NULL').fetchone()[0]);db.close()
    log=open(root/'darksignal.log','w+')
    process=subprocess.Popen([str(SIGNAL),'run','--config',str(root/'signal.json')],stdout=log,stderr=log)
    try:
        deadline=time.monotonic()+15
        while not sock.exists():
            assert process.poll() is None,'darksignal exited before binding'
            assert time.monotonic()<deadline,'socket timeout'
            time.sleep(.1)
        time.sleep(1.1)
        # Wrong binary with the same name cannot submit for the configured producer.
        copied=root/'darkapple';shutil.copy2(APPLE,copied)
        p=subprocess.run([str(copied),'ship','--config',str(root/'apple.json')],capture_output=True,timeout=15)
        assert p.returncode==2,'copy unexpectedly authenticated'
        time.sleep(2.1)
        run('ship','--config',root/'apple.json')
        deadline=time.monotonic()+15
        signals=[]
        while time.monotonic()<deadline:
            signals=[item for path,body in received if path=='/v1/darksignal/darkapple' for item in body['signals'] if item['rule']=='macos.process.hidden_executable']
            if signals: break
            time.sleep(.1)
        assert len(signals)==1,received
        signal=signals[0]
        assert signal['tool']=='darkapple' and signal['host']=='mac-test'
        assert signal['schema']=='darksignal.signal.v2' and signal['class']=='threat'
        assert signal['source_ref']=={'kind':'darkapple.event','id':original['event_id']}
        assert {'type':'exe','value':'/opt/.cache/example'} in signal['join']
        assert 'argv' not in json.dumps(signal)
        # Re-send same durable event after an ACK/commit crash simulation: receiver dedupes.
        db=sqlite3.connect(root/'apple/events.db');db.execute("UPDATE records SET state='pending',next_try=0 WHERE event IS NOT NULL");db.commit();db.close()
        run('ship','--config',root/'apple.json')
        db=sqlite3.connect(root/'signal/signals.db')
        rows=db.execute("SELECT payload FROM signals WHERE tool='darkapple'").fetchall();db.close()
        assert sum(json.loads(r[0])['rule']=='macos.process.hidden_executable' for r in rows)==1
        status=json.loads(run('status','--config',root/'apple.json').stdout)
        assert status['store']['pending']==0
        print('PASS: real peer identity, wrong-binary rejection, durable retries, source reference, dedupe, HTTP shipment')
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill();process.wait()
        log.seek(0)
        if process.returncode not in (-15,0): print(log.read())
        log.close();server.shutdown();server.server_close()
