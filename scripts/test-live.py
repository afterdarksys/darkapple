#!/usr/bin/env python3
"""Read-only live collection into disposable state, no running Darksignal."""
import json,pathlib,subprocess,tempfile,time
root=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='darkapple-live-',dir='/private/tmp') as temp:
    folder=pathlib.Path(temp);folder.chmod(0o700)
    config={'host':'live-smoke','state_dir':str(folder/'state'),'darksignal_socket':str(folder/'absent.sock'),'interval_seconds':1,'capacity':10000,'retention_days':1,'endpoint_helper':str(root/'build/EndpointSensor'),'launch_dirs':['/Library/LaunchAgents','/Library/LaunchDaemons']}
    path=folder/'config.json';path.write_text(json.dumps(config));path.chmod(0o600)
    p=subprocess.Popen([str(root/'target/debug/darkapple'),'run','--config',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            assert p.poll() is None,'daemon exited'
            status=folder/'state/status.json'
            if status.exists():
                result=json.loads(status.read_text())
                if result['store']['counters'].get('health_transport_errors',0)>0: break
            time.sleep(.2)
        else: raise AssertionError('No collection/failed-delivery status before deadline')
        assert result['store']['records']>0
        assert result['coverage']['endpoint_security']['status']=='unavailable'
        p.terminate();out,err=p.communicate(timeout=10)
        assert p.returncode==0,(p.returncode,err)
        print('PASS: live collection continues with socket unavailable; unsigned ES reports unavailable; graceful shutdown')
        print(json.dumps({k:v['status'] for k,v in result['coverage'].items()},sort_keys=True))
    finally:
        if p.poll() is None: p.kill();p.communicate()
