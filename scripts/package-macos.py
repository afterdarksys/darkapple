#!/usr/bin/env python3
"""Package already-built native-architecture development binaries. No installation."""
import pathlib, plistlib, shutil, sys, subprocess
root=pathlib.Path(__file__).resolve().parents[1]
bundle=root/'build/Darkapple.app'
if bundle.exists(): shutil.rmtree(bundle)  # generated development artifact only
contents=bundle/'Contents'
helper=contents/'Helpers/EndpointSensor.app/Contents'
for d in [contents/'MacOS',contents/'Library/LaunchDaemons',helper/'MacOS']:
    d.mkdir(parents=True,exist_ok=True)
for src,dst in [(root/'build/Darkapple',contents/'MacOS/Darkapple'),(root/'target/debug/darkapple',contents/'MacOS/darkappled'),(pathlib.Path(sys.argv[1]),contents/'MacOS/darksignal'),(root/'build/EndpointSensor',helper/'MacOS/EndpointSensor')]:
    shutil.copy2(src,dst)
for name in ['com.afterdark.darkapple.plist','com.afterdark.darksignal.plist']:
    shutil.copy2(root/'deploy'/name,contents/'Library/LaunchDaemons'/name)
for folder,name,identifier in [(contents,'Darkapple','com.afterdark.darkapple'),(helper,'EndpointSensor','com.afterdark.darkapple.endpoint')]:
    info={'CFBundleExecutable':name,'CFBundleIdentifier':identifier,'CFBundleName':name,'CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'0.1.0','LSMinimumSystemVersion':'13.0'}
    (folder/'Info.plist').write_bytes(plistlib.dumps(info))
# Ad-hoc signing is useful for a repeatable local bundle, NOT ES entitlement approval.
for binary in [helper.parent,contents/'MacOS/darkappled',contents/'MacOS/darksignal',bundle]:
    subprocess.run(['codesign','--force','--sign','-',str(binary)],check=True)
print(f'Development bundle: {bundle}\nNo Endpoint Security entitlement or distribution signature applied.')
