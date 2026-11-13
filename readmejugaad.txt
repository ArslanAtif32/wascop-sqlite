run mitmdump -q -s .\Interception.py in one terminal 

now run & $chrome="$env:ProgramFiles\Google\Chrome\Application\chrome.exe" --user-data-dir="$env:TEMP\wascope-test" --proxy-server="http://127.0.0.1:8080" --proxy-bypass-list="<-loopback>" http://localhost:3000 to run chrome
on debug mode


step2: now run  chrome driver
for running chrome driver if  :
$chrome = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"

& $chrome `
  --user-data-dir="$env:TEMP\wascope-test" `
  --proxy-server="http://127.0.0.1:8080" `
  --proxy-bypass-list="<-loopback>" `
  http://localhost:3000

step 3:
now verify headers python -c "import json; d=json.load(open('mitmproxy/localhost/header.json',encoding='utf-8')); print('Keys:',list(d)); print('Headers captured:',bool(d.get('request_header')))"

now run replay.py py -3.12 Replay.py --host localhost       

make sure to run your website in second terminal so it will pop up in chrome driver