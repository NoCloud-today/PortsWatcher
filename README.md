# PortsWatcher

The tool reads new open ports using
```
nmap -p0- -v -A -T4 -Pn -sT -sU -oX file.xml <host>
```

and deliver them with the tool of choice to the system of choice.

```bash
sudo apt install python3 python3-venv
git clone git@github.com:NoCloud-today/PortsWatcher.git
cd PortsWatcher
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
chmod +x nmap_monitor.sh
vi settings.ini
sudo ./nmap_monitor.sh
```

An example crontab entry:
```crontab
*/5 * * * * sudo python3 /.../cloudron_monitor/cloudron_monitor.sh
```