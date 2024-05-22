# PortsWatcher

# Installation

```bash
sudo apt install python3 python3-venv nmap
git clone https://github.com/NoCloud-today/PortsWatcher.git
cd PortsWatcher
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
chmod +x run.sh
vi settings.ini
sudo ./run.sh
```

An example crontab entry:
```crontab
*/5 * * * * sudo python3 /.../PortsWatcher/run.sh
```

# Update to the latest version
```bash
git pull
```
