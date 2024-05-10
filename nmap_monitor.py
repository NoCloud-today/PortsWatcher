import json
import os
import sys
import xml.etree.ElementTree as ET
import nmap3
import configparser
from urllib.parse import quote
import subprocess


def get_config() -> tuple:
    config = configparser.ConfigParser()

    if not os.path.exists("settings.ini"):
        sys.stderr.write(f"\033[mError: The configuration file 'settings.ini' does not exist.\033[0m\n")
        sys.stderr.flush()
        exit(1)

    try:
        config.read("settings.ini")
        bash_command = config["NOTIFICATION"]["NOTIFICATION_CMD"]
        message_template = config["NOTIFICATION"]["NOTIFICATION_TEMPLATE"]
    except KeyError as e:
        sys.stderr.write(
            f"\033[mConfiguration error: Check the environment variables: {e}.\033[0m\n"
        )
        sys.stderr.flush()
        exit(1)

    hosts = {}

    for section in config.sections():
        for host in config[section]:
            if host.startswith('host'):
                hosts[section] = config[section][host]

    return bash_command, message_template, hosts


def scan_nmap(filename: str, host: str) -> None:
    nmap = nmap3.NmapScanTechniques()

    try:
        nmap.nmap_tcp_scan(target=host,
                           args="-p0-65535 -v -A -T4 -Pn -sT -sU -oX {}.xml".format(filename))

    except nmap3.exceptions.NmapXMLParserError as e:
        pass

    except Exception as e:
        sys.stderr.write(
            f"\033[mScan error: {e}.\033[0m\n"
        )
        sys.stderr.flush()
        exit(1)

    sys.stdout.write(
        f"\033[92mScan \"{host}\" have been successfully received.\033[0m\n"
    )
    sys.stdout.flush()


def curl_handler(process: subprocess.CompletedProcess, id: str) -> bool:
    try:
        json_data = json.loads(process.stdout)

        if json_data["ok"]:
            sys.stdout.write(
                f"\033[92mThe scan \"{id}\" has been sent successfully.\033[0m\n"
            )
            sys.stdout.flush()

        else:
            sys.stderr.write(
                f"\033[mScan \"{id}\" was not sent successfully.\n{process.stdout}\033[0m\n"
            )
            sys.stderr.flush()
            return False

    except json.JSONDecodeError:
        sys.stderr.write(
            f"\033[mScan \"{id}\" was not sent successfully: NOTIFICATION_CMD error: Check the curl "
            f"cmd.\033[0m\n"
        )
        sys.stderr.flush()
        return False

    return True


def not_curl_handler(process: subprocess.CompletedProcess, id: str) -> bool:
    if process.returncode == 0:
        sys.stdout.write(
            f"\033[92mThe scan \"{id}\" has been sent successfully.\033[0m\n"
        )
        sys.stdout.flush()
        return True

    else:
        sys.stderr.write(
            f"\033[mScan \"{id}\" was not sent successfully.\n{process.stderr}\033[0m\n"
        )
        sys.stderr.flush()
        return False


def send_notification(bash_command: str, message: str, id: str) -> bool:
    if "curl" in bash_command:
        bash_command_message = bash_command.replace("{MESSAGE}", quote(message))
    else:
        bash_command_message = bash_command.replace(
            "{MESSAGE}", message)

    process = subprocess.run(
        bash_command_message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    return (
        curl_handler(process, id)
        if "curl" in bash_command
        else not_curl_handler(process, id)
    )


def handler(filename: str) -> str:
    #Add checking host: up
    pass


def parse(filename1: str, filename2: str) -> str:
    tree1 = ET.parse(filename1)
    tree2 = ET.parse(filename2)
    root1 = tree1.getroot()
    root2 = tree2.getroot()




if __name__ == '__main__':

    bash_command, message_template, hosts = get_config()

    for name, host in hosts.items():
        if not os.path.exists(f".scan_{name}_1.xml"):
            scan_nmap(f".scan_{name}_1", host)
        else:
            scan_nmap(f".scan_{name}_2", host)

    for name, host in hosts.items():
        differences = parse(f".scan_{name}_1.xml", f".scan_{name}_2.xml")
        send_notification(bash_command, differences, name)

    for name, host in hosts.items():
        if os.path.exists(f".scan_{name}_1.xml") and os.path.exists(f".scan_{name}_2.xml"):
            os.remove(f".scan_{name}_1.xml")
            os.rename(f".scan_{name}_2.xml", f".scan_{name}_1.xml")
