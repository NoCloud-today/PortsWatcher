import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import nmap3
import configparser
from urllib.parse import quote
import subprocess


def get_config() -> tuple:
    """
    Retrieves configuration settings from 'settings.ini'.

    Returns:
        tuple: A tuple containing the notification command, template, and hosts dictionary.
    """
    config = configparser.ConfigParser()

    if not os.path.exists("settings.ini"):
        sys.stderr.write(f"\033[mError: The configuration file 'settings.ini' does not exist.\033[0m\n")
        sys.stderr.flush()
        exit(1)

    try:
        config.read("settings.ini")
        bash_command = config["NOTIFICATION"]["NOTIFICATION_CMD"]
        message_template = config["NOTIFICATION"]["NOTIFICATION_TEMPLATE"]

        if bash_command == '':
            sys.stderr.write(
                f"\033[mConfiguration error: Check the environment variables: NOTIFICATION_CMD.\033[0m\n"
            )
            sys.stderr.flush()
            exit(1)

        if message_template == '':
            sys.stderr.write(
                f"\033[mConfiguration error: Check the environment variables: NOTIFICATION_TEMPLATE.\033[0m\n"
            )
            sys.stderr.flush()
            exit(1)

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
                if config[section][host] == '':
                    sys.stderr.write(
                        f"\033[33mWarning: The host {section} is empty. It will be skipped.\033[0m\n"
                    )
                    sys.stderr.flush()
                else:
                    hosts[section] = config[section][host]

    return bash_command, message_template, hosts


def scan_nmap(filename: str, host: str, name: str) -> None:
    """
    Performs a Nmap scan on the specified host and saves the results to an XML file.

    Args:
        filename (str): The name of the XML file where the scan results will be saved.
        host (str): The target host IP address or hostname.
        name (str): A descriptive name for the scan.
    """
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
        f"\033[92mScan \"{name}\" have been successfully received.\033[0m\n"
    )
    sys.stdout.flush()


def curl_handler(process: subprocess.CompletedProcess, id: str) -> bool:
    """
    Handles the response from a cURL command used for sending notifications.

    Args:
        process (subprocess.CompletedProcess): The completed subprocess object.
        id (str): An identifier for the scan.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
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
    """
    Handles the response from a non-cURL command used for sending notifications.

    Args:
        process (subprocess.CompletedProcess): The completed subprocess object.
        id (str): An identifier for the scan.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
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
    """
    Sends a notification based on the provided command and message.

    Args:
        bash_command (str): The command to execute for sending the notification.
        message (str): The message to include in the notification.
        id (str): An identifier for the scan.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
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


def get_ports(root: ET.Element) -> dict:
    """
    Extracts port information from a Nmap XML scan result.

    Args:
        root (ET.Element): The root element of the Nmap XML document.

    Returns:
        dict: A dictionary mapping port IDs to dictionaries containing protocol and state.
    """
    ports_dict = {}

    for port in root.findall(".//port"):
        protocol = port.attrib['protocol']
        port_id = port.attrib['portid']
        state = port.find('state').attrib['state']
        ports_dict[port_id] = {'protocol': protocol, 'state': state}

    return ports_dict


def parse(filename1: str, filename2: str = None) -> str:
    """
    Compares two Nmap XML scan results and generates a message describing the differences.

    Args:
        filename1 (str): The name of the first XML file containing a scan result.
        filename2 (str, optional): The name of the second XML file containing another scan result. Defaults to None.

    Returns:
        str: A string summarizing the differences between the two scan results.
    """
    if not (filename2 is None):
        tree1 = ET.parse(filename1)
        tree2 = ET.parse(filename2)
        root1 = tree1.getroot()
        root2 = tree2.getroot()

        ports1 = get_ports(root1)
        ports2 = get_ports(root2)

        list_ports1 = list(ports1)
        list_ports2 = list(ports2)

        start_before = 'is' if len(ports2) == 1 else 'are'
        ending_before = '' if len(ports2) == 1 else 's'

        message_before = f'There {start_before} {len(ports2)} open port{ending_before}.\n'

        for port in list_ports1:
            if port in list_ports2:
                list_ports2.remove(port)

        starting = 'were' if len(list_ports1) > 1 or len(list_ports1) == 0 else 'was'
        ending = '' if len(list_ports1) == 1 else 's'
        last_modified_time = datetime.fromtimestamp((os.path.getmtime(filename1))).strftime("%Y-%m-%d %H:%M:%S")
        str_ports1 = ': ' + ','.join(list_ports1) if len(list_ports1) > 0 else '.'

        message_prev = f'There {starting} {len(list_ports1)} open port{ending} in the previous scan ({last_modified_time}){str_ports1}\n'
        ending = '' if len(list_ports2) == 1 else 's'
        str_ports2 = ': ' + ','.join(list_ports2) if len(list_ports2) > 0 else '.'

        message_new = f'{len(list_ports2)} open port{ending} detected{str_ports2}'

        return message_prev + message_before + message_new

    else:
        tree1 = ET.parse(filename1)
        root1 = tree1.getroot()
        ports1 = list(get_ports(root1))

        ending = 's' if len(ports1) > 1 else ""
        str_ports1 = ': ' + ','.join(ports1) if len(ports1) > 0 else '.'

        if len(ports1) > 0:
            message_new = (f"This is the first scan of host.\n"
                           f"{len(ports1)} open port{ending} detected{str_ports1}")
        else:
            message_new = "No open ports found"

        return message_new


def update_template(message_template: str, message, time: str) -> str:
    """
    Updates a notification message template with specific details.

    Args:
        message_template (str): The original message template.
        message (str): The message content to insert into the template.
        time (str): The timestamp to insert into the template.

    Returns:
        str: The updated message template.
    """
    message_content = message_template.replace('{MESSAGE}', message)
    message_content = message_content.replace('{creationTime}', time)

    return message_content


def is_debug() -> bool:
    """
        Checks if the script is running in debug mode.

        Returns:
        - bool: True if the script is running in debug mode, False otherwise.
        """
    return '--debug' in sys.argv


if __name__ == '__main__':

    current_time = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    sys.stdout.write(f"Time: {current_time}.\n")
    sys.stdout.flush()

    bash_command, message_template, hosts = get_config()

    for name, host in hosts.items():
        if not os.path.exists(f".scan_{name}_1.xml"):
            scan_nmap(f".scan_{name}_1", host, name)
            differences = parse(f".scan_{name}_1.xml")
            message = update_template(message_template, differences, current_time)
        else:
            scan_nmap(f".scan_{name}_2", host, name)
            differences = parse(f".scan_{name}_1.xml", f".scan_{name}_2.xml")
            message = update_template(message_template, differences, current_time)
            os.remove(f".scan_{name}_1.xml")
            os.rename(f".scan_{name}_2.xml", f".scan_{name}_1.xml")

        stat = send_notification(bash_command, f'{name}{message}', name)

        if stat and is_debug():
            sys.stdout.write(f'{name}{message}\n')
            sys.stdout.flush()
