import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import nmap3
import configparser
from urllib.parse import quote
from concurrent.futures import ProcessPoolExecutor, Future, as_completed
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
        bash_command_conf = config["NOTIFICATION"]["NOTIFICATION_CMD"]
        message_template_conf = config["NOTIFICATION"]["NOTIFICATION_TEMPLATE"]

        if bash_command_conf == '':
            sys.stderr.write(
                f"\033[mConfiguration error: Check the environment variables: NOTIFICATION_CMD.\033[0m\n"
            )
            sys.stderr.flush()
            exit(1)

        if message_template_conf == '':
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

    hosts_conf = {}

    for section in config.sections():
        if section != 'NOTIFICATION':
            try:
                if config[section]['HOST'] == '':
                    sys.stderr.write(
                        f"\033[33mWarning: The host {section} is empty. It will be skipped.\033[0m\n"
                    )
                    sys.stderr.flush()
                else:
                    hosts_conf[section] = config[section]['HOST']

            except KeyError as e:
                sys.stderr.write(
                    f"\033[33mWarning: The host {section} does not exist. It will be skipped.\033[0m\n"
                )
                sys.stderr.flush()

    return bash_command_conf, message_template_conf, hosts_conf


def scan_nmap(filename_scan: str, host_scan: str, name_host: str) -> None:
    """
    Performs a Nmap scan on the specified host and saves the results to an XML file.

    Args:
        filename_scan (str): The name of the XML file where the scan results will be saved.
        host_scan (str): The target host IP address or hostname.
        name_host (str): A descriptive name for the scan.
    """
    nmap = nmap3.NmapScanTechniques()

    try:
        nmap.nmap_tcp_scan(target=host_scan,
                           args="-vv -sT -sU -p0-65535 -T4 -Pn --max-rtt-timeout 200ms --max-retries 3 --max-scan-delay 2 -oX {}".format(
                               filename_scan))

    except nmap3.exceptions.NmapXMLParserError as e:
        pass

    except Exception as e:
        sys.stderr.write(
            f"\033[mScan error: {e}.\033[0m\n"
        )
        sys.stderr.flush()
        exit(1)

    sys.stdout.write(
        f"\033[92mScan \"{name_host}\" have been successfully received.\033[0m\n"
    )
    sys.stdout.flush()


def curl_handler(process_curl: subprocess.CompletedProcess, name_host: str) -> bool:
    """
    Handles the response from a cURL command used for sending notifications.

    Args:
        process_curl (subprocess.CompletedProcess): The completed subprocess object.
        name_host (str): An identifier for the scan.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
    if process_curl.returncode != 0:
        sys.stderr.write(
            f"\033[mScan \"{name_host}\" was not sent successfully.\n{process_curl.stdout}\033[0m\n"
            f"\033[0m\n"
        )
        sys.stderr.flush()
        return False

    try:
        json_data_result = json.loads(process_curl.stdout)

        if json_data_result["ok"]:
            sys.stdout.write(
                f"\033[92mThe scan \"{name_host}\" has been sent successfully.\033[0m\n"
            )
            sys.stdout.flush()

        else:
            sys.stderr.write(
                f"\033[mScan \"{name_host}\" was not sent successfully.\n{process_curl.stdout}\033[0m\n"
            )
            sys.stderr.flush()
            return False

    except json.JSONDecodeError:
        sys.stderr.write(
            f"\033[mScan \"{name_host}\" was not sent successfully: NOTIFICATION_CMD error: Check the curl "
            f"cmd.\033[0m\n"
        )
        sys.stderr.flush()
        return False

    except KeyError as e:
        sys.stderr.write(
            f"\033[mScan \"{name_host}\" was not sent successfully: {e}\n.\033[0m\n{json.dumps(json_data_result, indent=4)}\n"
        )
        sys.stderr.flush()
        return False

    return True


def not_curl_handler(process_not_curl: subprocess.CompletedProcess, name_host: str) -> bool:
    """
    Handles the response from a non-cURL command used for sending notifications.

    Args:
        process_not_curl (subprocess.CompletedProcess): The completed subprocess object.
        name_host (str): An identifier for the scan.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
    if process_not_curl.returncode == 0:
        sys.stdout.write(
            f"\033[92mThe scan \"{name_host}\" has been sent successfully.\033[0m\n"
        )
        sys.stdout.flush()
        return True

    else:
        sys.stderr.write(
            f"\033[mScan \"{name_host}\" was not sent successfully.\n{process_not_curl.stderr}\033[0m\n"
        )
        sys.stderr.flush()
        return False


def send_notification(bash_command_send: str, message_send: str, name_host: str) -> bool:
    """
    Sends a notification based on the provided command and message.

    Args:
        bash_command_send (str): The command to execute for sending the notification.
        message_send (str): The message to include in the notification.
        name_host (str): An identifier for the scan.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
    if "curl" in bash_command_send:
        bash_command_message = bash_command_send.replace("{MESSAGE}", quote(message_send))
    else:
        bash_command_message = bash_command_send.replace(
            "{MESSAGE}", message_send)

    process = subprocess.run(
        bash_command_message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    return (
        curl_handler(process, name_host)
        if "curl" in bash_command_send
        else not_curl_handler(process, name_host)
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


def find_host_ranges(hosts_check_srt: list) -> list:
    hosts_check = [int(num_str) for num_str in hosts_check_srt]
    if hosts_check == []:
        return []
    hosts_check.sort()
    ranges = []
    start = hosts_check[0]

    for i in range(1, len(hosts_check)):
        if int(hosts_check[i]) - int(hosts_check[i - 1]) > 1:
            if start == hosts_check[i - 1]:
                ranges.append(str(start))
            else:
                ranges.append(f'{start} - {hosts_check[i - 1]}')
            start = hosts_check[i]

    if start == hosts_check[-1]:
        ranges.append(str(start))
    else:
        ranges.append(f'{start} - {hosts_check[-1]}')
    return ranges


def group_and_join(lst, group_size=5):
    groups = [lst[i:i + group_size] for i in range(0, len(lst), group_size)]

    result = '\n'.join(', '.join(group) for group in groups)

    return result


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

        ending_before = '' if len(ports2) == 1 else 's'
        message_before = f'{len(ports2)} open port{ending_before}.\n'

        for port in list_ports1:
            if port in list_ports2:
                list_ports2.remove(port)

        ending = '' if len(list_ports1) == 1 else 's'
        last_modified_time = datetime.fromtimestamp((os.path.getmtime(filename1))).strftime("%Y-%m-%d %H:%M:%S")

        message_prev = f'{len(list_ports1)} open port{ending} in the previous scan ({last_modified_time})\n'
        ending = '' if len(list_ports2) == 1 else 's'
        ranges_port = find_host_ranges(list_ports2)
        str_ports2 = ':\n ' + group_and_join(ranges_port) if len(list_ports2) > 0 else '.'

        message_new = f'{len(list_ports2)} new open port{ending} detected{str_ports2}'

        return message_prev + message_before + message_new

    else:
        tree1 = ET.parse(filename1)
        root1 = tree1.getroot()
        ports1 = list(get_ports(root1))

        ending = 's' if len(ports1) > 1 else ""
        range_ports1 = find_host_ranges(ports1)
        str_ports1 = ':\n ' + group_and_join(range_ports1) if len(ports1) > 0 else '.'

        if len(ports1) > 0:
            message_new = (f"This is the first scan of host.\n"
                           f"{len(ports1)} open port{ending} detected{str_ports1}")
        else:
            message_new = "No open ports found"

        return message_new


def update_template(message_template_up: str, message_send, curr_time: str) -> str:
    """
    Updates a notification message template with specific details.

    Args:
        message_template_up (str): The original message template.
        message_send (str): The message content to insert into the template.
        curr_time (str): The timestamp to insert into the template.

    Returns:
        str: The updated message template.
    """
    message_content = message_template_up.replace('{MESSAGE}', message_send)
    message_content = message_content.replace('{creationTime}', curr_time)

    return message_content


def is_debug() -> bool:
    """
        Checks if the script is running in debug mode.

        Returns:
        - bool: True if the script is running in debug mode, False otherwise.
        """
    return '--debug' in sys.argv


def handler_callback(future_curr: Future, info_future: dict) -> None:
    name_host = info_future['name']
    if not os.path.exists(f".scan_{name_host}_2.xml"):
        differences = parse(f".scan_{name_host}_1.xml")
    else:
        differences = parse(f".scan_{name_host}_1.xml", f".scan_{name_host}_2.xml")
        os.remove(f".scan_{name_host}_1.xml")
        os.rename(f".scan_{name_host}_2.xml", f".scan_{name_host}_1.xml")

    message = update_template(info_future['message_template'], differences, info_future['current_time'])
    stat = send_notification(info_future['bash_command'], f'{name_host}{message}', name_host)

    if stat and is_debug():
        sys.stdout.write(f'{name_host}{message}\n')
        sys.stdout.flush()


if __name__ == '__main__':

    current_time = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    sys.stdout.write(f"Time: {current_time}.\n")
    sys.stdout.flush()

    bash_command, message_template, hosts = get_config()

    with ProcessPoolExecutor() as executor:
        message_template_lambda = message_template
        futures = {}
        for name, host in hosts.items():
            filename = f".scan_{name}_2.xml" if os.path.exists(f".scan_{name}_1.xml") else f".scan_{name}_1.xml"
            futures[executor.submit(scan_nmap, filename, host, name)] = name

        for future in as_completed(futures.keys()):
            name = futures[future]

            data = {
                'bash_command': bash_command,
                'message_template': message_template_lambda,
                'name': name,
                'current_time': current_time
            }

            future.add_done_callback(lambda x: handler_callback(x, data))
