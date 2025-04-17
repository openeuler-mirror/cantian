import os
import re
from exec_cmd import exec_popen
from get_config_info import get_value

cantian_user = get_value("deploy_user")


def pad_file_to_512(input_file, output_file=None):
    """
    Pads a file to 512-byte alignment with zero bytes.

    Args:
        input_file (str): Source file path.
        output_file (str, optional): Destination file path  . If None, overwrites the input file.

    Returns:
        int: Final file size in bytes.

    Raises:
        FileNotFoundError: If the input file does not exist.
        IOError: If read/write fails.
    """
    try:
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"Input file '{input_file}' not found.")

        with open(input_file, 'rb') as f:
            data = f.read()

        original_size = len(data)
        pad_size = (512 - original_size % 512) % 512
        if pad_size:
            data += b'\x00' * pad_size

        if output_file is None:
            output_file = input_file

        with open(output_file, 'wb') as f:
            f.write(data)

        total_size = len(data)
        return total_size

    except Exception as e:
        raise IOError(f"Failed to pad file '{input_file}': {e}")


def parse_numeric(val: str) -> int:
    try:
        return int(float(val))
    except ValueError:
        raise ValueError(f"Cannot convert '{val}' to integer.")


def get_written_size(vg_file_path: str) -> int:
    cmd = f'su -s /bin/bash - {cantian_user} -c "dsscmd ls -p {vg_file_path} -w 0"'
    code, stdout, stderr = exec_popen(cmd)

    no_file_result = " ".join(["The path", vg_file_path, "is not exsit."])

    if stdout == no_file_result:
        return 0

    if code != 0:
        raise RuntimeError(f"`dsscmd ls` failed: {stderr}")

    lines = stdout.strip().splitlines()
    if len(lines) < 2:
        raise ValueError("Unexpected `dsscmd ls` output: too few lines.")

    headers = lines[0].split()
    values = lines[1].split()

    if 'written_size' not in headers:
        raise ValueError("'written_size' column not found.")

    index = headers.index('written_size')
    return parse_numeric(values[index])


def parse_hex_dump(raw_output: str) -> str:
    hex_bytes = []

    for line in raw_output.strip().splitlines():
        # Extract exactly 16 hex bytes using regex: 2-digit hex tokens
        matches = re.findall(r'\b[0-9a-fA-F]{2}\b', line)
        if matches:
            hex_bytes.extend(matches)

    try:
        byte_data = bytes.fromhex(''.join(hex_bytes))
        return byte_data.replace(b'\x00', b'').decode('utf-8', errors='replace').strip()
    except Exception as e:
        raise ValueError(f"Failed to decode hex dump: {e}")


def read_dss_content(vg_file_path: str, size: int) -> str:
    cmd = f'su -s /bin/bash - {cantian_user} -c "dsscmd examine -p {vg_file_path} -o 0 -f x -s {size}"'
    code, stdout, stderr = exec_popen(cmd)

    if code != 0:
        raise RuntimeError(f"`dsscmd examine` failed: {stderr}")

    return parse_hex_dump(stdout)


def read_dss_file(vg_file_path: str) -> str:
    written_size = get_written_size(vg_file_path)
    if written_size == 0:
        return "[Empty] No actual data written to this DSS file."
    return read_dss_content(vg_file_path, written_size)


# Example usage:
if __name__ == "__main__":
    # Example usage for padding file to 512-byte alignment
    try:
        pad_file_to_512("./example.txt")
    except Exception as e:
        print(f"Operation failed: {e}")

    # Example usage for reading DSS file content
    path = '+vg1/testfile.txt'
    content = read_dss_file(path)
    print(content)
