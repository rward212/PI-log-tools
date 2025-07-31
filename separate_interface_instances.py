import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import sys

# Regular expression to match headers and extract point source and interface ID
header_pattern = re.compile(
    r'''
    ^[A-Z]\s+                           # Severity
    \d{2}-\w{3}-\d{2}                   # Date
    \s\d{2}:\d{2}:\d{2}\s+              # Time
    (.*?):(.*?):               
    (?P<point_source>\w+)               # Point source
    \s+\|\s+(?P<interface_id>\d+)\s+\|  # Interface ID
    ''',
    re.VERBOSE
)

def get_validated_path(path_str):
    path = Path(path_str)
    if not path.is_absolute():
        raise ValueError("Log file path must be absolute")
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return path

def main(log_file_path):
    path = get_validated_path(log_file_path)

    # Dictionary to collect log messages by (point_source, interface_id)
    logs_by_key = defaultdict(list)
    global_logs = []

    # Current message context
    current_key = None
    current_message = []

    def flush_message():
        """Store the current message in the appropriate bucket."""
        if current_message:
            joined_message = ''.join(current_message)
            if current_key:
                # Timestamp pattern: '15-Jun-25 18:07:15'
                ts_match = re.search(r'\d{2}-\w{3}-\d{2} \d{2}:\d{2}:\d{2}', joined_message)
                if ts_match:
                    ts_str = ts_match.group()
                    timestamp = datetime.strptime(ts_str, '%d-%b-%y %H:%M:%S')
                else:
                    timestamp = datetime.min  # fallback for malformed entries

                if current_key:
                    logs_by_key[current_key].append((timestamp, joined_message))
                else:
                    global_logs.append((timestamp, joined_message))
            else:
                ts_match = re.search(r'\d{2}-\w{3}-\d{2} \d{2}:\d{2}:\d{2}', joined_message)
                if ts_match:
                    ts_str = ts_match.group()
                    timestamp = datetime.strptime(ts_str, '%d-%b-%y %H:%M:%S')
                else:
                    timestamp = datetime.min
                global_logs.append((timestamp, joined_message))

    # Parse the log file
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            # Check if the line is a header
            header_match = header_pattern.match(line)
            if header_match:
                # Save the previous message before starting a new one
                flush_message()
                current_message = [line]

                point_source = header_match.group('point_source')
                interface_id = header_match.group('interface_id')
                current_key = (point_source, interface_id)
            elif re.match(r'^[A-Z]\s+\d{2}-\w{3}-\d{2}', line):
                # Another log header that doesn't match the pattern → global message
                flush_message()
                current_message = [line]
                current_key = None
            else:
                # Continuation of previous log message
                current_message.append(line)

    # Flush the final message
    flush_message()

    # Sort global logs
    global_logs.sort()

    print("\nLog files created:")
    for (point_source, interface_id), messages in logs_by_key.items():
        filename = f'{point_source}_{interface_id}.txt'
        with open(filename, 'w', encoding='utf-8') as f:
            combined_logs = sorted(global_logs + messages)

            for _, message in combined_logs:
                f.write(message)
                if not message.endswith('\n'):
                    f.write('\n')
        print(f'    {filename}')

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python separate_interface_instances.py <log_file_path>")
        sys.exit(1)
    main(sys.argv[1])