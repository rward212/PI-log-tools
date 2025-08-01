"""
PI Message Log Tools

This module provides tools for parsing and analyzing PI Message logs.
It can extract information about interface primary/backup states and
separate logs by interface instance.

The module contains two main functionalities:
1. Finding time ranges when an interface was in primary state
2. Separating log messages for different interface instances

Usage:
    python pi_log_tools.py
"""

import os
import sys
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from tqdm import tqdm
from typing import List, Tuple, Dict, Optional, Union, Pattern, Match, Any

# Constants
DATE_FORMAT = "%d-%b-%y %H:%M:%S"
LOG_LINE_PATTERN = r"^[A-Z] \d{2}-\w{3}-\d{2} \d{2}:\d{2}:\d{2}"
TIMESTAMP_PATTERN = r'\d{2}-\w{3}-\d{2} \d{2}:\d{2}:\d{2}'
PRIMARY_STATE = "Primary"
BACKUP_STATE = "Backup"
BACKUP_WITH_ERROR = "Backup_with_error"

# ===== Functions from log_tool_launcher.py =====

def get_log_file_path() -> Path:
    """
    Prompt the user for a log file path and validate it.
    
    Returns:
        Path: A validated Path object pointing to the log file
        
    Raises:
        No exceptions are raised as errors are handled internally with user prompts
    """
    while True:
        path_str = input("Please enter the path to the log file: ").strip().strip('"')
        print(f"Checking path: {path_str}")
        path = Path(path_str)
        if not path.is_absolute():
            print("Please provide an absolute path.")
            continue
        try:
            if not path.exists():
                print(f"File '{path}' does not exist.")
                continue
            return path
        except PermissionError:
            print(f"Permission denied accessing '{path}'. Please run as administrator or check permissions.")
            continue

def display_menu() -> str:
    """
    Display the main menu and get the user's choice.
    
    Returns:
        str: The user's menu choice as a string
    """
    print("\nWhat would you like to do?")
    print("1. Find time ranges when an interface was primary")
    print("2. Separate out log messages for separate interface instances")
    print("3. Exit")
    return input("Enter your choice (1, 2, or 3): ").strip()

def get_interface_details() -> Tuple[str, str]:
    """
    Prompt the user for interface details.
    
    Returns:
        Tuple[str, str]: A tuple containing (point_source, interface_id)
    """
    point_source = input("Enter the point source (e.g. OPC, RDBMS, PI2PI): ").strip()
    interface_id = input("Enter the interface ID (e.g. 1, 2): ").strip()
    return point_source, interface_id

# ===== Functions from find_times_when_primary.py =====

class LogParser:
    """
    Parser for finding time periods when an interface was in Primary state.
    
    This class parses PI Message logs to identify when an interface
    transitions between Primary and Backup states.
    """
    
    def __init__(self, point_source: str, interface_id: str) -> None:
        """
        Initialize the log parser with point source and interface ID.
        
        Args:
            point_source: The point source identifier (e.g., OPC, RDBMS)
            interface_id: The interface ID (e.g., 1, 2)
        """
        self.point_source: str = point_source
        self.interface_id: str = interface_id
        self.primary_periods: List[Tuple[datetime, Optional[datetime]]] = []
        self.current_primary_start: Optional[datetime] = None
        self.first_match_state: Optional[str] = None
        self.pattern: Pattern = re.compile(
            r'[A-Z]\s+'  # Log level (e.g., I)
            r'(\d{2}-\w{3}-\d{2} \d{2}:\d{2}:\d{2})\s+'  # Timestamp
            r'(?:[^:]+):(?:[^:]+):' + re.escape(point_source) + r'\s+'  # Match module:point_source
            r'\|\s*' + re.escape(interface_id) + r'\s*\|\s*\d+\s+'  # Match | interface_id | number
            r'\(\d+\)\s+'  # Match (#####)
            r'>>\s+UniInt failover: Interface in the "(Primary|Backup)" state(?:\. Communication with PI is in error\.)?.*',
            re.DOTALL
        )

    def is_new_log_line(self, line: str) -> bool:
        """
        Check if a line starts a new log entry.
        
        Args:
            line: The line to check
            
        Returns:
            True if the line starts a new log entry, False otherwise
        """
        return bool(re.match(LOG_LINE_PATTERN, line))

    def process_log_entry(self, full_message: str) -> None:
        """
        Process a single log entry to update Primary state periods.
        
        Args:
            full_message: The complete log message to process
        """
        match = self.pattern.search(full_message)
        if match:
            timestamp_str, state = match.groups()
            timestamp = datetime.strptime(timestamp_str, DATE_FORMAT)

            # Track the first matching state
            if self.first_match_state is None:
                self.first_match_state = state
                if full_message.endswith("Communication with PI is in error."):
                    self.first_match_state = BACKUP_WITH_ERROR

            if state == PRIMARY_STATE:
                if self.current_primary_start is None:
                    self.current_primary_start = timestamp
            elif state == BACKUP_STATE:
                if self.current_primary_start is not None:
                    self.primary_periods.append((self.current_primary_start, timestamp))
                    self.current_primary_start = None

    def parse_log_file(self, log_file_path: Union[str, Path]) -> None:
        """
        Parse the log file to extract Primary state periods.
        
        Args:
            log_file_path: Path to the log file to parse
            
        Raises:
            FileNotFoundError: If the log file does not exist
            PermissionError: If the log file cannot be accessed
        """
        current_entry: List[str] = []

        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if self.is_new_log_line(line):
                    if current_entry:
                        full_message = " ".join(l.strip() for l in current_entry)
                        self.process_log_entry(full_message)
                        current_entry = []
                current_entry.append(line)

        # Handle last log entry
        if current_entry:
            full_message = " ".join(l.strip() for l in current_entry)
            self.process_log_entry(full_message)
            if self.current_primary_start is not None:
                self.primary_periods.append((self.current_primary_start, None))

    def print_results(self) -> None:
        """
        Print the Primary state time ranges and initial state.
        
        This method outputs the results of the log parsing, including:
        - Whether the interface was in Primary or Backup state at the start of the log
        - All time periods when the interface was in Primary state
        """
        print("\nPrimary State Time Ranges:")
        sys.stdout.flush()

        # Check if the interface was in Primary state at the start of the log
        if self.first_match_state in [PRIMARY_STATE, BACKUP_WITH_ERROR]:
            print("Interface was in Primary state at the beginning of the log.")
        elif self.first_match_state == BACKUP_STATE:
            print("Interface was in Backup state at the beginning of the log.")
        else:
            print("No matching failover state entries found in the log.")
        sys.stdout.flush()

        if self.primary_periods:
            for start, end in self.primary_periods:
                if end:
                    print(f"From {start} to {end}")
                else:
                    print(f"From {start} to [still in Primary state at end of log]")
                sys.stdout.flush()
        else:
            print("No Primary state periods found.")
            sys.stdout.flush()

def find_times_when_primary(log_file_path: Union[str, Path], point_source: str, interface_id: str) -> None:
    """
    Find and display time periods when an interface was in Primary state.
    
    This function creates a LogParser instance, parses the specified log file,
    and prints the results showing when the interface was in Primary state.
    
    Args:
        log_file_path: Path to the log file to parse
        point_source: The point source identifier (e.g., OPC, RDBMS)
        interface_id: The interface ID (e.g., 1, 2)
        
    Raises:
        FileNotFoundError: If the log file does not exist
        PermissionError: If the log file cannot be accessed
    """
    log_file_path = get_validated_path(log_file_path)
    parser = LogParser(point_source, interface_id)
    parser.parse_log_file(log_file_path)
    parser.print_results()

# ===== Functions from separate_interface_instances.py =====

# Regular expression to match headers and extract point source and interface ID
header_pattern = re.compile(
    r'''
    ^[A-Z]\s+                           # Severity
    \d{2}-\w{3}-\d{2}                   # Date
    \s\d{2}:\d{2}:\d{2}\s+              # Time
    [^:]+:[^:]+:(?P<point_source>[^|]+)      # Source with colons and point source (non-greedy)
    \s+\|\s+(?P<interface_id>\d+)\s+\|  # Interface ID
    ''',
    re.VERBOSE
)

def get_validated_path(path_str: str) -> Path:
    """
    Validate a file path string and return a Path object.
    
    Args:
        path_str: The file path as a string
        
    Returns:
        A validated Path object
        
    Raises:
        ValueError: If the path is not absolute
        FileNotFoundError: If the file does not exist
    """
    path = Path(path_str)
    if not path.is_absolute():
        raise ValueError("Log file path must be absolute")
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return path

def extract_timestamp(message: str) -> datetime:
    """
    Extract timestamp from a log message.
    
    Args:
        message: The log message to extract timestamp from
        
    Returns:
        The extracted timestamp as a datetime object, or datetime.min if no timestamp is found
    """
    ts_match = re.search(TIMESTAMP_PATTERN, message)
    if ts_match:
        ts_str = ts_match.group()
        return datetime.strptime(ts_str, DATE_FORMAT)
    return datetime.min  # fallback for malformed entries

def store_message(message: str, 
                 logs_by_key: Dict[Tuple[str, str], List[Tuple[datetime, str]]], 
                 global_logs: List[Tuple[datetime, str]], 
                 key: Optional[Tuple[str, str]] = None) -> None:
    """
    Store a message in the appropriate collection.
    
    Args:
        message: The log message to store
        logs_by_key: Dictionary to store messages by interface key
        global_logs: List to store global messages
        key: The interface key (point_source, interface_id) or None for global messages
    """
    timestamp = extract_timestamp(message)
    if key:
        logs_by_key[key].append((timestamp, message))
    else:
        global_logs.append((timestamp, message))

def separate_interface_instances(log_file_path: Union[str, Path]) -> None:
    """
    Separate log messages for different interface instances.
    
    This function parses a PI Message log file and separates messages by interface instance.
    It creates separate log files for each interface instance, including global messages
    in each file.
    
    Args:
        log_file_path: Path to the log file to parse
        
    Raises:
        ValueError: If the path is not absolute
        FileNotFoundError: If the file does not exist
        PermissionError: If the file cannot be accessed
    """
    path = get_validated_path(log_file_path)

    # Dictionary to collect log messages by (point_source, interface_id)
    logs_by_key: Dict[Tuple[str, str], List[Tuple[datetime, str]]] = defaultdict(list)
    global_logs: List[Tuple[datetime, str]] = []

    # Current message context
    current_key: Optional[Tuple[str, str]] = None
    current_message: List[str] = []

    def flush_message() -> None:
        """Store the current message in the appropriate bucket."""
        if current_message:
            joined_message = ''.join(current_message)
            store_message(joined_message, logs_by_key, global_logs, current_key)

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
            elif re.match(LOG_LINE_PATTERN, line):
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

# ===== Main function =====

def main() -> None:
    """
    Main function to run the PI Message Log Tools application.
    
    This function displays a menu and handles user input to execute
    the appropriate functionality.
    """
    log_path = None

    while True:
        try:
            choice = display_menu()

            if choice == "1":
                if not log_path:
                    log_path = get_log_file_path()
                point_source, interface_id = get_interface_details()
                find_times_when_primary(log_path, point_source, interface_id)
            elif choice == "2":
                if not log_path:
                    log_path = get_log_file_path()
                separate_interface_instances(log_path)
            elif choice == "3":
                print("Goodbye!")
                break
            else:
                print("Invalid option. Please enter 1, 2, or 3.")
        except FileNotFoundError as e:
            print(f"Error: {e}")
        except PermissionError as e:
            print(f"Error: {e}")
        except ValueError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
            print("Please try again.")

if __name__ == '__main__':
    main()