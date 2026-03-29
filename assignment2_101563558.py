"""
Author: Maria Tai
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform

import datetime


pyVer = platform.python_version()
osName = os.name

print(f"Python Version: {pyVer}")
print(f"Operating System: {osName}")


# This dictionary stores common ports; which are numbers that help direct data to its right endpoint in a network.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target
    
    # Q3: What is the benefit of using @property and @target.setter?
    
    # The decorators @property and @target.setter represent getters 
    # and setters methods (respectively) through a single shared attribute
    # name. These allows both methods to be accesed as an attribute, rather
    # than as a method call.  
    
    @property
    def target(self):
        return self.__target
    
    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")

    def __del__(self):
        print("\nNetworkTool instance destroyed")


    # Q1: How does PortScanner reuse code from NetworkTool?
    
    # By inheritance. First, it passes the parent class (NetworkTool) 
    # as a parameter. Then, it implements methods from the NetworkTool
    # class by first calling the super() function, followed by the 
    # method it wants to reuse from its parent.
    

class PortScanner(NetworkTool):
    def __init__(self, target="127.0.0.1"):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("\nPortScanner instance destroyed")
        super().__del__()


    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        
        # A runtime error will likely occur, which means the
        # program will stop exeuting and display and error message. 
        # However, for this case, not using try-except causes the 
        # socket to not be properly closed, which could lead to 
        # resource leak. 
        

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            for key, value in common_ports.items():
                if key == port: 
                    service_name = value
                    break
                else:
                    service_name = "Unknown"
            
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as error_message:
            print(f"Error scanning port {port}: {error_message}")

        finally:
            sock.close()


    def get_open_ports(self):
        results = [result for result in self.scan_results if "Open" in result]
        return results
    

    # Q2: Why do we use threading instead of scanning one port at a time?
    
    # Threading allows multiple tasks to be performed side by side. So
    # essentially, while waiting for a task to be completed, another
    # process can be performed during that time. Scanning, on the other 
    # hand, may take longer to finish multiple tasks; one process has 
    # to be finished before proceeding to the following one.
    

    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port):
            thread = threading.Thread(target = self.scan_port, args=(port,))
            threads.append(thread)
        for t in threads:
            t.start()
        for t in threads:
            t.join()



    def save_results(self, results):
        try:
            conn = sqlite3.connect("scan_history.db")
            cursor = conn.cursor()
            cursor.execute('''
                        CREATE TABLE IF NOT EXISTS scans(
                        id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        target TEXT, 
                        port INTEGER, 
                        status TEXT, 
                        service TEXT, 
                        scan_date TEXT
                        )''')
            for result in results:
                cursor.execute('''
                            INSERT INTO scans (target, port, status, service, scan_date) 
                            VALUES (?, ?, ?, ?, ?
                            )''',
                            (self.target, result[0], result[1], result[2], str(datetime.datetime.now()))
                            )
            conn.commit()
        except sqlite3.Error as error:
            print(f"Error: {error}")
        finally:
            conn.close()



    def load_past_scans(self):
        try:
            conn = sqlite3.connect("scan_history.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans")
            rows = cursor.fetchall()
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        
        except (FileNotFoundError, sqlite3.OperationalError, sqlite3.Error):
            print("No past scans found.")

        finally:
            conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":

    try:
        target = input("\nEnter a target IP address: ")

        start = int(input("Enter a starting port number (between 1-1024): "))
        while (start < 1) or (start > 1024):
            start = int(input("Port must be between 1 and 1024.\nEnter starting point: "))

        end = int(input(f"Enter an ending port number (between 1-1024): "))
        while (end < start) or (end < 1) or (end > 1024):
            end = int(input(f"\t- Port must be between 1 and 1024\n\t- Greater than or equal to start => {start}\nTry again: "))

    except ValueError, TypeError:
        print("\nInvalid input. Please enter a valid integer. ")


    scanner = PortScanner(target)
    
    print(f"Scanning {target} from port {start} to {end}...")
    scanner.scan_range(start, end)

    results = scanner.get_open_ports()

    print(f"--- Scan Results for {target} ---")
    for result in results:
        print(f"Port {result[0]}: {result[1]} ({result[2]}) ")
    print("------")
    print(f"Total open ports found: {len(results)}")
    scanner.save_results(results)

    history = input("Would you like to see past scan history? (yes/no): ")

    if history == "yes":
        scanner.load_past_scans()


    # Q5: New Feature Proposal

    # Feature Name: Common Ports Protocol-based Classifier

    # This feature classifies ports based on the protocols
    # it mostly uses (like TCP, UDP or both). TCP provides
    # reliability, while UDP is less accurate but prioritizes
    # speed. 

    # P.S: There are varying classified results, but
    # for this case I will use CBT Nuggets' list.

    # Diagram: See diagram_101563558.png in the repository root

