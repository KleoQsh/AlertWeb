import streamlit as st
import pandas as pd
import json
import time
from datetime import datetime
import threading
import os
import subprocess
import logging
from typing import List, Dict, Optional
import io



class SuricataMonitor:
    """
    A class to monitor Suricata alerts from pfSense via SSH connection (Windows compatible)
    """

    def __init__(self, host: str, username: str, password: str, log_path: str, port: int = 22):
        """
        Initialize the Suricata monitor

        Args:
            host: pfSense host IP address
            username: SSH username
            password: SSH password
            log_path: Path to Suricata eve.json log file
            port: SSH port (default: 22)
        """
        self.host = host
        self.username = username
        self.password = password
        self.log_path = log_path
        self.port = port
        self.connected = False


        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """
        Test SSH connection to pfSense using Windows SSH client

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:

            ssh_command = [
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10',
                '-o', 'BatchMode=yes',
                '-p', str(self.port),
                f'{self.username}@{self.host}',
                'echo "connection_test"'
            ]


            result = subprocess.run(
                ssh_command,
                capture_output=True,
                text=True,
                timeout=15,
                input=self.password + '\n' if self.password else None
            )

            if result.returncode == 0 and "connection_test" in result.stdout:
                self.connected = True
                self.logger.info(f"Successfully connected to {self.host}")
                return True
            else:

                return self._try_powershell_ssh()

        except subprocess.TimeoutExpired:
            self.logger.error("Connection timeout")
            return False
        except FileNotFoundError:

            self.logger.info("Windows SSH client not found, trying alternative method")
            return self._try_powershell_ssh()
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            return False

    def _try_powershell_ssh(self) -> bool:
        """Try connecting using PowerShell SSH"""
        try:

            powershell_cmd = [
                'powershell', '-Command',
                f'''
                $securePassword = ConvertTo-SecureString "{self.password}" -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential ("{self.username}", $securePassword)
                try {{
                    ssh -o StrictHostKeyChecking=no -p {self.port} {self.username}@{self.host} "echo connection_test"
                }} catch {{
                    Write-Output "failed"
                }}
                '''
            ]

            result = subprocess.run(
                powershell_cmd,
                capture_output=True,
                text=True,
                timeout=15
            )

            if "connection_test" in result.stdout:
                self.connected = True
                self.logger.info(f"Successfully connected to {self.host} via PowerShell")
                return True
            else:
                self.logger.error("PowerShell SSH connection failed")
                return False

        except Exception as e:
            self.logger.error(f"PowerShell SSH error: {e}")
            return False

    def disconnect(self):
        """Mark SSH connection as closed"""
        self.connected = False
        self.logger.info("SSH connection marked as closed")

    def execute_command(self, command: str) -> Optional[str]:
        """
        Execute a command on the remote pfSense system using Windows SSH

        Args:
            command: Command to execute

        Returns:
            str: Command output or None if error
        """

        if not self.connected:
            self.logger.info("Attempting to reconnect for command execution")
            if not self.connect():
                self.logger.error("Not connected to pfSense")
                return None

        try:

            sshpass_command = [
                'sshpass', '-p', self.password,
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10',
                '-o', 'BatchMode=no',
                '-p', str(self.port),
                f'{self.username}@{self.host}',
                command
            ]

            result = subprocess.run(
                sshpass_command,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return result.stdout
            else:

                return self._execute_powershell_ssh_secure(command)

        except FileNotFoundError:

            return self._execute_powershell_ssh_secure(command)
        except subprocess.TimeoutExpired:
            self.logger.error("Command execution timeout")
            return None
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            return None

    def _execute_powershell_ssh_secure(self, command: str) -> Optional[str]:
        """Execute SSH command via PowerShell with secure credential handling"""
        try:

            powershell_cmd = [
                'powershell', '-Command',
                f'''
                $env:SSHPASS = "{self.password}"
                try {{
                    $result = sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {self.port} {self.username}@{self.host} "{command}" 2>$null
                    if ($LASTEXITCODE -eq 0) {{
                        Write-Output $result
                    }} else {{
                        # Try alternative method with expect-like behavior
                        $script = @"
                        spawn ssh -o StrictHostKeyChecking=no -p {self.port} {self.username}@{self.host} "{command}"
                        expect "password:"
                        send "{self.password}\r"
                        expect eof
"@
                        Write-Output "command_alternative_failed"
                    }}
                }} catch {{
                    Write-Output "command_failed"
                }}
                Remove-Item Env:SSHPASS -ErrorAction SilentlyContinue
                '''
            ]

            result = subprocess.run(
                powershell_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if "command_failed" not in result.stdout and "command_alternative_failed" not in result.stdout:
                return result.stdout.strip()
            else:

                return self._execute_with_temp_key(command)

        except Exception as e:
            self.logger.error(f"PowerShell SSH secure command error: {e}")
            return self._execute_with_temp_key(command)

    def _execute_with_temp_key(self, command: str) -> Optional[str]:
        """Fallback method using temporary authentication"""
        try:

            batch_content = f'''@echo off
echo {self.password} | ssh -o StrictHostKeyChecking=no -p {self.port} {self.username}@{self.host} "{command}"'''


            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False) as f:
                f.write(batch_content)
                temp_file = f.name


            result = subprocess.run(
                [temp_file],
                capture_output=True,
                text=True,
                timeout=30,
                shell=True
            )


            import os
            try:
                os.unlink(temp_file)
            except:
                pass

            if result.returncode == 0:
                return result.stdout.strip()
            else:
                self.logger.error(f"Temp key method failed: {result.stderr}")
                return None

        except Exception as e:
            self.logger.error(f"Temp key method error: {e}")
            return None

    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """
        Retrieve recent Suricata alerts from the eve.json log file

        Args:
            limit: Maximum number of alerts to retrieve

        Returns:
            List[Dict]: List of alert dictionaries
        """

        if not self.connected:
            self.logger.info("Attempting to reconnect for alerts retrieval")
            if not self.connect():
                self.logger.error("Not connected to pfSense")
                return []

        try:

            command = f"tail -n {limit * 2} {self.log_path} 2>/dev/null || echo 'Log file not found'"

            output = self.execute_command(command)

            if not output or "Log file not found" in output:
                self.logger.warning(f"Could not read log file: {self.log_path}")
                return []

            alerts = []
            lines = output.strip().split('\n')

            for line in lines:
                if not line.strip():
                    continue

                try:

                    log_entry = json.loads(line.strip())


                    if log_entry.get('event_type') == 'alert':
                        alert = self.parse_alert(log_entry)
                        if alert:
                            alerts.append(alert)

                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse JSON line: {e}")
                    continue
                except Exception as e:
                    self.logger.warning(f"Error processing log entry: {e}")
                    continue


            alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            return alerts[:limit]

        except Exception as e:
            self.logger.error(f"Error retrieving alerts: {e}")
            return []

    def parse_alert(self, log_entry: Dict) -> Optional[Dict]:
        """
        Parse a Suricata alert log entry into a structured format

        Args:
            log_entry: Raw log entry dictionary

        Returns:
            Dict: Parsed alert dictionary or None if parsing fails
        """
        try:
            alert_data = log_entry.get('alert', {})


            alert = {
                'timestamp': log_entry.get('timestamp', ''),
                'alert_signature': alert_data.get('signature', 'Unknown'),
                'alert_category': alert_data.get('category', 'Unknown'),
                'severity': alert_data.get('severity', 3),
                'signature_id': alert_data.get('signature_id', 0),
                'rev': alert_data.get('rev', 0)
            }


            if 'src_ip' in log_entry:
                alert['src_ip'] = log_entry['src_ip']
            if 'dest_ip' in log_entry:
                alert['dest_ip'] = log_entry['dest_ip']
            if 'src_port' in log_entry:
                alert['src_port'] = log_entry['src_port']
            if 'dest_port' in log_entry:
                alert['dest_port'] = log_entry['dest_port']
            if 'proto' in log_entry:
                alert['protocol'] = log_entry['proto']


            if 'flow' in log_entry:
                flow_data = log_entry['flow']
                alert['flow_start'] = flow_data.get('start', '')
                alert['flow_state'] = flow_data.get('state', '')


            if 'http' in log_entry:
                http_data = log_entry['http']
                alert['http_hostname'] = http_data.get('hostname', '')
                alert['http_url'] = http_data.get('url', '')
                alert['http_method'] = http_data.get('http_method', '')
                alert['http_status'] = http_data.get('status', '')


            if alert['timestamp']:
                try:
                    dt = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                    alert['formatted_time'] = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    alert['formatted_time'] = alert['timestamp']

            return alert

        except Exception as e:
            self.logger.error(f"Error parsing alert: {e}")
            return None

    def block_ip(self, ip_address: str, description: str = "Blocked via Security Monitor") -> bool:
        """
        Block an IP address by adding a firewall rule to pfSense

        Args:
            ip_address: IP address to block
            description: Description for the rule

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # pfSense command to add a block rule
            command = f'''
            /usr/local/bin/easyrule block wan {ip_address} && 
            echo "IP {ip_address} blocked successfully"
            '''

            result = self.execute_command(command)

            if result and "blocked successfully" in result:
                self.logger.info(f"Successfully blocked IP: {ip_address}")
                return True
            else:
                self.logger.error(f"Failed to block IP: {ip_address}")
                return False

        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address}: {e}")
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address by removing firewall rule

        Args:
            ip_address: IP address to unblock

        Returns:
            bool: True if successful, False otherwise
        """
        try:

            command = f'''
            /usr/local/bin/easyrule unblock wan {ip_address} && 
            echo "IP {ip_address} unblocked successfully"
            '''

            result = self.execute_command(command)

            if result and "unblocked successfully" in result:
                self.logger.info(f"Successfully unblocked IP: {ip_address}")
                return True
            else:
                self.logger.error(f"Failed to unblock IP: {ip_address}")
                return False

        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False

    def __del__(self):
        """Cleanup: ensure SSH connection is closed"""
        if hasattr(self, 'connected') and self.connected:
            self.disconnect()



st.set_page_config(
    page_title="pfSense IP Security Manager",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown("""
<style>
    .stApp {
        color: #2B2B2B;
    }
    .main .block-container {
        color: #2B2B2B;
    }
    h1, h2, h3, h4, h5, h6 {
        color: #1A1A1A !important;
    }
    .stMarkdown {
        color: #2B2B2B;
    }
    .stText {
        color: #2B2B2B;
    }
    div[data-testid="stMetricValue"] {
        color: #1A1A1A;
    }
    .stDataFrame {
        color: #2B2B2B;
    }
</style>
""", unsafe_allow_html=True)


if 'monitor' not in st.session_state:
    st.session_state.monitor = None
if 'alerts_df' not in st.session_state:
    st.session_state.alerts_df = pd.DataFrame()
if 'ip_summary_df' not in st.session_state:
    st.session_state.ip_summary_df = pd.DataFrame()
if 'connection_status' not in st.session_state:
    st.session_state.connection_status = "Disconnected"
if 'last_update' not in st.session_state:
    st.session_state.last_update = None
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = False


def initialize_monitor():
    """Initialize the Suricata monitor with connection parameters"""
    try:

        pfsense_host = os.getenv("PFSENSE_HOST", "192.168.1.1")
        pfsense_user = os.getenv("PFSENSE_USER", "admin")
        pfsense_password = os.getenv("PFSENSE_PASSWORD", "Leoqsh!1")
        log_path = os.getenv("SURICATA_LOG_PATH", "/var/log/suricata/suricata_vtnet156394/eve.json")

        st.session_state.monitor = SuricataMonitor(
            host=pfsense_host,
            username=pfsense_user,
            password=pfsense_password,
            log_path=log_path
        )
        return True
    except Exception as e:
        st.error(f"Failed to initialize monitor: {str(e)}")
        return False


def connect_to_pfsense():
    """Connect to pfSense and update connection status"""
    if st.session_state.monitor is None:
        if not initialize_monitor():
            return False

    try:
        if st.session_state.monitor.connect():
            st.session_state.connection_status = "Connected"
            return True
        else:
            st.session_state.connection_status = "Connection Failed"
            return False
    except Exception as e:
        st.session_state.connection_status = f"Error: {str(e)}"
        return False


def fetch_alerts_and_process_ips():
    """Fetch latest alerts from Suricata logs and process IP summary"""
    if st.session_state.monitor:
        try:
            alerts = st.session_state.monitor.get_recent_alerts(limit=200)
            if alerts:
                st.session_state.alerts_df = pd.DataFrame(alerts)
                st.session_state.last_update = datetime.now()


                if st.session_state.monitor.connected:
                    st.session_state.connection_status = "Connected"


                process_ip_summary()
                return True
            else:

                if not st.session_state.monitor.connected:
                    st.session_state.connection_status = "Disconnected"
        except Exception as e:
            st.error(f"Error fetching alerts: {str(e)}")
            st.session_state.connection_status = "Error: " + str(e)
    return False


def process_ip_summary():
    """Process alerts to create IP summary table"""
    if st.session_state.alerts_df.empty:
        st.session_state.ip_summary_df = pd.DataFrame()
        return


    ip_groups = st.session_state.alerts_df.groupby('src_ip').agg({
        'alert_signature': 'count',
        'severity': ['min', 'mean'],
        'timestamp': ['max', 'min'],
        'dest_ip': 'nunique',
        'alert_category': lambda x: ', '.join(x.unique()[:3])
    }).round(2)


    ip_groups.columns = ['Total_Alerts', 'Max_Severity', 'Avg_Severity', 'Last_Seen', 'First_Seen', 'Targets',
                         'Categories']


    ip_summary = ip_groups.reset_index()


    ip_summary['Last_Seen'] = pd.to_datetime(ip_summary['Last_Seen']).dt.strftime('%Y-%m-%d %H:%M')
    ip_summary['First_Seen'] = pd.to_datetime(ip_summary['First_Seen']).dt.strftime('%Y-%m-%d %H:%M')


    ip_summary['Risk_Level'] = ip_summary.apply(lambda row:
                                                "🔴 High" if row['Max_Severity'] == 1 or row['Total_Alerts'] > 20
                                                else "🟡 Medium" if row['Max_Severity'] == 2 or row['Total_Alerts'] > 5
                                                else "🟢 Low", axis=1)


    ip_summary = ip_summary.sort_values('Total_Alerts', ascending=False)

    st.session_state.ip_summary_df = ip_summary


def get_ip_alerts(ip_address: str) -> pd.DataFrame:
    """Get all alerts for a specific IP address"""
    if st.session_state.alerts_df.empty:
        return pd.DataFrame()

    return st.session_state.alerts_df[st.session_state.alerts_df['src_ip'] == ip_address]


def download_ip_report(ip_address: str) -> str:
    """Generate downloadable report for an IP"""
    ip_alerts = get_ip_alerts(ip_address)

    if ip_alerts.empty:
        return ""


    csv_buffer = io.StringIO()
    ip_alerts.to_csv(csv_buffer, index=False)
    return csv_buffer.getvalue()



def main():
    st.title("🛡️ pfSense IP Security Manager")
    st.markdown("Monitor and manage suspicious IP addresses from Suricata alerts")


    with st.sidebar:
        st.header("Connection Controls")


        if st.button("Connect to pfSense", type="primary"):
            with st.spinner("Connecting to pfSense..."):
                success = connect_to_pfsense()
                if success:
                    st.success("Connected successfully!")
                    st.rerun()
                else:
                    st.error("Connection failed!")


        if st.session_state.monitor and hasattr(st.session_state.monitor, 'connected'):
            if st.session_state.monitor.connected:
                st.session_state.connection_status = "Connected"
            else:
                st.session_state.connection_status = "Disconnected"


        status_color = "🟢" if st.session_state.connection_status == "Connected" else "🔴"
        st.markdown(f"**Status:** {status_color} {st.session_state.connection_status}")

        st.divider()


        st.header("Monitoring Controls")
        st.session_state.auto_refresh = st.checkbox("Auto-refresh alerts", value=st.session_state.auto_refresh)

        refresh_interval = st.selectbox(
            "Refresh interval (seconds)",
            options=[10, 30, 60, 120],
            index=1
        )

        if st.button("Refresh Data"):
            with st.spinner("Fetching latest alerts..."):
                fetch_alerts_and_process_ips()

        st.divider()


        st.header("System Info")
        pfsense_host = os.getenv("PFSENSE_HOST", "192.168.1.1")
        st.text(f"Host: {pfsense_host}")
        st.text(f"User: {os.getenv('PFSENSE_USER', 'admin')}")

        if st.session_state.last_update:
            st.text(f"Last update: {st.session_state.last_update.strftime('%H:%M:%S')}")


    if st.session_state.connection_status != "Connected":
        st.warning("Please connect to pfSense to start monitoring.")
        st.info("Click the 'Connect to pfSense' button in the sidebar.")
        return


    if st.session_state.ip_summary_df.empty:
        with st.spinner("Loading security data..."):
            fetch_alerts_and_process_ips()


    if not st.session_state.ip_summary_df.empty:
        st.header("🚨 Suspicious IP Addresses")


        col1, col2, col3, col4 = st.columns(4)
        with col1:
            total_ips = len(st.session_state.ip_summary_df)
            st.metric("Total IPs", total_ips)
        with col2:
            high_risk = len(
                st.session_state.ip_summary_df[st.session_state.ip_summary_df['Risk_Level'].str.contains('High')])
            st.metric("High Risk IPs", high_risk)
        with col3:
            total_alerts = st.session_state.ip_summary_df['Total_Alerts'].sum()
            st.metric("Total Alerts", total_alerts)
        with col4:
            avg_alerts = round(st.session_state.ip_summary_df['Total_Alerts'].mean(), 1)
            st.metric("Avg Alerts/IP", avg_alerts)

        st.divider()


        st.subheader("IP Management Console")


        for idx, row in st.session_state.ip_summary_df.iterrows():
            ip = row['src_ip']


            col_info, col_actions = st.columns([3, 2])

            with col_info:
                st.write(f"**{ip}** - {row['Risk_Level']}")
                st.write(f"📊 {row['Total_Alerts']} alerts | 🎯 {row['Targets']} targets | 📅 Last: {row['Last_Seen']}")
                st.write(f"📋 Categories: {row['Categories']}")

            with col_actions:
                col_btn1, col_btn2, col_btn3, col_btn4 = st.columns(4)

                with col_btn1:
                    if st.button("📊 Report", key=f"report_{ip}"):
                        report_data = download_ip_report(ip)
                        if report_data:
                            st.download_button(
                                label="💾 Download Report",
                                data=report_data,
                                file_name=f"security_report_{ip}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                                mime="text/csv",
                                key=f"download_{ip}"
                            )

                with col_btn2:
                    if st.button("🚫 Block", key=f"block_{ip}"):
                        with st.spinner(f"Blocking {ip}..."):
                            success = st.session_state.monitor.block_ip(ip)
                            if success:
                                st.success(f"✅ Blocked {ip}")
                            else:
                                st.error(f"❌ Failed to block {ip}")

                with col_btn3:
                    if st.button("✅ Unblock", key=f"unblock_{ip}"):
                        with st.spinner(f"Unblocking {ip}..."):
                            success = st.session_state.monitor.unblock_ip(ip)
                            if success:
                                st.success(f"✅ Unblocked {ip}")
                            else:
                                st.error(f"❌ Failed to unblock {ip}")

                with col_btn4:
                    if st.button("🔍 Details", key=f"details_{ip}"):

                        ip_alerts = get_ip_alerts(ip)
                        if not ip_alerts.empty:
                            with st.expander(f"Alert Details for {ip}", expanded=True):
                                st.dataframe(
                                    ip_alerts[['timestamp', 'alert_signature', 'severity', 'dest_ip', 'dest_port']],
                                    use_container_width=True,
                                    hide_index=True
                                )

            st.divider()

    else:
        st.info("No security alerts found. The system is monitoring for threats.")


    if st.session_state.auto_refresh and st.session_state.connection_status == "Connected":
        time.sleep(refresh_interval)
        st.rerun()


if __name__ == "__main__":
    main()