# Lab Submission Manager
# Greene, 2024

# Basic Imports
import time
import sys
import os
import io
import json
import tempfile
import subprocess
import random
import string
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import uuid
import threading
import requests
import urllib.request
import tarfile
import nmap
import paramiko
import signal

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, or_
from werkzeug.middleware.proxy_fix import ProxyFix

from slack_sdk.errors import SlackApiError
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# SSH Login Name
ssh_user_name = 'root'

# Private SSH key location
ssh_private_key_file = './.keys/fabric_rsa'

# Public SSH key locations
ssh_public_key_file = './.keys/fabric_rsa.pub'

# Block these boards from being available in "first available"
# Users will still be able manually select them
blocked_boards = [3,]

# Interrupt Signal Handler
PROGRAM_RUNNING = threading.Event()

def handle_program_closing(signal, frame):
    global PROGRAM_RUNNING
    print("[Main] Program was asked to close...")
    PROGRAM_RUNNING.set()

# Convert a DateTime object to a local datetime string
def to_local_datetime(obj):
    return obj.astimezone(tz=ZoneInfo("America/New_York")).strftime('%Y-%m-%d %H:%M:%S')

# Convert a DateTime object to a local time string
def to_local_time(obj):
    return obj.astimezone(tz=ZoneInfo("America/New_York")).strftime('%H:%M:%S')

# Slack Tokens
SLACK_BOT_TOKEN = '[REMOVED FROM GITHUB]'
SLACK_APP_TOKEN = '[REMOVED FROM GITHUB]'

# Initialize Slack Bolt app
slack_app = App(token=SLACK_BOT_TOKEN)

# Construct and configure the Flask application
flask_app = Flask(__name__)
flask_app.config['UPLOAD_FOLDER'] = 'uploads'
flask_app.config['RESULTS_FOLDER'] = 'results'
flask_app.config['SECRET_KEY'] = '[REMOVED FROM GITHUB]'
flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///uploads.db'
flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Construct the database
db = SQLAlchemy(flask_app)

# Fix Apache Reverse Proxy
flask_app.wsgi_app = ProxyFix(flask_app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


class LabSubmission(db.Model):
    # Instance
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True)
    case_id = db.Column(db.String(36), nullable=False, unique=True)
    # User information
    slack_id = db.Column(db.String(100), nullable=False)
    slack_username = db.Column(db.String(100), nullable=False)
    slack_name = db.Column(db.String(100), nullable=False)
    # Input information
    file_application = db.Column(db.String(100), nullable=False)
    file_board = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    # Timestamps
    time_submitted = db.Column(db.DateTime, default=datetime.now, nullable=False)


class ExecutionRequest(db.Model):
    # Request
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True)
    execution_id = db.Column(db.String(36), nullable=False, unique=True)
    for_case_id = db.Column(db.String(36), nullable=False)
    slack_id = db.Column(db.String(100), nullable=False)
    slack_username = db.Column(db.String(100), nullable=False)
    # Input
    command = db.Column(db.String(512), nullable=False) # Execution string for the command line
    board_preference = db.Column(db.String(36), default="first-available", nullable=False) # Board preference (0: first available, otherwise: IP address of the board)
    # Timestamps
    time_submitted = db.Column(db.DateTime, default=datetime.now, nullable=False)
    time_execution_started = db.Column(db.DateTime, default=None, nullable=True)
    time_execution_finished = db.Column(db.DateTime, default=None, nullable=True)
    # Output
    assigned = db.Column(db.String(36), default=None, nullable=True)
    status_code = db.Column(db.Integer, default=None, nullable=True)  # Program status code
    result_file = db.Column(db.String(36), default=None, nullable=True) # Zipped filename of the results


class RFSoCBoard(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()), unique=True)
    address = db.Column(db.String(100), nullable=False)
    hostname = db.Column(db.String(100), nullable=False)
    time_last_seen = db.Column(db.DateTime, default=datetime.now, nullable=False)


class BoardWorker(threading.Thread):
    def __init__(self, address, sleep_delay_seconds=3, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.event = threading.Event()
        self.address = address
        self.sleep_delay_seconds = sleep_delay_seconds
        print(f'[Board Worker {self.address}] Thread created.')

    def do_job(self, requisition):

        # Store the start time
        time_start = datetime.now()

        # Send message referencing the uploaded file
        slack_app.client.chat_postMessage(
            channel=requisition['slack_id'],
            text=f'Submission *{requisition["case_id"]}* started running at {to_local_time(time_start)} on *{self.address}*'
        )

        execution_id = requisition["execution_id"]
        case_id = requisition["case_id"]
        command_string = requisition["command_string"]

        # Paths and files
        local_upload_dir = f'./{flask_app.config["UPLOAD_FOLDER"]}/{case_id}'
        local_results_dir = f'./{flask_app.config["RESULTS_FOLDER"]}'
        remote_submission_dir = f'/home/root/jobs'
        remote_execution_dir = f'{remote_submission_dir}/{execution_id}'
        remote_results_file = f'{remote_submission_dir}/{execution_id}.tar.gz'
        local_results_file = f'{local_results_dir}/{execution_id}.tar.gz'

        # Store the start time
        time_start = datetime.now()

        # Copy the xclbin file to the TFTP directory
        fpga_bitstream_submitted = requisition['command_string'].split(' ')[-1]
        fpga_bitstream_stored = f'system{self.address[-1]}.bin'
        print(f'Copying submission bitstream ({fpga_bitstream_submitted}) to the TFTP directory ({fpga_bitstream_stored})')
        os.system(f'cp {local_upload_dir}/{fpga_bitstream_submitted} /tftpboot/{fpga_bitstream_stored}')

        # Tell the rfsoc board to reboot
        try:
            print('Asking the board to reboot')
            with (paramiko.SSHClient() as ssh):

                # Connect to the RFSoC board
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=self.address, username=ssh_user_name, key_filename=ssh_private_key_file)

                # Ask it to reboot
                ssh.exec_command('reboot')

        except paramiko.AuthenticationException:
            print("Authentication failed. Please check your credentials.")
        except paramiko.SSHException as e:
            print(f"SSH connection failed: {e}")

        finally:
            if ssh:
                ssh.close()


        # Wait until it comes back online
        start_time = datetime.now()
        print(f'Waiting for board {self.address} to reboot')
        while True:
            time.sleep(60)
            board_port_scanner = nmap.PortScanner()
            scan_result = board_port_scanner.scan(hosts=self.address, arguments='-sn -T4 -PA22 --open')
            if len(scan_result["nmap"]["scanstats"]["uphosts"]) > 0:
                print(f'Board {self.address} is back online.')
                break
            else:
                time_offline = (datetime.now() - start_time)
                print(f' -- {self.address} has been offline for {time_offline}')

                if time_offline > datetime.timedelta(minutes=10):
                    print(f"ERROR: Board {self.address} has been offline for too long, it's probably dead.")

                    # Store the finish time
                    time_finished = datetime.now()

                    # Update the database
                    with (flask_app.app_context()):
                        ExecutionRequest.query.filter_by(execution_id=execution_id).update(dict(
                            time_execution_started=time_start,
                            time_execution_finished=time_finished,
                            result_file=None
                        ))
                        db.session.commit()

                    # Send message referencing the uploaded file
                    slack_app.client.chat_postMessage(
                        channel=requisition['slack_id'],
                        text=f'Submission *{requisition["case_id"]}* failed at {to_local_time(time_finished)} on *{self.address}*. The board is not responding, please notify @David Greene to restart it.'
                    )
                    return

        # Run the executable and log the results
        try:
            with (paramiko.SSHClient() as ssh):

                # Connect to the RFSoC board
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=self.address, username=ssh_user_name, key_filename=ssh_private_key_file)

                # Clear out the old directory, if it exists
                ssh.exec_command(f'rm -rf {remote_execution_dir}')

                # Create the execution directory
                ssh.exec_command(f'mkdir -p {remote_execution_dir}')

                # Upload the submission folder
                os.system(f'scp -o StrictHostKeyChecking=no -r {local_upload_dir}/* root@{self.address}:{remote_execution_dir}')

                # Run the command on the rfsoc board
                tran = ssh.get_transport()
                chan = tran.open_session()
                chan.get_pty()
                f = chan.makefile()
                command = f"cd {remote_execution_dir}; " \
                    f"{command_string} > console.txt 2>&1; " \
                    f"cd {remote_submission_dir}; " \
                    f"tar zcvf {execution_id}.tar.gz {execution_id}"
                print(f"Executing command: {command}")
                chan.exec_command(command)

                output_string = f.read()
                if len(output_string)>0:
                    print(output_string)
                chan.close()

                # Pull back the results
                os.system(f'scp -o StrictHostKeyChecking=no -r root@{self.address}:{remote_results_file} {local_results_dir}')

        except paramiko.AuthenticationException:
            print("Authentication failed. Please check your credentials.")
            return
        except paramiko.SSHException as e:
            print(f"SSH connection failed: {e}")
            return
        finally:
            if ssh:
                ssh.close()

        # Store the finish time
        time_finished = datetime.now()

        # Update the database
        with (flask_app.app_context()):
            ExecutionRequest.query.filter_by(execution_id=execution_id).update(dict(
                time_execution_started=time_start,
                time_execution_finished=time_finished,
                result_file=f'{execution_id}.tar.gz'
            ))
            db.session.commit()

        # Upload the results to Slack
        user_to_channel=slack_app.client.conversations_open(users=requisition['slack_id'])
        user_to_channel=user_to_channel["channel"]["id"]
        print(f'Finished processing {requisition["case_id"]} at {to_local_time(time_finished)} on {self.address}\n')
        upload_response = slack_app.client.files_upload_v2(
            file=local_results_file,
            title=f'Execution Results {execution_id}',
            channel=user_to_channel,
            initial_comment=f':checkered_flag: Submission *{requisition["case_id"]}* finished at {to_local_time(time_finished)}'
        )

    def requisition_job(self):
        with (flask_app.app_context()):
			
			
            # Get the first job we can work on
            if (self.address.split('.'))[-1] in [3,4]:
                first_request = ExecutionRequest.query.filter(and_(ExecutionRequest.assigned == None, ExecutionRequest.board_preference == self.address)).order_by(ExecutionRequest.time_submitted).first()
            else:
                first_request = ExecutionRequest.query.filter(and_(ExecutionRequest.assigned == None, or_(ExecutionRequest.board_preference == 'first-available', ExecutionRequest.board_preference == self.address))).order_by(ExecutionRequest.time_submitted).first()

            if first_request is not None:
                # Store the execution id
                execution_id = first_request.execution_id
                case_id = first_request.for_case_id
                command_string = first_request.command
                slack_id = first_request.slack_id

                # Assign the job to this board
                ExecutionRequest.query.filter_by(id=first_request.id).update(dict(assigned=self.address))
                db.session.commit()

                print(f"[Board Worker {self.address}] Assigned queue request {execution_id}")
                return {'execution_id': execution_id, 'case_id': case_id, 'command_string': command_string, 'slack_id': slack_id, }
            else:
                return None

    def stop(self) -> None:
        self.event.set()
        print(f'[Board Worker {self.address}] Thread asked to stop.')

    def run(self) -> None:
        while not self.event.is_set():
            # Check if a job is available
            requisition = self.requisition_job()
            if requisition is not None:
                # Do it
                self.do_job(requisition)

            # Sleep before checking if we can work on another job
            time.sleep(self.sleep_delay_seconds)
        print(f'[Board Worker {self.address}] Thread finished.')

# A list of active RFSoC Boards
Active_BoardWorkers = []


def check_for_lost_jobs():
    # Query the current database
    with flask_app.app_context():
        # Calculate the time
        minutes_ago = datetime.utcnow() - timedelta(minutes=10)

        # Run the query
        unrun_jobs = ExecutionRequest.query.filter(and_(ExecutionRequest.assigned != None,
                                                        and_(ExecutionRequest.time_execution_started == None,
                                                             ExecutionRequest.time_submitted < minutes_ago))).all()

        # Unassign the job(s)
        for job in unrun_jobs:
            print(f'Board {job.assigned} took too long to start job {job.execution_id}. Unassigning.')
            ExecutionRequest.query.filter_by(id=job.id).update(dict(assigned=None))
        db.session.commit()


def update_active_rfsoc_boards():
    # Get a list of active RFSoC boards
    port_scanner = nmap.PortScanner()
    port_scanner.scan(hosts='10.0.60.0/24', arguments='-sn -T4 -PA22 --open')
    new_boards = []

    # Query the current database
    with (flask_app.app_context()):
        for address in port_scanner.all_hosts():
            if len(port_scanner[address]["hostnames"]) > 0:
                if port_scanner[address]["hostnames"][0]["name"].startswith("rfsoc"):

                    # Append the new board to the list
                    new_boards.append((address, port_scanner[address]["hostnames"][0]["name"]))

                    # Update the time we last saw this host
                    num_rows_updated = RFSoCBoard.query.filter_by(address=address).update(dict(time_last_seen=datetime.now()))
                    db.session.commit()

                    # If that host didn't exist, add it
                    if num_rows_updated == 0:

                        # Add a database entry for this host
                        new_board = RFSoCBoard(
                            id=str(uuid.uuid4()),
                            address=address,
                            hostname=port_scanner[address]["hostnames"][0]["name"],
                            time_last_seen=datetime.now()
                        )
                        db.session.add(new_board)
                        db.session.commit()

                        # Start a thread worker for this host
                        print(f'[Boards] Added new board at {address} on {to_local_datetime(datetime.now())}')

        # Remove all board we haven't seen for more than 5 minutes
        five_minutes_ago = datetime.now() - timedelta(minutes=5)
        for board in RFSoCBoard.query.filter(RFSoCBoard.time_last_seen < five_minutes_ago).all():
            print(f'[Boards dB] Remove board at {board.address} since it was last seen on {to_local_datetime(board.time_last_seen)}')
            db.session.delete(board)
        db.session.commit()

        ## Process our local thread workers

        # Get the current list from the database
        db_active_boards = RFSoCBoard.query.all()
        db_active_hosts = [board.address for board in db_active_boards]

        # Stop and old thread workers
        for board_worker in Active_BoardWorkers:
            if board_worker.address not in db_active_hosts:
                board_worker.stop()
                Active_BoardWorkers.remove(board_worker)

        # Start any new thread workers
        local_active_hosts = [board_worker.address for board_worker in Active_BoardWorkers]
        for active_host in db_active_hosts:
            if active_host not in local_active_hosts:
                new_worker = BoardWorker(address=active_host)
                new_worker.start()
                Active_BoardWorkers.append(new_worker)
                time.sleep(1)


def queue_execution_request(case_id, board_preference="first-available"):
    try:
        with (flask_app.app_context()):

            # Check that this is a valid case_id
            cases = LabSubmission.query.filter_by(case_id=case_id).all()
            assert len(cases) == 1, f'Error: There were {len(cases)} case(s) with id {case_id}.'
            case = cases[0]

            case_slack_id = case.slack_id
            case_slack_username = case.slack_username


            # Assign an execution ID
            while True:
                execution_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=9))
                execution_id = f'{execution_id[:3]}-{execution_id[3:6]}-{execution_id[-3:]}'
                found_execution_ids = ExecutionRequest.query.filter_by(execution_id=execution_id).all()
                if len(found_execution_ids) == 0:
                    break

            # Create an output folder
            submission_directory = os.path.join(flask_app.config['RESULTS_FOLDER'], execution_id, )
            os.makedirs(submission_directory)

            # Get the submission time
            submission_time = datetime.now()

            # Push a request to the database
            new_request = ExecutionRequest(
                id=str(uuid.uuid4()),
                execution_id=execution_id,
                for_case_id=case_id,
                slack_id=case_slack_id,
                slack_username=case_slack_username,
                command=f'./{case.file_application} {case.file_board}',
                board_preference=board_preference,
                time_submitted=submission_time
            )
            db.session.add(new_request)
            db.session.commit()

            # All done!
            print(f'[{to_local_datetime(submission_time)}] @{case_slack_username} requested {case_id} to run on {board_preference if board_preference != "first-available" else "the first available board"}')
            slack_app.client.chat_postMessage(channel=case_slack_id, text=f"Submission *{case_id}* was queued at {to_local_time(submission_time)} on *{board_preference if board_preference != 'first-available' else 'the first available board'}*")
    except SlackApiError as e:
        print(f"Error requesting execution of {case_id}: {e.response['error']}")


def refresh_home_tab(client, user_id):

    # Setup an initial view
    initial_view = {
        "type": "home",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Tasks:",
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "text": "Upload a new submission..."
                },
                "accessory": {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "New Submission",
                    },
                    "action_id": "open_modal_upload_lab_submission"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "text": "Queue an uploaded submission..."
                },
                "accessory": {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Queue Submission",
                    },
                    "action_id": "open_modal_queue_execution"
                }
            },
            {"type": "divider"},
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Boards Online:"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "There are no boards online :worried:"
                }
            },
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Queued Submissions:"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "There are no boards online :worried:"
                }
            },
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Recent Submissions:"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ""
                }
            }
        ]
    }


    with (flask_app.app_context()):
        IDX_BOARD = 5
        IDX_QUEUE = 7
        IDX_UPLOADS = 9

        # Populate the list of boards online
        online_boards = RFSoCBoard.query.all()
        if len(online_boards) == 0:
            initial_view["blocks"][IDX_BOARD]["text"]["text"] = "There are no boards online :worried:"
        else:
            initial_view["blocks"][IDX_BOARD]["text"]["text"] = ""
            for board in online_boards:
                initial_view["blocks"][IDX_BOARD]["text"]["text"] += f":gear: *{board.address}* ({board.hostname})\nLast Seen: {to_local_datetime(board.time_last_seen)}\n\n"

        # Check the status of any queued submissions
        queued_requests = ExecutionRequest.query.filter(ExecutionRequest.time_execution_finished==None).order_by(ExecutionRequest.time_submitted).all()
        if len(queued_requests) == 0:
            initial_view["blocks"][IDX_QUEUE]["text"]["text"] = "There are no submissions queued right now! :tada:"
        else:
            initial_view["blocks"][IDX_QUEUE]["text"]["text"] = ""
            for job in queued_requests:
                initial_view["blocks"][IDX_QUEUE]["text"]["text"] += f"*{to_local_datetime(job.time_submitted)}*\n@{job.slack_username} scheduled submission _{job.for_case_id}_ to run on {job.board_preference if job.board_preference != 'first-available' else 'the first available board'}\n\n"

        # Check the status of any queued submissions
        recent_activity = LabSubmission.query.order_by(LabSubmission.time_submitted.desc()).limit(5).all()
        if len(recent_activity) == 0:
            initial_view["blocks"][IDX_UPLOADS]["text"]["text"] = "There haven't been any recent submissions :yawning_face:"
        else:
            initial_view["blocks"][IDX_UPLOADS]["text"]["text"] = ""
            for job in recent_activity:
                initial_view["blocks"][IDX_UPLOADS]["text"]["text"] += f"*{to_local_datetime(job.time_submitted)}*\n@{job.slack_name} uploaded submission _{job.case_id}_\n\n"

    # Push the view to the user's home page
    client.views_publish(user_id=user_id, view=initial_view)


# Slack command to trigger the modal
@slack_app.action("open_modal_upload_lab_submission")
@slack_app.shortcut("upload_lab_submission")
def open_modal_upload_lab_submission(ack, body, client):
    ack()

    # Get a list of RFSoC boards that are online
    online_boards = [('first-available', 'First Available Board'),]
    with (flask_app.app_context()):
        for board in RFSoCBoard.query.all():
            online_boards.append((board.address, board.address))

    # Open a modal
    client.views_open(

        # Pass a valid trigger_id within 3 seconds of receiving it
        trigger_id=body["trigger_id"],

        # View payload
        view={
            "type": "modal",
            "callback_id": "handle_uploaded_lab_submission",
            "submit": {
                "type": "plain_text",
                "text": "Submit"
            },
            "close": {
                "type": "plain_text",
                "text": "Cancel"
            },
            "title": {
                "type": "plain_text",
                "text": "Upload a Submission"
            },
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "Please submit a tarball using gzip compressions, containing your *Host Executable* and *FPGA Bitstream* files inside. The bot will DM you with a submission acknowledgement and the results.\n\nYou can create a tarball using the following command in a Ubuntu bash shell: `tar zcvf submission.tar.gz app bitstream.xclbin`"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "input",
                    "block_id": "compressed_submission",
                    "label": {
                        "type": "plain_text",
                        "text": "Compressed Submission:"
                    },
                    "element": {
                        "type": "file_input",
                        "max_files": 1,
                        "action_id": "compressed_submission_input",
                        "filetypes": ["gz", "zip",]
                    },
                    "optional": False
                },
                {
                    "type": "input",
                    "block_id": "job_description",
                    "label": {
                        "type": "plain_text",
                        "text": "Description:"
                    },
                    "element": {
                        "type": "plain_text_input",
                        "multiline": True,
                        "action_id": "job_description_input"
                    },
                    "optional": False
                }
            ]
        }
    )


# Slack modal submission listener
@slack_app.view("handle_uploaded_lab_submission")
def handle_uploaded_lab_submission(ack, body, client, view):
    ack()
    try:
        with (flask_app.app_context()):
            # Assign a Case ID
            case_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            case_id = f'{case_id[:3]}-{case_id[-3:]}'
            found_case_ids = LabSubmission.query.filter_by(case_id=case_id).all()
            while len(found_case_ids)>0:
                # This case id already exists, generate a new one
                case_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
                found_case_ids = LabSubmission.query.filter_by(case_id=case_id).all()

            # Ensure the submission folder exists
            submission_directory = f'./{flask_app.config["UPLOAD_FOLDER"]}/{case_id}'
            os.makedirs(submission_directory)

            # Collect the submitted file
            submitted_file_info = view["state"]["values"]["compressed_submission"]["compressed_submission_input"]["files"][0]
            submitted_file_name = submitted_file_info["name"]
            full_submitted_file_name = f'{submission_directory}/{submitted_file_name}'
            response = requests.get(submitted_file_info["url_private_download"], headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}",})
            with open(full_submitted_file_name, "wb") as file:
                file.write(response.content)

            # Extract the contents of the file
            print(f'Extracting compressed file: {full_submitted_file_name}')
            if submitted_file_name.endswith('.gz'):
                with tarfile.open(full_submitted_file_name) as tar_ref:
                    tar_ref.extractall(submission_directory)
            os.remove(full_submitted_file_name)

            # Create the XRT file
            xrt_options = \
                "[Debug]\n" \
                "power_profile=true\n" \
                "opencl_trace=true\n" \
                "lop_trace=false\n" \
                "xrt_trace=true\n" \
                "app_debug=true\n" \
                "host_trace=true\n" \
                "device_trace=fine\n" \
                "continuous_trace=true\n" \
                "profile_api=true\n" \
                "native_xrt_trace=false\n" \
                "pl_deadlock_detection=false\n" \
                "device_counters=false\n"
            with open(f'{submission_directory}/xrt.ini', 'w') as xrt_file:
                xrt_file.write(xrt_options)
            os.system(f'cp -f xrt.ini {submission_directory}/.')

            # Set default filenames
            file_executable = 'app'
            file_bitstream = 'bitstream.xclbin'

            # Determine the filenames
            for filename in os.listdir(submission_directory):
                if filename.endswith(".xclbin"):
                    print('-- found bitstream:', filename)
                    file_bitstream = filename
                elif (not filename.endswith(".xclbin")) and os.path.isfile(f'{submission_directory}/{filename}') and os.access(f'{submission_directory}/{filename}', os.X_OK):
                    print('-- found executable:', filename)
                    file_executable = filename

            # Create description file
            submission_description = view["state"]["values"]["job_description"]["job_description_input"]["value"]

            # Get the submission time
            submission_time = datetime.now()

            # Get the user's information
            slack_id = body["user"]["id"]
            slack_username = body["user"]['username']

            # Create a new Lab Submission object
            new_request = LabSubmission(
                id=str(uuid.uuid4()),
                case_id=case_id,
                slack_id=slack_id,
                slack_username=slack_username,
                slack_name=body["user"]["name"],
                file_application=file_executable,
                file_board=file_bitstream,
                description=submission_description,
                time_submitted=submission_time
            )
            db.session.add(new_request)
            db.session.commit()

        # Update the user's home page
        refresh_home_tab(client, slack_id)

        # All done!
        print(f'[{to_local_datetime(submission_time)}] A new submission has been uploaded by @{slack_username} with case id {case_id}')
        message_blocks = [{"type": "section",
                           "text": {
                               "type": "mrkdwn",
                               "text": f"Submission *{case_id}* finished uploading to the server! Click here to queue a job on the first available board:"
                           },
                           "accessory": {
                               "type": "button",
                               "value": f"{case_id}",
                               "text": { "type": "plain_text", "text": f"Queue {case_id}", },
                               "action_id": "button_clicked_queue_job",  # Replace with your desired callback ID
                           }}]
        slack_app.client.chat_postMessage(channel=slack_id, blocks=message_blocks, text=f"Submission *{case_id}* finished uploading to the server!")

    except SlackApiError as e:
        print(f"Error creating submission {case_id}: {e.response['error']}")
        slack_app.client.chat_postMessage(channel=slack_id,
                                          text=f"There was an error uploading submission *{case_id}*. Try again, contact @djgreene, or contact @tanfwong for more help.")


# Slack command to trigger the modal
@slack_app.action("open_modal_queue_execution")
@slack_app.shortcut("queue_execution")
def open_modal_queue_execution(ack, body, client):
    ack()

    # Get the user's slack id
    slack_id = body["user"]['id']

    with (flask_app.app_context()):

        # Get a list of the user's lab submissions
        lab_submissions = LabSubmission.query.filter_by(slack_id=slack_id).order_by(LabSubmission.time_submitted.desc()).all()

        # Get a list of RFSoC boards that are online
        online_boards = [('first-available', 'First Available Board'),]
        with (flask_app.app_context()):
            for board in RFSoCBoard.query.all():
                online_boards.append((board.address, board.address))

    # Open a modal
    client.views_open(

        # Pass a valid trigger_id within 3 seconds of receiving it
        trigger_id=body["trigger_id"],

        # View payload
        view={
            "type": "modal",
            "callback_id": "handle_modal_queue_lab_submission",
            "submit": {
                "type": "plain_text",
                "text": "Submit"
            },
            "close": {
                "type": "plain_text",
                "text": "Cancel"
            },
            "title": {
                "type": "plain_text",
                "text": "Queue a Submission"
            },
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "The following form allows you to queue your submission on one of the available hardware platforms in the lab. The bot will DM you with a submission acknowledgement and the results."
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "input",
                    "block_id": "board_preference",
                    "element": {
                        "type": "radio_buttons",
                        "action_id": "board_preference_input",
                        "initial_option": {"text": {"type": "plain_text", "text": f"{online_boards[0][1]}"}, "value": f"{online_boards[0][0]}"},
                        "options": [{"text": {"type": "plain_text", "text": f"{hostname}"}, "value": f"{address}"} for (address, hostname) in online_boards]
                    },
                    "label": {
                        "type": "plain_text",
                        "text": "Board Preference:"
                    }
                },
                {
                    "type": "input",
                    "block_id": "chosen_lab",
                    "element": {
                        "type": "static_select",
                        "placeholder": {
                            "type": "plain_text",
                            "text": "Choose a submission..."
                        },
                        "options": [{"text": {"type": "plain_text", "text": f"{submission.case_id} ({to_local_datetime(submission.time_submitted)})"}, "value": f"{submission.case_id}"} for submission in lab_submissions],
                        "action_id": "static_select_submission"
                    },
                    "label": {
                        "type": "plain_text",
                        "text": "Submission:"
                    }
                }
            ]
        }
    )


@slack_app.action("button_clicked_queue_job")
def button_clicked_queue_job(ack, body, client):
    ack()

    # Queue the execution request
    case_id = body['actions'][0]['value']
    queue_execution_request(case_id)

    # Update the user's home page
    slack_id = body['user']['id']
    refresh_home_tab(client, slack_id)


@slack_app.view("handle_modal_queue_lab_submission")
def handle_modal_queue_lab_submission(ack, body, client):
    ack()

    # Queue the execution request
    case_id = body["view"]["state"]["values"]["chosen_lab"]["static_select_submission"]["selected_option"]["value"]
    board_preference = body["view"]["state"]["values"]["board_preference"]["board_preference_input"]["selected_option"]["value"]
    queue_execution_request(case_id, board_preference)

    # Update the user's home page
    slack_id = body['user']['id']
    refresh_home_tab(client, slack_id)


@slack_app.event("app_home_opened")
def event_app_home_opened(client, event, logger):
    try:
        refresh_home_tab(client, event["user"])
    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")


@slack_app.event("message")
def handle_event_new_message(body, client, logger):
    # We don't do anything here
    return


# Thread Function - Slack
def run_slack(slack_handler):
    slack_handler.start()
    print("[Thread] Finished run_flask()")

# Thread Function - Flask
def run_flask():
    flask_app.run(port=8089, debug=True, use_reloader=False)
    print("[Thread] Finished run_flask()")


# Thread Function - Update active boards every minute
def run_update_active_rfsoc_boards():
    global PROGRAM_RUNNING
    while not PROGRAM_RUNNING.is_set():
        # Run these tasks
        update_active_rfsoc_boards()
        check_for_lost_jobs()

        # Sleep for 60 seconds, but wakeup if the flag is set
        for _ in range(60):
            if PROGRAM_RUNNING.is_set():
                break
            time.sleep(1)

    print("[run_update_active_rfsoc_boards] Thread Finished")


# Main
if __name__ == "__main__":

    # Ensure the upload folder exists
    if not os.path.exists(flask_app.config['UPLOAD_FOLDER']):
        os.makedirs(flask_app.config['UPLOAD_FOLDER'])

    # Ensure the results folder exists
    if not os.path.exists(flask_app.config['RESULTS_FOLDER']):
        os.makedirs(flask_app.config['RESULTS_FOLDER'])

    # Ensure the database is setup
    with flask_app.app_context():
        db.create_all()

    # Start the flask thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.start()

    # Start the slack thread
    slack_handler = SocketModeHandler(app=slack_app, app_token=SLACK_APP_TOKEN)
    slack_handler.connect()
    #slack_thread = threading.Thread(target=run_slack, args=(slack_handler,))
    #slack_thread.start()

    # Start the board updater thread
    board_thread = threading.Thread(target=run_update_active_rfsoc_boards)
    board_thread.start()

    # Sleep until it's all over
    signal.signal(signal.SIGINT, handle_program_closing)
    while not PROGRAM_RUNNING.is_set():
        time.sleep(1)

    # Stop all board workers
    for board_worker in Active_BoardWorkers:
        print(f"[Main] Asking board worker {board_worker.address} to stop...")
        board_worker.stop()

    # Ask slack to stop
    print("[Main] Asking the Slack handler to close...")
    slack_handler.disconnect()

    # ASk the threads to join
    print("[Main] Asking the board thread to close...")
    board_thread.join()
    print("[Main] Asking the flask thread to close...")
    flask_thread.join()
