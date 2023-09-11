import sys
from handle_info import HandleInfo
from uds_client import client_socket


def main(params):
    handle_info = HandleInfo()
    data_to_uds, status = handle_info.input_params_handler(params)
    if not status and handle_info.high_risk_command_judgement():
        receive_data = client_socket(data_to_uds)
        handle_info.receipt_info_handler(receive_data)


if __name__ == '__main__':
    input_params = sys.argv[1:]
    main(input_params)
