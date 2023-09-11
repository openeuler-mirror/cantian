from logs_handler import LogsHandler
from logs_tool.log import LOGS_HANDLER_LOG as LOG


def main():
    logs_handler_obj = LogsHandler()
    try:
        logs_handler_obj.execute()
    except Exception as err:
        LOG.error(str(err))


if __name__ == "__main__":
    main()
