#!/usr/bin/env python3
"""A module for filtering sensitive information from logs.
"""
import os
import re
import logging
import mysql.connector
from typing import List


patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str,
        ) -> str:
    """Redacts sensitive fields in a log message.

    Args:
        fields (List[str]): List of field names to redact.
        redaction (str): The replacement text for redacted fields.
        message (str): The original log message.
        separator (str): The separator between fields in the log message.

    Returns:
        str: The log message with specified fields redacted.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """Sets up and returns a logger configured to redact sensitive information.

    Returns:
        logging.Logger: A logger instance configured for user data logging.
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()  # Logs to console/stream
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)  # Set logging level to INFO
    logger.propagate = False  # Disable log propagation
    logger.addHandler(stream_handler)  # Attach the handler to the logger
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Establishes a connection to a MySQL database.

    Uses environment variables for database configuration.

    Returns:
        mysql.connector.connection.MySQLConnection: Database connection object.
    """
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    """Fetches user data from the database and logs each record with redaction.

    Logs the columns `name`, `email`, `phone`, `ssn`, `password`, `ip`,
    `last_login`, and `user_agent` for each user in the `users` table.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)  # Query to retrieve user records
    info_logger = get_logger()  # Obtain logger configured for redaction
    connection = get_db()  # Establish database connection
    with connection.cursor() as cursor:
        cursor.execute(query)  # Execute query
        rows = cursor.fetchall()  # Retrieve all records
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))  # Format message string
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)  # Create log record
            info_logger.handle(log_record)  # Log the redacted record


class RedactingFormatter(logging.Formatter):
    """Formatter for redacting sensitive fields in log messages.

    Attributes:
        REDACTION (str): The string to replace sensitive data.
        FORMAT (str): The log message format.
        SEPARATOR (str): The separator used to split fields in the log message.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initializes the formatter with fields to redact.

        Args:
            fields (List[str]): List of sensitive fields to redact in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Redacts sensitive information in a log record.

        Args:
            record (logging.LogRecord): Log record containing message to redact.

        Returns:
            str: The formatted and redacted log message.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt  # Return the redacted message


if __name__ == "__main__":
    main()
